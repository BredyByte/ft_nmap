#include "defines.h"

extern t_nmap g_data;

/* --- Helper: compute checksum --- */
unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    unsigned short answer;
    
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if(nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;
    return answer;
}


/* --- Packet-Specific Send Functions --- */
// TCP pseudo-header structure for checksum calculation.
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

uint32_t get_local_ip() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);
    connect(sock, (struct sockaddr*)&serv, sizeof(serv));
    struct sockaddr_in local;
    socklen_t addr_len = sizeof(local);
    getsockname(sock, (struct sockaddr*)&local, &addr_len);
    close(sock);
    return local.sin_addr.s_addr;
}

#define NUM_SCAN_TYPES 6  // Order: SYN, NULL, ACK, FIN, XMAS, UDP

/* --- Updated Result Enumeration --- */
typedef enum {
    SCAN_RESULT_NO_RESPONSE,     // initial state: no reply received
    SCAN_RESULT_OPEN,
    SCAN_RESULT_OPEN_FILTERED,   // ambiguous: open|filtered (no response in NULL, FIN, XMAS, UDP)
    SCAN_RESULT_UNFILTERED,
    SCAN_RESULT_CLOSED,
    SCAN_RESULT_FILTERED         // unambiguous filtered (for SYN/ACK, ACK scans)
} scan_result_t;

typedef struct {
    int port;
    scan_result_t results[NUM_SCAN_TYPES];
} port_result_t;

/* --- TCP Socket Information --- */
// One TCP socket per port for the TCP-based scans.
typedef struct {
    int sock;
    int port;
    int scan_mask; // bitmask of TCP scan types sent for this port (SCAN_SYN|SCAN_NULL|SCAN_ACK|SCAN_FIN|SCAN_XMAS)
} tcp_sock_info_t;



const char *result_to_string(scan_result_t res) {
    switch (res) {
        case SCAN_RESULT_OPEN:            return "OPEN";
        case SCAN_RESULT_OPEN_FILTERED:   return "OPEN|FILTERED";
        case SCAN_RESULT_UNFILTERED:      return "UNFILTERED";
        case SCAN_RESULT_CLOSED:          return "CLOSED";
        default:                          return "FILTERED";
    }
}

/* --- Helper Function: Set Non-blocking --- */
int set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

/* --- Helper Structures --- */
typedef struct {
    int used;
    int dest_port;
    int scan_index;
} mapping_entry;

/* --- Header Preparation Helpers --- */
void prepare_ip_header(struct iphdr *iph, uint32_t local_ip, uint32_t dest_ip, int total_length) {
    memset(iph, 0, sizeof(struct iphdr));
    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 0;
    iph->tot_len  = htons(total_length);
    iph->id       = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr    = local_ip;
    iph->daddr    = dest_ip;
    iph->check    = csum((unsigned short*)iph, sizeof(struct iphdr));
}

void prepare_tcp_header(struct tcphdr *tcph, int src_port, int dest_port, int scan_flag) {
    memset(tcph, 0, sizeof(struct tcphdr));
    tcph->source  = htons(src_port);
    tcph->dest    = htons(dest_port);
    tcph->seq     = htonl(0);
    tcph->ack_seq = 0;
    tcph->doff    = 5;
    tcph->window  = htons(5840);
    tcph->urg_ptr = 0;
    if (scan_flag == SCAN_SYN)
        tcph->syn = 1;
    else if (scan_flag == SCAN_NULL)
        ; // no flags for NULL scan
    else if (scan_flag == SCAN_ACK)
        tcph->ack = 1;
    else if (scan_flag == SCAN_FIN)
        tcph->fin = 1;
    else if (scan_flag == SCAN_XMAS)
        tcph->fin = tcph->psh = tcph->urg = 1;
}

unsigned short compute_tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address   = iph->daddr;
    psh.placeholder    = 0;
    psh.protocol       = IPPROTO_TCP;
    psh.tcp_length     = htons(sizeof(struct tcphdr));
    char pseudogram[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    return csum((unsigned short*)pseudogram, sizeof(pseudogram));
}

/* --- TCP Packet Sending per Port --- */
void send_tcp_packets_for_port(int raw_sock, struct sockaddr_in *dest, uint32_t local_ip,
                               int port, int tcp_scan_types, mapping_entry *lookup) {
    const int hdr_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    char packet[hdr_len];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    /* Prepare base IP header for this port */
    prepare_ip_header(iph, local_ip, dest->sin_addr.s_addr, hdr_len);

    for (int scan_idx = 0; scan_idx < 5; scan_idx++) {
        int flag = 1 << scan_idx;
        if (!(tcp_scan_types & flag))
            continue;

        int src_port;
        do {
            src_port = 1024 + rand() % (65535 - 1024);
        } while (lookup[src_port].used);

        /* Update fields that vary per packet */
        prepare_tcp_header(tcph, src_port, port, flag);
        iph->id = htons(rand() % 65535);
        iph->check = csum((unsigned short*)iph, sizeof(struct iphdr));
        tcph->check = compute_tcp_checksum(iph, tcph);

        if (sendto(raw_sock, packet, hdr_len, 0, (struct sockaddr*)dest, sizeof(*dest)) < 0)
            perror("sendto");
        else {
            lookup[src_port].used = 1;
            lookup[src_port].dest_port = port;
            lookup[src_port].scan_index = scan_idx;
        }
        usleep(500);
    }
}
/* --- UDP Packet Sending --- */
void send_udp_packet(int udp_sock, struct sockaddr_in *dest, int port) {
    dest->sin_port = htons(port);
    const char *data = "UDP";
    if (sendto(udp_sock, data, strlen(data), 0, (struct sockaddr*)dest, sizeof(*dest)) < 0)
        perror("sendto UDP");
}


/* --- Process TCP Responses --- */
void process_tcp_responses(int raw_sock, struct sockaddr_in *dest, mapping_entry *lookup,
                           port_result_t results[], int tcp_scan_types) {
    char recv_buf[4096];
    for (int i = 0; i < (1 << 16); i++) {
        if (lookup[i].used)
            usleep(500);
    }
    time_t start_time = time(NULL);
    while ((time(NULL) - start_time) < 3 && tcp_scan_types) {
        ssize_t data_size = recv(raw_sock, recv_buf, sizeof(recv_buf), 0);
        if (data_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) { usleep(10000); continue; }
            else { perror("recv"); break; }
        }
        struct iphdr *rec_iph = (struct iphdr*)recv_buf;
        if (rec_iph->protocol != IPPROTO_TCP)
            continue;
        int iphdrlen = rec_iph->ihl * 4;
        if (data_size < iphdrlen + (int)sizeof(struct tcphdr))
            continue;
        struct tcphdr *rec_tcph = (struct tcphdr*)(recv_buf + iphdrlen);
        if (rec_iph->saddr != dest->sin_addr.s_addr)
            continue;
        int resp_src_port = ntohs(rec_tcph->dest);
        mapping_entry entry = lookup[resp_src_port];
        if (!entry.used)
            continue;
        int scanned_port = entry.dest_port;
        int scan_idx = entry.scan_index;
        /* Update based on received TCP flags */
        if (scan_idx == 0) { /* SYN scan */
            if (rec_tcph->syn && rec_tcph->ack)
                results[scanned_port].results[0] = SCAN_RESULT_OPEN;
            else if (rec_tcph->rst)
                results[scanned_port].results[0] = SCAN_RESULT_CLOSED;
        } else if (scan_idx == 1) { /* NULL scan */
            if (rec_tcph->rst)
                results[scanned_port].results[1] = SCAN_RESULT_CLOSED;
        } else if (scan_idx == 2) { /* ACK scan */
            if (rec_tcph->rst)
                results[scanned_port].results[2] = SCAN_RESULT_UNFILTERED;
        } else if (scan_idx == 3) { /* FIN scan */
            if (rec_tcph->rst)
                results[scanned_port].results[3] = SCAN_RESULT_CLOSED;
        } else if (scan_idx == 4) { /* XMAS scan */
            if (rec_tcph->rst)
                results[scanned_port].results[4] = SCAN_RESULT_CLOSED;
        }
    }
}

/* --- Mark Unanswered TCP Scans --- */
void mark_unanswered_tcp_scans(mapping_entry *lookup, port_result_t results[]) {
    /* For each source port in the lookup table, adjust unanswered responses */
    for (int i = 0; i < (1 << 16); i++) {
        if (lookup[i].used) {
            int port = lookup[i].dest_port;
            int scan_idx = lookup[i].scan_index;
            if (results[port].results[scan_idx] == SCAN_RESULT_NO_RESPONSE) {
                if (scan_idx == 0 || scan_idx == 2)
                    results[port].results[scan_idx] = SCAN_RESULT_FILTERED;
                else if (scan_idx == 1 || scan_idx == 3 || scan_idx == 4)
                    results[port].results[scan_idx] = SCAN_RESULT_OPEN_FILTERED;
            }
        }
    }
}
/* Process UDP responses. */
void process_udp_responses(int udp_sock, uint8_t *ports, port_result_t results[]) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(udp_sock, &readfds);
    struct timeval timeout_udp = {3, 0};
    int ready = select(udp_sock + 1, &readfds, NULL, NULL, &timeout_udp);
    if (ready > 0 && FD_ISSET(udp_sock, &readfds)) {
        char buf[1024];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(udp_sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
        if (n >= 0) {
            int resp_port = ntohs(from.sin_port);
            if (resp_port < PORTS_LEN && ports[resp_port])
                results[resp_port].results[5] = SCAN_RESULT_CLOSED;
        }
    }
}

/* --- Mark Unanswered UDP Scans --- */
void mark_unanswered_udp_scans(uint8_t *ports, port_result_t results[]) {
    for (int port = 0; port < PORTS_LEN; port++) {
        if (!ports[port])
            continue;
        if (results[port].results[5] == SCAN_RESULT_NO_RESPONSE)
            results[port].results[5] = SCAN_RESULT_OPEN_FILTERED;
    }
}

/* --- Refactored sendAllPackets Function --- */
void sendAllPackets(uint32_t ip, uint8_t *ports, int types, port_result_t results[]) {
    uint32_t local_ip = get_local_ip();
    int tcp_scan_types = types & (SCAN_SYN | SCAN_NULL | SCAN_ACK | SCAN_FIN | SCAN_XMAS);
    int do_udp = (types & SCAN_UDP) ? 1 : 0;
    int raw_sock = -1, udp_sock = -1;

    if (tcp_scan_types) {
        raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (raw_sock < 0) { perror("raw socket"); exit(1); }
        int one = 1;
        if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt");
            close(raw_sock);
            exit(1);
        }
        set_nonblocking(raw_sock);
    }
    if (do_udp) {
        udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_sock < 0)
            perror("UDP socket");
        else
            set_nonblocking(udp_sock);
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip;

    /* Initialize results to NO_RESPONSE for all scans */
    for (int i = 0; i < PORTS_LEN; i++) {
        results[i].port = i;
        for (int j = 0; j < NUM_SCAN_TYPES; j++)
            results[i].results[j] = SCAN_RESULT_NO_RESPONSE;
    }

    mapping_entry *lookup = calloc(1 << 16, sizeof(mapping_entry));
    if (!lookup) { perror("calloc lookup"); exit(1); }

    /* For each port, send TCP and/or UDP packets */
    for (int port = 1; port < PORTS_LEN; port++) {
        if (!ports[port])
            continue;
        dest.sin_port = htons(port);
        if (tcp_scan_types)
            send_tcp_packets_for_port(raw_sock, &dest, local_ip, port, tcp_scan_types, lookup);
        if (do_udp)
            send_udp_packet(udp_sock, &dest, port);
    }

    /* Process TCP responses and mark unanswered scans */
    process_tcp_responses(raw_sock, &dest, lookup, results, tcp_scan_types);
    mark_unanswered_tcp_scans(lookup, results);

    /* Process UDP responses */
    if (do_udp) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(udp_sock, &readfds);
        struct timeval timeout_udp = {3, 0};
        int ready = select(udp_sock + 1, &readfds, NULL, NULL, &timeout_udp);
        if (ready > 0 && FD_ISSET(udp_sock, &readfds)) {
            char buf[1024];
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            ssize_t n = recvfrom(udp_sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
            if (n >= 0) {
                int resp_port = ntohs(from.sin_port);
                if (resp_port < PORTS_LEN && ports[resp_port])
                    results[resp_port].results[5] = SCAN_RESULT_CLOSED;
            }
        }
        mark_unanswered_udp_scans(ports, results);
        close(udp_sock);
    }
    if (tcp_scan_types)
        close(raw_sock);
    free(lookup);
}

void print_scan_results(port_result_t results[], size_t len, uint8_t *ports, int scan_types) {
    (void)len;
    printf("Scan results:\n");
    for (int i = 0; i < PORTS_LEN; i++) {
        if (ports[i] != 1)
            continue;
        printf("Port %d:\n", i);
        if (scan_types & SCAN_SYN)
            printf("  SYN:   %s\n", result_to_string(results[i].results[0]));
        if (scan_types & SCAN_NULL)
            printf("  NULL:  %s\n", result_to_string(results[i].results[1]));
        if (scan_types & SCAN_ACK)
            printf("  ACK:   %s\n", result_to_string(results[i].results[2]));
        if (scan_types & SCAN_FIN)
            printf("  FIN:   %s\n", result_to_string(results[i].results[3]));
        if (scan_types & SCAN_XMAS)
            printf("  XMAS:  %s\n", result_to_string(results[i].results[4]));
        if (scan_types & SCAN_UDP)
            printf("  UDP:   %s\n", result_to_string(results[i].results[5]));
    }
}

void nmap_performance() {
    struct in_addr src_addr;
    src_addr.s_addr = get_local_ip();
    printf("Local IP: %s\n", inet_ntoa(src_addr));
    port_result_t results[PORTS_LEN];
    memset(results, 0, sizeof(results));
    t_destlst *dest = g_data.opts.host_destlsthdr;
    while (dest) {
        sendAllPackets(dest->dest_ip.sin_addr.s_addr, g_data.opts.ports, g_data.opts.scan_types, results);
        dest = dest->next;
    }
    print_scan_results(results, PORTS_LEN, g_data.opts.ports, g_data.opts.scan_types);
}