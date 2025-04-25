#include "defines.h"
#include "utils.h"

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

        // Find an unused random source port for this scan
        int src_port;
        do {
            src_port = 1024 + rand() % (65535 - 1024);
        } while (lookup[src_port].used);

        // Store mapping for response matching
        lookup[src_port].used = 1;
        lookup[src_port].dest_port = port;
        lookup[src_port].scan_index = scan_idx;

        /* Update fields that vary per packet */
        prepare_tcp_header(tcph, src_port, port, flag);
        iph->id = htons(rand() % 65535);
        iph->check = csum((unsigned short*)iph, sizeof(struct iphdr));
        tcph->check = compute_tcp_checksum(iph, tcph);

        // Wait until socket is writable
        while (1) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(raw_sock, &wfds);
            struct timeval tv = {0, 10000}; // 10ms
            int ready = select(raw_sock + 1, NULL, &wfds, NULL, &tv);
            if (ready > 0 && FD_ISSET(raw_sock, &wfds)) {
                if (sendto(raw_sock, packet, hdr_len, 0, (struct sockaddr*)dest, sizeof(*dest)) < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        continue; // Try again
                    perror("sendto");
                }
                break;
            }
        }
    }
}

void send_udp_packet(int udp_sock, struct sockaddr_in *dest, int port) {
    dest->sin_port = htons(port);
    const char *data = "UDP";
    while (1) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(udp_sock, &wfds);
        struct timeval tv = {0, 10000}; // 10ms
        int ready = select(udp_sock + 1, NULL, &wfds, NULL, &tv);
        if (ready > 0 && FD_ISSET(udp_sock, &wfds)) {
            if (sendto(udp_sock, data, strlen(data), 0, (struct sockaddr*)dest, sizeof(*dest)) < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    continue; // Try again
                perror("sendto UDP");
                printf("port: %d\n", ntohs(dest->sin_port));
            }
            break;
        }
    }
}


/* --- Process TCP Responses --- */

void process_tcp_responses(int raw_sock, struct sockaddr_in *dest, mapping_entry *lookup,
    port_result_t **results, int tcp_scan_types) {
(void)tcp_scan_types;
char recv_buf[4096];
struct timeval timeout;
timeout.tv_sec = 0;
timeout.tv_usec = 300000; // 300 ms timeout

fd_set readfds;

while (1) {
FD_ZERO(&readfds);
FD_SET(raw_sock, &readfds);

int sel = select(raw_sock + 1, &readfds, NULL, NULL, &timeout);
if (sel < 0) {
perror("select");
break;
} else if (sel == 0) {
// Timeout expired, no more packets
break;
}

ssize_t data_size = recv(raw_sock, recv_buf, sizeof(recv_buf), 0);
if (data_size <= 0) {
if (errno == EAGAIN || errno == EWOULDBLOCK)
continue;
perror("recv");
break;
}

struct iphdr *ip_hdr = (struct iphdr *)recv_buf;
if (ip_hdr->protocol != IPPROTO_TCP)
continue;

int iphdr_len = ip_hdr->ihl * 4;
if (data_size < iphdr_len + (int)sizeof(struct tcphdr))
continue;

struct tcphdr *tcp_hdr = (struct tcphdr *)(recv_buf + iphdr_len);

// Check if packet is from the target IP
if (ip_hdr->saddr != dest->sin_addr.s_addr)
continue;

uint16_t resp_src_port = ntohs(tcp_hdr->dest);
mapping_entry entry = lookup[resp_src_port];
if (!entry.used)
continue;

int scanned_port = entry.dest_port;
int scan_idx = entry.scan_index;

// Find the index in the results array for this port
int i;
for (i = 0; results[i] != NULL; ++i) {
if (results[i]->port == scanned_port)
break;
}
if (results[i] == NULL)
continue; // Not a tracked port

// Update results based on received TCP flags
switch (scan_idx) {
case 0: // SYN scan
if (tcp_hdr->syn && tcp_hdr->ack) {
results[i]->results[scan_idx] = SCAN_RESULT_OPEN;
} else if (tcp_hdr->rst)
results[i]->results[scan_idx] = SCAN_RESULT_CLOSED;
break;
case 1: // NULL scan
case 3: // FIN scan
case 4: // XMAS scan
if (tcp_hdr->rst)
results[i]->results[scan_idx] = SCAN_RESULT_CLOSED;
break;
case 2: // ACK scan
if (tcp_hdr->rst)
results[i]->results[scan_idx] = SCAN_RESULT_UNFILTERED;
break;
}
}
}


/* --- Mark Unanswered TCP Scans --- */
void mark_unanswered_tcp_scans(mapping_entry *lookup, port_result_t **results) {
    // For each possible source port, check if we sent a probe and got no response
    for (int i = 0; i < (1 << 16); i++) {
        if (lookup[i].used) {
            int scanned_port = lookup[i].dest_port;
            int scan_idx = lookup[i].scan_index;

            // Find the index in the results array for this port
            int j;
            for (j = 0; results[j] != NULL; ++j) {
                if (results[j]->port == scanned_port)
                    break;
            }
            if (results[j] == NULL)
                continue; // Not a tracked port

            if (results[j]->results[scan_idx] == SCAN_RESULT_NO_RESPONSE) {
                if (scan_idx == 0 || scan_idx == 2) // SYN or ACK scan
                    results[j]->results[scan_idx] = SCAN_RESULT_FILTERED;
                else if (scan_idx == 1 || scan_idx == 3 || scan_idx == 4) // NULL, FIN, XMAS
                    results[j]->results[scan_idx] = SCAN_RESULT_OPEN_FILTERED;
            }
        }
    }
}

/* --- Mark Unanswered UDP Scans --- */
void mark_unanswered_udp_scans(uint32_t port, port_result_t results[]) {
    if (results[port].results[5] == SCAN_RESULT_NO_RESPONSE)
        results[port].results[5] = SCAN_RESULT_OPEN_FILTERED;
}

#include <fcntl.h>

void process_udp_responses(int udp_sock, port_result_t **results, int *ports) {
    // Set socket to non-blocking
    int flags = fcntl(udp_sock, F_GETFL, 0);
    fcntl(udp_sock, F_SETFL, flags | O_NONBLOCK);

    fd_set readfds;
    struct timeval timeout_udp = {0, 300000}; // 300ms timeout

    char buf[1024];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    int total_ports = 0;
    for (int i = 0; ports[i] != 0; ++i) total_ports++;

    int *responded = calloc(total_ports, sizeof(int));
    if (!responded) {
        perror("calloc");
        return;
    }

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(udp_sock, &readfds);

        int ready = select(udp_sock + 1, &readfds, NULL, NULL, &timeout_udp);
        if (ready < 0) {
            perror("select");
            break;
        } else if (ready == 0) {
            // Timeout reached
            break;
        }

        ssize_t n = recvfrom(udp_sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
        if (n >= 0) {
            int resp_port = ntohs(from.sin_port);
            // Find which scanned port this response matches
            for (int i = 0; i < total_ports; ++i) {
                if (!responded[i] && ports[i] == resp_port) {
                    results[i]->results[5] = SCAN_RESULT_OPEN;  // <-- Mark as OPEN
                    responded[i] = 1;
                    break;
                }
            }
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recvfrom");
            break;
        }
    }

    // Mark unanswered UDP scans as open|filtered, but only if not already set by ICMP as CLOSED
    for (int i = 0; i < total_ports; ++i) {
        if (!responded[i] && results[i]->results[5] == SCAN_RESULT_NO_RESPONSE) {
            results[i]->results[5] = SCAN_RESULT_OPEN_FILTERED;
        }
    }

    free(responded);
}

#include <netinet/udp.h>

/* --- Refactored sendAllPackets Function --- */
void process_icmp_responses(int icmp_sock, port_result_t **results, int *ports) {
    char buf[1024];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    // Nmap waits several seconds for ICMP errors due to rate-limiting (default is 3-10s)
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 3000;

    fd_set readfds;
    int total_ports = 0;
    for (int i = 0; ports[i] != 0; ++i) total_ports++;

    // Track which ports have been marked closed
    int *closed = calloc(total_ports, sizeof(int));
    if (!closed) {
        perror("calloc");
        return;
    }

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(icmp_sock, &readfds);

        int sel = select(icmp_sock + 1, &readfds, NULL, NULL, &timeout);
        if (sel < 0) {
            perror("select");
            break;
        } else if (sel == 0) {
            // Timeout
            break;
        }

        ssize_t n = recvfrom(icmp_sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            perror("recvfrom");
            break;
        }

        struct iphdr *ip = (struct iphdr *)buf;
        int iphdrlen = ip->ihl * 4;
        struct icmphdr *icmp = (struct icmphdr *)(buf + iphdrlen);

        // Only process ICMP Destination Unreachable, Port Unreachable
        if (icmp->type == 3 && icmp->code == 3) {
            // ICMP payload contains the original IP header + 8 bytes of UDP header
            unsigned char *data = (unsigned char *)buf + iphdrlen + sizeof(struct icmphdr);
            struct iphdr *orig_ip = (struct iphdr *)data;
            int orig_iphdrlen = orig_ip->ihl * 4;
            struct udphdr *orig_udp = (struct udphdr *)(data + orig_iphdrlen);

            int dport = ntohs(orig_udp->dest);

            // Find which scanned port this matches
            for (int i = 0; i < total_ports; ++i) {
                if (!closed[i] && ports[i] == dport) {
                    results[i]->results[5] = SCAN_RESULT_CLOSED;
                    closed[i] = 1;
                    break;
                }
            }
        }
    }

    free(closed);
}


void sendAllPackets(uint32_t ip, int *ports, port_result_t **results, uint32_t local_ip) {
    int tcp_scan_types = g_data.opts.scan_types;
    int do_udp = (tcp_scan_types & SCAN_UDP) ? 1 : 0;
    tcp_scan_types &= ~SCAN_UDP;
    int raw_sock = -1, udp_sock = -1, icmp_sock = -1;

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

        // Open ICMP socket for UDP closed detection
        icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (icmp_sock < 0)
            perror("ICMP socket");
        else
            set_nonblocking(icmp_sock);
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip;

    // Allocate lookup table for TCP scans
    mapping_entry *lookup = NULL;
    if (tcp_scan_types) {
        lookup = calloc(1 << 16, sizeof(mapping_entry));
        if (!lookup) { perror("calloc lookup"); exit(1); }
    }

    // Send all packets first
    for (int i = 0; ports[i] != 0; ++i) {
        dest.sin_port = htons(ports[i]);
        if (tcp_scan_types)
            send_tcp_packets_for_port(raw_sock, &dest, local_ip, ports[i], tcp_scan_types, lookup);
        if (do_udp)
            send_udp_packet(udp_sock, &dest, ports[i]);
    }

    // Process TCP responses and mark unanswered scans
    if (tcp_scan_types) {
        process_tcp_responses(raw_sock, &dest, lookup, results, tcp_scan_types);
        mark_unanswered_tcp_scans(lookup, results);
    }

    // Process ICMP errors (UDP closed) and UDP replies (UDP open)
    if (do_udp) {
        process_udp_responses(udp_sock, results, ports); // Does not work for OPEN, as I need to send a DNS query and will only work for that port (What Nmap does)
        process_icmp_responses(icmp_sock, results, ports);
    }

    if (tcp_scan_types) {
        close(raw_sock);
        free(lookup);
    }
    if (do_udp) {
        close(udp_sock);
        if (icmp_sock >= 0)
            close(icmp_sock);
    }
}


void print_scan_results() {
    for (t_destlst *ptr = g_data.opts.host_destlsthdr; ptr; ptr = ptr->next) {
        printf("IP address: %s\n", inet_ntoa(ptr->dest_ip.sin_addr));
        printf("Port\tService Name\t\tResults\n");
        printf("--------------------------------------------------------------\n");

        for (int i = 1; i < PORTS_LEN; ++i) {
            if (!g_data.opts.ports[i].is_active)
                continue;


            const char *service = g_data.opts.ports[i].service_name
                                      ? g_data.opts.ports[i].service_name
                                      : "Unknown";

            printf("%-5d\t%-16s\t", i, service);  // Print port and service once

            char result_buf[64];
            bool printed_any = false;

            if (g_data.opts.scan_types & SCAN_SYN) {
                snprintf(result_buf, sizeof(result_buf), "SYN(%s)",
                         result_to_string(ptr->results[i].results[0]));
                printf("%s  ", result_buf);
                printed_any = true;
            }
            if (g_data.opts.scan_types & SCAN_NULL) {
                snprintf(result_buf, sizeof(result_buf), "NULL(%s)",
                         result_to_string(ptr->results[i].results[1]));
                printf(printed_any ? "%s  " : "%s  ", result_buf);
                printed_any = true;
            }
            if (g_data.opts.scan_types & SCAN_ACK) {
                snprintf(result_buf, sizeof(result_buf), "ACK(%s)",
                         result_to_string(ptr->results[i].results[2]));
                printf("%s  ", result_buf);
            }
            if (g_data.opts.scan_types & SCAN_FIN) {
                snprintf(result_buf, sizeof(result_buf), "FIN(%s)",
                         result_to_string(ptr->results[i].results[3]));
                printf("%s  ", result_buf);
            }
            if (g_data.opts.scan_types & SCAN_XMAS) {
                snprintf(result_buf, sizeof(result_buf), "XMAS(%s)",
                         result_to_string(ptr->results[i].results[4]));
                printf("%s  ", result_buf);
            }
            if (g_data.opts.scan_types & SCAN_UDP) {
                snprintf(result_buf, sizeof(result_buf), "UDP(%s)",
                         result_to_string(ptr->results[i].results[5]));
                printf("%s  ", result_buf);
            }

            printf("\n\n");
        }
    }
}

void nmap_performance(void *ip) {
    uint32_t local_ip = *(uint32_t*)ip;

    t_queue_node *node = dequeue();


    while (node) {
        // node->ports is uint16_t* terminated by 0
        // node->results is port_result_t** terminated by NULL
        sendAllPackets(node->ip, node->ports, node->results, local_ip);


        t_destlst *ip = g_data.opts.host_destlsthdr;
        while (ip)
        {
            if (ip->dest_ip.sin_addr.s_addr == (unsigned int)node->ip){
                for (int i = 0; node->results[i] != 0; ++i)
                    ip->results[node->results[i]->port] = *node->results[i];
                break ;
            }
            ip = ip->next;
        }

        for (int i = 0; node->ports[i] != 0; i++) {
            free(node->results[i]);
        }
        free(node->results);
        free(node->ports);
        free(node);

        node = dequeue();
    }
}
