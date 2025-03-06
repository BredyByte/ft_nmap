#include "defines.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void	nmap_performance(){
        return;
    }


/* --- Unified Send Function --- */
// Uses an existing socket and destination to send data.
int send_packet(int sock, int protocol, const char *data, size_t data_len, struct sockaddr_in *dest) {
    if (protocol == PROTO_TCP) {
        send(sock, data, data_len, 0);
    } else if (protocol == PROTO_UDP) {
        sendto(sock, data, data_len, 0, (struct sockaddr *)dest, sizeof(*dest));
    }
    return 0;
}

/* --- Helper: compute checksum --- */
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

/* --- Packet-Specific Send Functions --- */
// TCP pseudo-header structure for checksum calculation.
struct pseudo_header {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
};

void sendSyn(int sock, struct sockaddr_in *dest, int ip) {
    // Allocate space for IP + TCP headers.
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    // Fill in the IP header.
    struct iphdr *iph = (struct iphdr *)packet;
    iph->ihl = 5;  
    iph->version = 4;
    iph->tot_len = htons(sizeof(packet));
    iph->id = htons(54321);  
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = ip;  // Update source IP.
    iph->daddr = dest->sin_addr.s_addr;
    iph->check = 0;
    iph->check = checksum(iph, sizeof(struct iphdr));

    // Fill in the TCP header.
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcph->source = htons(12345);  // Arbitrary source port.
    tcph->dest = dest->sin_port;
    tcph->seq = htonl(rand());  // Random sequence number.
    tcph->ack_seq = 0;
    tcph->doff = 5;  // TCP header size.
    tcph->syn = 1;   // SYN flag set.
    tcph->window = htons(5840);
    tcph->check = 0;

    // Calculate TCP checksum.
    struct pseudo_header psh;
    psh.saddr = iph->saddr;
    psh.daddr = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(psh) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr));
    tcph->check = checksum(pseudogram, psize);
    free(pseudogram);

    // Send the packet.
    send_packet(sock, PROTO_TCP, packet, sizeof(packet), dest);
}

void sendNull(int sock, struct sockaddr_in *dest, int ip) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct iphdr *iph = (struct iphdr *)packet;
    iph->ihl = 5;  
    iph->version = 4;
    iph->tot_len = htons(sizeof(packet));
    iph->id = htons(54321);  
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = ip;
    iph->daddr = dest->sin_addr.s_addr;
    iph->check = 0;
    iph->check = checksum(iph, sizeof(struct iphdr));

    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcph->source = htons(12345);
    tcph->dest = dest->sin_port;
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->rst = 1;  // RST flag (acts like a NULL scan).
    tcph->window = htons(5840);
    tcph->check = 0;

    struct pseudo_header psh;
    psh.saddr = iph->saddr;
    psh.daddr = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(psh) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr));
    tcph->check = checksum(pseudogram, psize);
    free(pseudogram);

    send_packet(sock, PROTO_TCP, packet, sizeof(packet), dest);
}

void sendAck(int sock, struct sockaddr_in *dest, int ip) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct iphdr *iph = (struct iphdr *)packet;
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(packet));
    iph->id = htons(54321);  
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = ip;
    iph->daddr = dest->sin_addr.s_addr;
    iph->check = 0;
    iph->check = checksum(iph, sizeof(struct iphdr));

    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcph->source = htons(12345);
    tcph->dest = dest->sin_port;
    tcph->seq = htonl(rand());
    tcph->ack_seq = htonl(rand());
    tcph->doff = 5;
    tcph->ack = 1;  // ACK flag set.
    tcph->window = htons(5840);
    tcph->check = 0;

    struct pseudo_header psh;
    psh.saddr = iph->saddr;
    psh.daddr = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(psh) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr));
    tcph->check = checksum(pseudogram, psize);
    free(pseudogram);

    send_packet(sock, PROTO_TCP, packet, sizeof(packet), dest);
}

void sendFin(int sock, struct sockaddr_in *dest, int ip) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct iphdr *iph = (struct iphdr *)packet;
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(packet));
    iph->id = htons(54321);  
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = ip;
    iph->daddr = dest->sin_addr.s_addr;
    iph->check = 0;
    iph->check = checksum(iph, sizeof(struct iphdr));

    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcph->source = htons(12345);
    tcph->dest = dest->sin_port;
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 1;  // FIN flag set.
    tcph->window = htons(5840);
    tcph->check = 0;

    struct pseudo_header psh;
    psh.saddr = iph->saddr;
    psh.daddr = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(psh) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr));
    tcph->check = checksum(pseudogram, psize);
    free(pseudogram);

    send_packet(sock, PROTO_TCP, packet, sizeof(packet), dest);
}

void sendXmas(int sock, struct sockaddr_in *dest, int ip) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct iphdr *iph = (struct iphdr *)packet;
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(packet));
    iph->id = htons(54321);  
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = ip;
    iph->daddr = dest->sin_addr.s_addr;
    iph->check = 0;
    iph->check = checksum(iph, sizeof(struct iphdr));

    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcph->source = htons(12345);
    tcph->dest = dest->sin_port;
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 1;   // FIN flag set.
    tcph->urg = 1;   // URG flag set.
    tcph->psh = 1;   // PSH flag set.
    tcph->window = htons(5840);
    tcph->check = 0;

    struct pseudo_header psh;
    psh.saddr = iph->saddr;
    psh.daddr = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(psh) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr));
    tcph->check = checksum(pseudogram, psize);
    free(pseudogram);

    send_packet(sock, PROTO_TCP, packet, sizeof(packet), dest);
}

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

void sendUdp(int sock, struct sockaddr_in *dest, int ip) {
    (void)ip;
    const char *data = "UDP";
    send_packet(sock, PROTO_UDP, data, strlen(data), dest);
}

/* --- Mapping Structure --- */
typedef void (*packet_func)(int, struct sockaddr_in*, int);

typedef struct {
    int type;          // e.g. SCAN_SYN, etc.
    packet_func func;
} TypeMapping;

static const TypeMapping mappings[] = {
    { SCAN_SYN,  sendSyn },
    { SCAN_NULL, sendNull },
    { SCAN_ACK,  sendAck },
    { SCAN_FIN,  sendFin },
    { SCAN_XMAS, sendXmas },
    { SCAN_UDP,  sendUdp }
};

/* --- Result Data Structures --- */
// Fast structure: one result per port with an array (indexed by mapping order)
// to hold the outcome for each scan type.
typedef enum {
    SCAN_RESULT_OPEN,
    SCAN_RESULT_FILTERED,
    SCAN_RESULT_UNFILTERED,
    SCAN_RESULT_CLOSED
} scan_result_t;

#define NUM_SCAN_TYPES 6  // Order: SYN, NULL, ACK, FIN, XMAS, UDP

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

/* --- Helper Function: Set Non-blocking --- */
int set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

/* --- sendAllPackets --- 
 * For a given IP and array of ports, this function:
 * 1. Opens one UDP socket for the IP (if any UDP scan requested).
 * 2. For each port that requires a TCP scan (any of SYN, NULL, ACK, FIN, XMAS),
 *    opens one TCP raw socket, sets IP_HDRINCL, connects, and sends the corresponding packets.
 * 3. After sending, uses select() to wait for responses (for up to 3 seconds)
 *    on all open sockets.
 * 4. Updates a fast array (one entry per port) with the scan results.
 *
 * The interpretation here is simplified:
 *   - For TCP: if the socket is readable and recv() returns >0, mark as OPEN;
 *     if recv() returns 0, mark as UNFILTERED;
 *     if error is detected, mark as CLOSED;
 *     if no response, mark as FILTERED.
 *   - For UDP: if a response is received, mark that port’s UDP result as CLOSED,
 *     otherwise FILTERED.
 */
void sendAllPackets(uint32_t ip, uint8_t *ports, int types, port_result_t results[]) {
    int udp_sock = -1;
    tcp_sock_info_t *tcp_infos = calloc(PORTS_LEN, sizeof(tcp_sock_info_t));
    size_t tcp_count = 0;
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip;
    int s_ip = get_local_ip();

    // Initialize results array.
    for (size_t i = 0; i < PORTS_LEN; i++) {
        results[i].port = i;
        for (int j = 0; j < NUM_SCAN_TYPES; j++)
            results[i].results[j] = SCAN_RESULT_CLOSED;
    }

    // Open UDP socket if UDP scan is requested.
    if (types & SCAN_UDP) {
        udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_sock < 0) {
            perror("UDP socket");
        } else {
            set_nonblocking(udp_sock);
        }
    }

    // For TCP scans (SYN, NULL, ACK, FIN, XMAS) open one TCP raw socket per port.
    int tcp_scan_types = types & (SCAN_SYN | SCAN_NULL | SCAN_ACK | SCAN_FIN | SCAN_XMAS);
    for (size_t i = 0; i < PORTS_LEN; i++) {
        if (ports[i] == 0)
            continue;
        dest.sin_port = htons(ports[i]);

        if (tcp_scan_types) {
            int tcp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            if (tcp_sock < 0) {
                perror("TCP socket");
                // Mark each requested TCP scan type as CLOSED for this port.
                for (int k = 0; k < NUM_SCAN_TYPES - 1; k++) { // indices 0-4 are TCP types
                    if (types & mappings[k].type)
                        results[i].results[k] = SCAN_RESULT_CLOSED;
                }
                continue;
            }
            int one = 1;
            if (setsockopt(tcp_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
                perror("setsockopt");
                for (int k = 0; k < NUM_SCAN_TYPES - 1; k++) {
                    if (types & mappings[k].type)
                        results[i].results[k] = SCAN_RESULT_CLOSED;
                }
                close(tcp_sock);
                continue;
            }
            set_nonblocking(tcp_sock);
            int ret = connect(tcp_sock, (struct sockaddr *)&dest, sizeof(dest));
            if (ret < 0 && errno != EINPROGRESS) {
                // Immediate connection failure.
                for (int k = 0; k < NUM_SCAN_TYPES - 1; k++) {
                    if (types & mappings[k].type)
                        results[i].results[k] = (errno == ECONNREFUSED) ? SCAN_RESULT_CLOSED : SCAN_RESULT_FILTERED;
                }
                close(tcp_sock);
                continue;
            }
            // Send all TCP scan packets for this port.
            for (size_t j = 0; j < sizeof(mappings)/sizeof(mappings[0]); j++) {
                if (mappings[j].type != SCAN_UDP && (types & mappings[j].type))
                    mappings[j].func(tcp_sock, &dest, s_ip);
            }
            // Save TCP socket info.
            tcp_infos[tcp_count].sock = tcp_sock;
            tcp_infos[tcp_count].port = ports[i];
            tcp_infos[tcp_count].scan_mask = tcp_scan_types;
            tcp_count++;
        }

        // For UDP: send a UDP packet for each port using the single UDP socket.
        if ((types & SCAN_UDP) && udp_sock >= 0)
            mappings[5].func(udp_sock, &dest, s_ip); // index 5 corresponds to SCAN_UDP.
    }

    /* --- Receive Responses --- */
    fd_set readfds;
    int maxfd = -1;
    struct timeval timeout = {3, 0};  // wait up to 3 seconds
    FD_ZERO(&readfds);
    // Add TCP sockets.
    for (size_t i = 0; i < tcp_count; i++) {
        FD_SET(tcp_infos[i].sock, &readfds);
        if (tcp_infos[i].sock > maxfd) maxfd = tcp_infos[i].sock;
    }
    // Add UDP socket.
    if (udp_sock >= 0) {
        FD_SET(udp_sock, &readfds);
        if (udp_sock > maxfd) maxfd = udp_sock;
    }
    int ready = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
    if (ready < 0)
        perror("select");

    char buf[1024];
    // Process TCP responses.
    printf("tcp_count: %zu\n", tcp_count);
    for (size_t i = 0; i < tcp_count; i++) {
        int s = tcp_infos[i].sock;
        // Find corresponding result entry for this port.
        size_t res_index = 0;
        for (size_t j = 0; j < PORTS_LEN; j++) {
            if (results[j].port == tcp_infos[i].port) {
                res_index = j;
                break;
            }
        }
        if (FD_ISSET(s, &readfds)) {
            ssize_t n = recv(s, buf, sizeof(buf), 0);
            if(n > 0) {
                buf[n] = '\0';
                printf("Received: %s\n", buf);
                // Data received; mark all TCP scan types as OPEN.
                for (int k = 0; k < NUM_SCAN_TYPES - 1; k++) {
                    if (tcp_infos[i].scan_mask & mappings[k].type)
                        results[res_index].results[k] = SCAN_RESULT_OPEN;
                }
            } else if (n == 0) {
                // Connection closed gracefully; mark as UNFILTERED.
                for (int k = 0; k < NUM_SCAN_TYPES - 1; k++) {
                    if (tcp_infos[i].scan_mask & mappings[k].type)
                        results[res_index].results[k] = SCAN_RESULT_UNFILTERED;
                }
            } else {
                // recv error; mark as CLOSED.
                for (int k = 0; k < NUM_SCAN_TYPES - 1; k++) {
                    if (tcp_infos[i].scan_mask & mappings[k].type)
                        results[res_index].results[k] = SCAN_RESULT_CLOSED;
                }
            }
        } else {
            // No response: mark as FILTERED.
            printf("FD not set? %d\n", tcp_infos[i].port);
            for (int k = 0; k < NUM_SCAN_TYPES - 1; k++) {
                if (tcp_infos[i].scan_mask & mappings[k].type)
                    results[res_index].results[k] = SCAN_RESULT_FILTERED;
            }
        }
        close(s);
    }
    free(tcp_infos);

    // Process UDP responses.
    if (udp_sock >= 0 && FD_ISSET(udp_sock, &readfds)) {
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(udp_sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
        if (n >= 0) {
            // Use the source port of the response to update the corresponding entry.
            int resp_port = ntohs(from.sin_port);
            for (size_t i = 0; i < PORTS_LEN; i++) {
                if (results[i].port == resp_port) {
                    results[i].results[5] = SCAN_RESULT_CLOSED; // UDP scan result slot.
                    break;
                }
            }
        } else {
            // No UDP response: mark all UDP results as FILTERED.
            for (size_t i = 0; i < PORTS_LEN; i++) {
                if (types & SCAN_UDP)
                    results[i].results[5] = SCAN_RESULT_FILTERED;
            }
        }
        close(udp_sock);
    } else if (udp_sock >= 0) {
        for (size_t i = 0; i < PORTS_LEN; i++) {
            if (types & SCAN_UDP)
                results[i].results[5] = SCAN_RESULT_FILTERED;
        }
        close(udp_sock);
    }
}

const char *result_to_string(scan_result_t res) {
    switch (res) {
        case SCAN_RESULT_OPEN:         return "OPEN";
        case SCAN_RESULT_FILTERED:     return "FILTERED";
        case SCAN_RESULT_UNFILTERED:   return "UNFILTERED";
        case SCAN_RESULT_CLOSED:       return "CLOSED";
        default:                       return "UNKNOWN";
    }
}

/* --- Example: Printing the Results --- */
void print_scan_results(port_result_t results[], size_t len, uint8_t *ports, int scan_types) {
    // Print results only for the scanned ports.
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
/*
int main(void) {
    // Set target IP (for example, localhost).
    uint32_t ip = inet_addr("50.28.12.130");

    // Create ports array of 1025 entries.
    // Each index represents a port number; value 0 means do not scan, 1 means scan.
    uint8_t ports[PORTS_LEN];
    memset(ports, 0, sizeof(ports));

    // Mark some ports to scan (for example, ports 22, 80, and 443).
    ports[22] = 1;
    ports[80] = 1;
    ports[443] = 1;

    // Choose scan types (bitmask combining all desired types).
    // These constants (SCAN_SYN, SCAN_NULL, etc.) should be defined in "defines.h".
    int scan_types = SCAN_SYN;

    // Create results array for PORTS_LEN ports.
    port_result_t results[PORTS_LEN];
    memset(results, 0, sizeof(results));

    struct in_addr ip_addr;
    ip_addr.s_addr = get_local_ip();
    printf("Local IP: %s\n", inet_ntoa(ip_addr));


    printf("Starting scan on IP: %s\n", inet_ntoa(*(struct in_addr *)&ip));
    sendAllPackets(ip, ports, scan_types, results);
    print_scan_results(results, PORTS_LEN, ports, scan_types);

    return 0;
}*/
