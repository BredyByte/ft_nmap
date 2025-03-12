# ifndef DEFINES_H
# define DEFINES_H

# include <arpa/inet.h>
# include <sys/socket.h>
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <unistd.h>
# include <errno.h>
# include <fcntl.h>
# include <sys/select.h>
# include <sys/time.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <stdbool.h>
# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <errno.h>
# include <fcntl.h>
# include <arpa/inet.h>
# include <unistd.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <pthread.h>

# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <unistd.h>
# include <errno.h>
# include <time.h>
# include <arpa/inet.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <sys/socket.h>
# include <time.h>
# include <limits.h>

# define PROTO_TCP IPPROTO_TCP
# define PROTO_UDP IPPROTO_UDP
# define PORTS_LEN 1025
# define NUM_SCAN_TYPES 6  // Order: SYN, NULL, ACK, FIN, XMAS, UDP

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

typedef enum	e_scan_type
{
    SCAN_SYN   = 1 << 0,   // 00000001 = 1
    SCAN_NULL  = 1 << 1,   // 00000010 = 2
    SCAN_ACK   = 1 << 2,   // 00000100 = 4
    SCAN_FIN   = 1 << 3,   // 00001000 = 8
    SCAN_XMAS  = 1 << 4,   // 00010000 = 16
    SCAN_UDP   = 1 << 5    // 00100000 = 32
}   t_scan_type;

typedef struct s_queue_node {
    int ip;
    int port;
    struct s_queue_node *next;
} t_queue_node;

// FIFO queue structure with pointers to head and tail nodes
typedef struct s_queue {
    t_queue_node *head;
    t_queue_node *tail;
} t_queue;

typedef struct	s_destlst
{
	char				*hostname;
	struct sockaddr_in	dest_ip;
	struct s_destlst	*next;
}	t_destlst;

typedef struct s_port_info
{
    bool            is_active;
    const char      *service_name;
}   t_port_info;

typedef struct	s_opts
{
	bool		port_flag;
	bool		file_flag;
	bool		ip_flag;
	t_port_info ports[PORTS_LEN];
	t_destlst	*host_destlsthdr;
	uint8_t		thrnum;
	uint8_t     scan_types;
    port_result_t results[PORTS_LEN];
    t_queue queue;
    //mutex
    pthread_mutex_t mutex;
}	t_opts;

	/*
	to applie scan type / how bit mask works
		opts.scan_types |= SCAN_SYN;	// activate SYN-scan
		opts.scan_types |= SCAN_NULL;	// activate NULL-scan
		opts.scan_types &= ~SCAN_NULL;	// desactivate NULL-scan

	to check if is applied
		if (opts.scan_types & SCAN_SYN)
			printf("SYN scan is enabled\n");

		if (opts.scan_types & SCAN_UDP)
			printf("UDP scan is enabled\n");

	check if the few scans are activated at the same time
		if (opts.scan_types & (SCAN_SYN | SCAN_ACK))
			printf("SYN or ACK scan is enabled\n");
	*/

typedef struct	s_nmap
{
	t_opts	opts;
}	t_nmap;

# endif
