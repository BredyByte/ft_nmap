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
#include <time.h>


# define PROTO_TCP IPPROTO_TCP
# define PROTO_UDP IPPROTO_UDP
# define PORTS_LEN 1025

typedef enum	e_scan_type
{
    SCAN_SYN   = 1 << 0,   // 00000001 = 1
    SCAN_NULL  = 1 << 1,   // 00000010 = 2
    SCAN_ACK   = 1 << 2,   // 00000100 = 4
    SCAN_FIN   = 1 << 3,   // 00001000 = 8
    SCAN_XMAS  = 1 << 4,   // 00010000 = 16
    SCAN_UDP   = 1 << 5    // 00100000 = 32
}   t_scan_type;

typedef struct	s_destlst
{
	char				*hostname;
	struct sockaddr_in	dest_ip;
	struct s_destlst	*next;
}	t_destlst;

typedef struct	s_opts
{
	bool		port_flag;
	bool		file_flag;
	bool		ip_flag;
	uint8_t		ports[PORTS_LEN];
	t_destlst	*host_destlsthdr;
	uint8_t		thrnum;
	uint8_t     scan_types;
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
