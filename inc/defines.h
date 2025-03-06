# ifndef DEFINES_H
# define DEFINES_H

# include <arpa/inet.h>
# include <sys/socket.h>

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
	uint8_t		ports[1025];
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
