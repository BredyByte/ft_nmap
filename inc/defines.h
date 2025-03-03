# ifndef DEFINES_H
# define DEFINES_H

# include <arpa/inet.h>

typedef struct s_nmap
{
	char				*hostname;
	struct sockaddr_in	host_sa;
}	t_nmap;

# endif
