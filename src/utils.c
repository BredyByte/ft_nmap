# include "defines.h"
# include <stdio.h>
# include <unistd.h>
# include <stdlib.h>

extern t_nmap	g_data;

void	exit_failure(char *str)
{
	if (!str)
		fprintf(stderr, "Fatal error\n");
	else
		fprintf(stderr, "%s\n", str);

	exit(EXIT_FAILURE);
}

void	print_help(void)
{
	printf("Help Screen\n");
	printf("ft_nmap [OPTIONS]\n");
	printf("  --help\tPrint this help message\n");
	printf("  --ports\tports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
	printf("  --ip\t\tip addresses/hostname to scan in dot format\n");
	printf("  --file\tFile name containing IP addresses/hostnames to scan, separated by comma\n");
	printf("  --speedup\t[250 max] number of parallel threads to use\n");
	printf("  --scan\tSYN/NULL/FIN/XMAS/ACK/UDP\n");
}
