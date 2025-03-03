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
