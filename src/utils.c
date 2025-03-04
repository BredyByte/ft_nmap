# include "defines.h"
# include <stdio.h>
# include <unistd.h>
# include <stdlib.h>
# include <string.h>

extern t_nmap	g_data;

void	free_list(t_destlst **head)
{
    if (!head || !(*head))
        return;

    t_destlst *current = *head;
    t_destlst *next;

    while (current)
    {
        next = current->next;
        free(current->hostname);
        free(current);
        current = next;
    }
    *head = NULL;
}

void	add_node_to_end(t_destlst **head, t_destlst *new_node)
{
    if (!head || !new_node)
        return;

    if (*head == NULL)
    {
        *head = new_node;
        return;
    }

    t_destlst *current = *head;
    while (current->next)
        current = current->next;

    current->next = new_node;
}

t_destlst	*create_node(const char *hostname, struct sockaddr_in ip)
{
    t_destlst *new_node = malloc(sizeof(t_destlst));
	if (!new_node)
        return (NULL);

    new_node->hostname = strdup(hostname);
    if (!new_node->hostname)
    {
        free(new_node);
        return (NULL);
    }

    new_node->dest_ip = ip;
    new_node->next = NULL;
    return (new_node);
}

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
