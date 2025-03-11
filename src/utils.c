# include "defines.h"
# include <stdio.h>
# include <unistd.h>
# include <stdlib.h>
# include <string.h>

extern t_nmap	g_data;

void	defvals_data_opts(void)
{
    g_data.opts.port_flag = false;
    g_data.opts.file_flag = false;
    g_data.opts.ip_flag = false;
	memset(g_data.opts.ports, 1, sizeof(g_data.opts.ports));
	g_data.opts.host_destlsthdr = NULL;
	g_data.opts.thrnum = 0;
	g_data.opts.scan_types = SCAN_SYN | SCAN_NULL | SCAN_ACK | SCAN_FIN | SCAN_XMAS | SCAN_UDP;
}

void	free_list(t_destlst **head)
{
    if (!head || !(*head))
        return;

    t_destlst *current = *head;
    t_destlst *next;

    while (current)
    {
        next = current->next;
        if (current->hostname)
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
        return NULL;

    if (hostname)
    {
        new_node->hostname = strdup(hostname);
        if (!new_node->hostname)
        {
            free(new_node);
            return NULL;
        }
    }
    else
    {
        new_node->hostname = NULL;
    }

    new_node->dest_ip = ip;
    new_node->next = NULL;
    return new_node;
}

void    memfree(void)
{
    free_list(&(g_data.opts.host_destlsthdr));
}

void	exit_failure(char *str)
{
	if (!str)
		fprintf(stderr, "Fatal error\n");
	else
		fprintf(stderr, "%s", str);

    memfree();

	exit(EXIT_FAILURE);
}

void	print_help(void)
{
	printf("Help Screen\n");
	printf("ft_nmap [OPTIONS]\n");
	printf("  --help\tPrint this help message\n");
	printf("  --port\tports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
	printf("  --ip\t\tip addresses or hostname to scan in dot format\n");
	printf("  --file\tFile name containing IP addresses/hostnames to scan, separated by comma\n");
	printf("  --speedup\t[1-250] number of parallel threads to use\n");
	printf("  --scan\tSYN/NULL/FIN/XMAS/ACK/UDP (eg, SYN or \"NULL FIN XMAS UDP\")\n");
}


// Initialize the queue by setting head and tail to NULL
void init_queue(t_queue *queue) {
    queue->head = queue->tail = NULL;
}

// Create a new node with provided IP, port, and scan type
t_queue_node* create_node(const char *ip, int port, char scan) {
    t_queue_node *node = malloc(sizeof(t_queue_node));
    if (!node) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
    strncpy(node->ip, ip, sizeof(node->ip) - 1);
    node->ip[sizeof(node->ip)-1] = '\0';
    node->port = port;
    node->scan = scan;
    node->next = NULL;
    return node;
}

// Enqueue: Insert a new node at the tail of the queue
void enqueue(t_queue *queue, const char *ip, int port, char scan) {
    t_queue_node *node = create_node(ip, port, scan);
    if (queue->tail) {
        queue->tail->next = node;
    }
    queue->tail = node;
    if (!queue->head) {
        queue->head = node;
    }
}

// Dequeue: Remove the node at the head of the queue and return it
t_queue_node* dequeue(t_queue *queue) {
    if (!queue->head)
        return NULL;
    t_queue_node *node = queue->head;
    queue->head = node->next;
    if (!queue->head) {
        queue->tail = NULL;
    }
    return node;
}
