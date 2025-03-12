# include "defines.h"
# include "utils.h"
# include <stdio.h>
# include <unistd.h>
# include <stdlib.h>
# include <string.h>

extern t_nmap	g_data;

void    init_ports(t_port_info *ports, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        ports[i].is_active = true;
        ports[i].service_name = get_service_name(i);
    }
}

void	defvals_data_opts(void)
{
    g_data.opts.port_flag = false;
    g_data.opts.file_flag = false;
    g_data.opts.ip_flag = false;
	init_ports(g_data.opts.ports, PORTS_LEN);
	g_data.opts.host_destlsthdr = NULL;
	g_data.opts.thrnum = 0;
	g_data.opts.scan_types = SCAN_SYN | SCAN_NULL | SCAN_ACK | SCAN_FIN | SCAN_XMAS | SCAN_UDP;
    init_queue(&g_data.opts.queue);
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
t_queue_node* create_queue_node(int ip, int port, port_result_t *results) {
    t_queue_node *node = malloc(sizeof(t_queue_node));
    if (!node) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
    node->ip = ip;
    node->port = port;
    node->results = results;
    node->next = NULL;
    return node;
}

// Enqueue: Insert a new node at the tail of the queue
void enqueue(int ip, int port, port_result_t *results) {
    t_queue_node *node = create_queue_node(ip, port, results);
    t_queue *queue = &g_data.opts.queue;
    if (queue->tail) {
        queue->tail->next = node;
    }
    queue->tail = node;
    if (!queue->head) {
        queue->head = node;
    }
}

// Dequeue: Remove the node at the head of the queue and return it
t_queue_node* dequeue() {
    pthread_mutex_lock(&g_data.opts.mutex);
    if (!g_data.opts.queue.head)
    {
        pthread_mutex_unlock(&g_data.opts.mutex);
        return NULL;
    }
    t_queue_node *node = g_data.opts.queue.head;
    g_data.opts.queue.head = node->next;
    if (!g_data.opts.queue.head) {
        g_data.opts.queue.tail = NULL;
    }
    pthread_mutex_unlock(&g_data.opts.mutex);
    return node;
}

const char  *get_service_name(uint16_t port)
{
    switch (port)
    {
        case 1: return "tcpmux";
        case 7: return "echo";
        case 9: return "discard";
        case 11: return "systat";
        case 13: return "daytime";
        case 15: return "netstat";
        case 17: return "qotd";
        case 19: return "chargen";
        case 20: return "ftp-data";
        case 21: return "ftp/fsp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 37: return "time";
        case 43: return "whois";
        case 49: return "tacacs";
        case 53: return "domain";
        case 67: return "bootps";
        case 68: return "bootpc";
        case 69: return "tftp";
        case 70: return "gopher";
        case 79: return "finger";
        case 80: return "http";
        case 88: return "kerberos";
        case 102: return "iso-tsap";
        case 104: return "acr-nema";
        case 110: return "pop3";
        case 111: return "sunrpc";
        case 113: return "auth";
        case 119: return "nntp";
        case 123: return "ntp";
        case 135: return "epmap";
        case 137: return "netbios-ns";
        case 138: return "netbios-dgm";
        case 139: return "netbios-ssn";
        case 143: return "imap2";
        case 161: return "snmp";
        case 162: return "snmp-trap";
        case 163: return "cmip-man";
        case 164: return "cmip-agent";
        case 174: return "mailq";
        case 177: return "xdmcp";
        case 179: return "bgp";
        case 199: return "smux";
        case 209: return "qmtp";
        case 210: return "z3950";
        case 213: return "ipx";
        case 319: return "ptp-event";
        case 320: return "ptp-general";
        case 345: return "pawserv";
        case 346: return "zserv";
        case 369: return "rpc2portmap";
        case 370: return "codaauth2";
        case 371: return "clearcase";
        case 389: return "ldap";
        case 427: return "svrloc";
        case 443: return "https";
        case 444: return "snpp";
        case 445: return "microsoft-ds";
        case 464: return "kpasswd";
        case 465: return "submissions";
        case 487: return "saft";
        case 500: return "isakmp";
        case 512: return "exec/biff";
        case 513: return "login/who";
        case 514: return "shell/syslog";
        case 515: return "printer";
        case 517: return "talk";
        case 518: return "ntalk";
        case 520: return "route";
        case 538: return "gdomap";
        case 540: return "uucp";
        case 543: return "klogin";
        case 544: return "kshell";
        case 546: return "dhcpv6-client";
        case 547: return "dhcpv6-server";
        case 548: return "afpovertcp";
        case 554: return "rtsp";
        case 563: return "nntps";
        case 587: return "submission";
        case 607: return "nqs";
        case 623: return "asf-rmcp";
        case 628: return "qmqp";
        case 631: return "ipp";
        case 636: return "ldaps";
        case 646: return "ldp";
        case 655: return "tinc";
        case 706: return "silc";
        case 749: return "kerberos-adm";
        case 853: return "domain-s";
        case 873: return "rsync";
        case 989: return "ftps-data";
        case 990: return "ftps";
        case 992: return "telnets";
        case 993: return "imaps";
        case 995: return "pop3s";
        default: return "Unassigned";
    }
}

