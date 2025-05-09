# include "defines.h"
# include "utils.h"
# include <getopt.h>
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <arpa/inet.h>		// inet_pton
# include <sys/types.h>		// getaddrinfo
# include <sys/socket.h>	// getaddrinfo
# include <netdb.h>			// getaddrinfo

# define BUFFER_SIZE 1024

extern t_nmap	g_data;

struct option long_options[] =
{
    {"help", no_argument, NULL, 0},      		// --help
    {"port", required_argument, NULL, 0},       // --port NUMBER/RANGED (eg. 10-15, 1,2,4,6,10-12) no specified port do scan from 1-1024. max num of ports 1024 at the same time
    {"ip", required_argument, NULL, 0},      	// --ip IP_ADDR
    {"file", required_argument, NULL, 0},  		// --file FILE
    {"speedup", required_argument, NULL, 0},	// --speedup NUMBER (def: 0, max: 250)
    {"scan", required_argument, NULL, 0},		//--scan TYPE/TYPE,TYPE (SYN, NULL, ACK, FIN, XMAS, UDP)
    {0, 0, 0, 0}
};

void				args_options(int argc, char **argv);
int					validate_number(const char *str, int max_value);
struct sockaddr_in	resolve_hostname(const char *hostname);
int					get_valid_ip(const char *input, struct sockaddr_in *out_ip);
int			        add_ip_to_list(const char *input);
int					get_scan_flag(const char *token);
void				apply_scans(const char *input);
void                print_options(void);
int                 parse_port_range(const char *range_str);
void                parse_ports(const char *input);
void                read_ips_from_file(const char *filename);
void                check_duplicates();

void	args_parser(int argc, char **argv)
{
    if (argc < 2)
	{
        print_help();
        exit(EXIT_FAILURE);
    }

	defvals_data_opts();

	args_options(argc, argv);

    if (g_data.opts.file_flag == false && g_data.opts.ip_flag == false)
        exit_failure("ft_nmap: --ip or --file is required\n");

    print_options();
}

void	args_options(int argc, char **argv)
{
	int opt;
	int option_index = 0;

	while ((opt = getopt_long(argc, argv, "", long_options, &option_index)) != -1)
    {
        if (opt == '?') // unknown argument
            exit_failure("");

		if (opt == 0)
		{
			const char *option_name = long_options[option_index].name;

			if (strcmp("help", option_name) == 0)
			{
				print_help();
				memfree();
                exit(EXIT_SUCCESS);
			}
			else if (strcmp("port", option_name) == 0)
			{
                for (int i = 0; i < PORTS_LEN; ++i)
                    g_data.opts.ports[i].is_active = false;
                g_data.opts.port_flag = true;
				parse_ports(optarg);
			}
			else if (strcmp("ip", option_name) == 0)
			{
                if (g_data.opts.file_flag == true)
                    exit_failure("ft_nmap: --ip can't be set with --file flag\n");

                if (add_ip_to_list(optarg) == -1)
                    exit_failure("");
                g_data.opts.ip_flag = true;
			}
			else if (strcmp("file", option_name) == 0)
			{
                if (g_data.opts.ip_flag == true)
                    exit_failure("ft_nmap: --ip can't be set with --file flag\n");

				read_ips_from_file(optarg);
			}
			else if (strcmp("speedup", option_name) == 0)
			{
				int speedup = validate_number(optarg, 250);

				if (speedup == -1)
				{
					fprintf(stderr, "ft_nmap: --speedup invalid value '%s'\n", optarg);
					exit_failure("");
				}

				g_data.opts.thrnum = speedup;
			}
			else if (strcmp("scan", option_name) == 0)
			{
                g_data.opts.scan_types = 0;
				apply_scans(optarg);
			}
		}
	}

    if (optind < argc)  // additional check for remaining arguments
    {
        fprintf(stderr, "ft_nmap: unknown argument: %s\n", argv[optind]);
        print_help();
        exit_failure("");
    }
}

int validate_number(const char *str, int max_value)
{
    char    *endptr;
    long    value = strtol(str, &endptr, 10);

    if (*endptr != '\0' || value <= 0 || value > max_value)
        return -1;

    return (int)value;
}

struct sockaddr_in  resolve_hostname(const char *hostname)
{
    struct addrinfo     hints, *result;
    struct sockaddr_in  addr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0)
    {
        addr.sin_addr.s_addr = INADDR_NONE;
        return addr;
    }

    memcpy(&addr, result->ai_addr, sizeof(struct sockaddr_in));
    freeaddrinfo(result);

    return addr;
}

int	get_valid_ip(const char *input, struct sockaddr_in *out_ip)
{
    int res;

	if (!out_ip)
	{
		fprintf(stderr, "ft_nmap: invalid sockaddr_in pointer in get_valid_ip\n");
		return -1;
	}

    res = inet_pton(AF_INET, input, &(out_ip->sin_addr));

    if (res == 1)
        return 1;

    *out_ip = resolve_hostname(input);
    if (out_ip->sin_addr.s_addr != INADDR_NONE)
        return 0;

    return -1;
}

// -1 - in case of error, 0 - OK
int add_ip_to_list(const char *input)
{
	struct sockaddr_in  ip;
	int                 is_ip;
    t_destlst           *new_node;

	if (input == NULL || strlen(input) == 0)
    {
		fprintf(stderr, "ft_nmap: Invalid input add_ip_to_list\n");
        return -1;
    }

	// vals: -1 unknown host, 0 - hostname, 1 - IPv4,
	is_ip = get_valid_ip(input, &ip);

    if (is_ip == -1) {
        fprintf(stderr, "ft_nmap: unknown host '%s'\n", input);
        return -1;
    }

    new_node = create_node(is_ip ? NULL : input, ip);
    if (!new_node)
    {
		fprintf(stderr, "ft_nmap: Failed to create node for '%s' in add_ip_to_list\n", input);
        return -1;
    }

	add_node_to_end(&(g_data.opts.host_destlsthdr), new_node);
    return 0;
}

int get_scan_flag(const char *token)
{
    if (strcmp(token, "SYN") == 0) return SCAN_SYN;
    if (strcmp(token, "NULL") == 0) return SCAN_NULL;
    if (strcmp(token, "ACK") == 0) return SCAN_ACK;
    if (strcmp(token, "FIN") == 0) return SCAN_FIN;
    if (strcmp(token, "XMAS") == 0) return SCAN_XMAS;
    if (strcmp(token, "UDP") == 0) return SCAN_UDP;
    return -1;
}

void	apply_scans(const char *input)
{
	char	*ptr;
	char	*copy;
	char	*token;
	int 	flag;

    if (input == NULL || strlen(input) == 0)
        exit_failure("ft_nmap: Invalid input apply_scans\n");

    copy = strdup(input);
    if (!copy)
        exit_failure("ft_nmap: Memory allocation in apply_scans failed\n");

    ptr = copy;

    while (*ptr == ' ')
        ptr++;

    while ((token = strsep(&ptr, " ")) != NULL)
    {
        if (*token == '\0')
            continue;

        flag = get_scan_flag(token);
        if (flag == -1)
        {
            fprintf(stderr, "ft_nmap: Invalid scan type '%s'\n", token);
            free(copy);
            exit_failure("");
        }

        g_data.opts.scan_types |= flag;
    }

    free(copy);
}

void    print_options(void)
{
    int len = 1024;

    printf("Scan Configurations\n\n");
    printf("Target IPs:\n");
    for (t_destlst *ptr = g_data.opts.host_destlsthdr; ptr; ptr = ptr->next)
    {
        printf("  IPv4: %s, Hostname: %s\n",
            inet_ntoa(ptr->dest_ip.sin_addr),
            ptr->hostname ? ptr->hostname : "NULL");
    }

    if (g_data.opts.port_flag)
    {
        len = 0;
        for (int i = 0; i < PORTS_LEN; ++i)
        {
            if (g_data.opts.ports[i].is_active)
                len++;
        }
    }
    printf("No. of Ports to scan:\n  %i\n", len);

    // speedup
    printf("Threads:\n  %d\n", g_data.opts.thrnum);

    // scan
    printf("Scan types:\n");
    printf("  SYN:\t%i\n  NULL:\t%i\n  ACK:\t%i\n  FIN:\t%i\n  XMAS:\t%i\n  UDP:\t%i",
        g_data.opts.scan_types & SCAN_SYN  ? 1 : 0,
        g_data.opts.scan_types & SCAN_NULL ? 1 : 0,
        g_data.opts.scan_types & SCAN_ACK  ? 1 : 0,
        g_data.opts.scan_types & SCAN_FIN  ? 1 : 0,
        g_data.opts.scan_types & SCAN_XMAS ? 1 : 0,
        g_data.opts.scan_types & SCAN_UDP  ? 1 : 0);
    printf("\n\n");
}

// -1 error else 0
int parse_port_range(const char *range_str)
{
    char    *dash_pos;
    int     start, end;
    char    start_str[10], end_str[10];

    // Find the '-' character to check for a range
    if ((dash_pos = strchr(range_str, '-')) == NULL)
        return 0;

    if (strlen (range_str) > 10)
    {
        fprintf(stderr, "ft_nmap: --port invalid range %s\n", range_str);
        return -1;
    }

    // dividing into two parts
    strncpy(start_str, range_str, dash_pos - range_str);
    start_str[dash_pos - range_str] = '\0'; // Null-terminate the start string
    strcpy(end_str, dash_pos + 1);  // Copy everything after the dash

    // Validate the start and end port numbers
    start = validate_number(start_str, PORTS_LEN - 1);
    end = validate_number(end_str, PORTS_LEN - 1);

    if (start == -1 || end == -1 || start > end)
    {
        fprintf(stderr, "ft_nmap: --port invalid range %s\n", range_str);
        return -1;
    }

    // setting the ports to is active
    for (int i = start; i <= end; i++)
        g_data.opts.ports[i].is_active = true;

    return 0;
}

void    parse_ports(const char *input)
{
    char    *copy;
    char    *token;
    int     port;

    if (input == NULL || strlen(input) == 0)
        exit_failure("ft_nmap: Invalid input in parse_ports\n");

    copy = strdup(input);
    if (!copy)
        exit_failure("ft_nmap: Memory allocation in parse_ports failed\n");

    token = strtok(copy, ",");

    while (token != NULL)
    {
        if (strchr(token, '-') != NULL)
        {
            if (parse_port_range(token) == -1)
            {
                free(copy);
                exit_failure("");
            }
        }
        else
        {
            port = validate_number(token, PORTS_LEN - 1);
            if (port == -1)
            {
                fprintf(stderr, "ft_nmap: invalid port '%s'\n", token);
                free(copy);
                exit_failure("");
            }
            g_data.opts.ports[port].is_active = true;
        }
        token = strtok(NULL, ",");
    }

    free(copy);
}

void    read_ips_from_file(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        fprintf(stderr, "ft_nmap: Failed to open file %s\n", filename);
        exit_failure("");
    }

    char    line[BUFFER_SIZE];
    char    *token;

    while (fgets(line, sizeof(line), file))
    {
        line[strcspn(line, "\n")] = '\0';

        token = strtok(line, " ");

        while (token != NULL)
        {
            if (strlen(token) > 0)
            {
                if (add_ip_to_list(token) == -1)
                {
                    fclose(file);
                    exit_failure("");
                }
            }

            token = strtok(NULL, " ");
        }
    }

    fclose(file);

    if (!g_data.opts.host_destlsthdr)
        exit_failure("ft_nmap: --file is empty\n");

    check_duplicates();

    g_data.opts.file_flag = true;
}

void    check_duplicates()
{
    for (t_destlst *current = g_data.opts.host_destlsthdr;
        current != NULL; current = current->next)
    {
        for (t_destlst *compare = current->next;
            compare != NULL; compare = compare->next)
            {
            if (current->dest_ip.sin_addr.s_addr == compare->dest_ip.sin_addr.s_addr ||
                (current->hostname && compare->hostname && strcmp(current->hostname, compare->hostname) == 0))
                {
                fprintf(stderr, "ft_nmap: --file duplicate IP or hostname detected: %s\n",
                        current->hostname ? current->hostname : inet_ntoa(current->dest_ip.sin_addr));
                exit_failure("");
            }
        }
    }
}
