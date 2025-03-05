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
void				add_ip_to_list(const char *input);

void	args_parser(int argc, char **argv)
{
    if (argc < 2)
	{
        print_help();
        exit(EXIT_FAILURE);
    }

	defvals_data_opts();

	args_options(argc, argv);
}

void	args_options(int argc, char **argv)
{
	int opt;
	int option_index = 0;

	while ((opt = getopt_long(argc, argv, "", long_options, &option_index)) != -1)
    {
		if (opt == 0)
		{
			const char *option_name = long_options[option_index].name;

			if (strcmp("help", option_name) == 0)
			{
				print_help();
				exit(EXIT_SUCCESS);
			}
			else if (strcmp("port", option_name) == 0)
			{
				printf("Port(s) selected: %s\n", optarg);
				exit(EXIT_SUCCESS);
			}
			else if (strcmp("ip", option_name) == 0)
			{
				add_ip_to_list(optarg);
			}
			else if (strcmp("file", option_name) == 0)
			{
				printf("Reading IPs from file: %s\n", optarg);
				exit(EXIT_SUCCESS);
			}
			else if (strcmp("speedup", option_name) == 0)
			{
				int speedup = validate_number(optarg, 250);

				if (speedup == -1)
				{
					fprintf(stderr, "ft_nmap: invalid value %s.\n", optarg);
					exit_failure("");
				}

				g_data.opts.thrnum = speedup;
			}
			else if (strcmp("scan", option_name) == 0)
			{
				printf("Scan type(s): %s\n", optarg);
				exit(EXIT_SUCCESS);
			}
			else
			{
                fprintf(stderr, "Unknown option: %s\n", option_name);
                print_help();
				exit_failure("");
            }
		}
	}
}

int	validate_number(const char *str, int max_value)
{
    char *endptr;
    long value = strtol(str, &endptr, 10);

    if (*endptr != '\0' || value < 0 || value > max_value)
        return -1;

    return (int)value;
}

struct sockaddr_in resolve_hostname(const char *hostname)
{
    struct addrinfo hints, *result;
    struct sockaddr_in addr;

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
	if (!out_ip)
	{
		fprintf(stderr, "Error: invalid sockaddr_in pointer\n");
		return -1;
	}

    int res = inet_pton(AF_INET, input, &(out_ip->sin_addr));

    if (res == 1)
        return 1;

    *out_ip = resolve_hostname(input);
    if (out_ip->sin_addr.s_addr != INADDR_NONE)
        return 0;

    return -1;
}

void	add_ip_to_list(const char *input)
{
	struct sockaddr_in ip;
	int is_ip;

	if (input == NULL || strlen(input) == 0)
		exit_failure("ft_nmap: Invalid input add_ip_to_list\n");

	// vals: -1 unknown host, 0 - hostname, 1 - IPv4,
	is_ip = get_valid_ip(input, &ip);

    if (is_ip == -1)
        exit_failure("ft_nmap: unknown host\n");

    t_destlst *new_node = create_node(is_ip ? NULL : input, ip);
    if (!new_node)
		exit_failure("ft_nmap: Failed to create node\n");

	add_node_to_end(&(g_data.opts.host_destlsthdr), new_node);
}
