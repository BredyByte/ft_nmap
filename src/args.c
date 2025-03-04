# include "defines.h"
# include "utils.h"
# include <getopt.h>
# include <stdio.h>
# include <string.h>
# include <stdlib.h>

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

void	args_options(int argc, char **argv);


void	args_parser(int argc, char **argv)
{
    if (argc < 2)
	{
        print_help();
        exit(EXIT_FAILURE);
    }

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
				printf("Target IP: %s\n", optarg);
				exit(EXIT_SUCCESS);
			}
			else if (strcmp("file", option_name) == 0)
			{
				printf("Reading IPs from file: %s\n", optarg);
				exit(EXIT_SUCCESS);
			}
			else if (strcmp("speedup", option_name) == 0)
			{
				printf("Speedup set to: %s\n", optarg);
				exit(EXIT_SUCCESS);
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
                exit(EXIT_FAILURE);
            }
		}
	}
}
