# include "defines.h"
# include "utils.h"
# include "args.h"
# include "nmap.h"

t_nmap g_data;



int	main(int argc, char **argv)
{
	if (getuid() !=  0)
		exit_failure("ft_nmap: Root privileges are required.\n");

	args_parser(argc, argv);


    t_destlst *dest = g_data.opts.host_destlsthdr;
    while (dest) {
        for (int port = 0; port < PORTS_LEN; port++)
        {
            if (g_data.opts.ports[port].is_active)
            {
                for (int j = 0; j < NUM_SCAN_TYPES; j++)
                    dest->results->results[j] = SCAN_RESULT_NO_RESPONSE;
                enqueue(dest->dest_ip.sin_addr.s_addr, port, dest->results);
            }
        }
        dest = dest->next;
    }
    int local_ip = get_local_ip();

    pthread_t thread; // Declare the thread variable outside the loop
    // Start the threads
    for (int i = 0; i < g_data.opts.thrnum; i++) {
        pthread_create(&thread, NULL, nmap_performance, (void*)&local_ip);
    }

    nmap_performance((void*)&local_ip);

    // Wait for all threads to finish
    for (int i = 0; i < g_data.opts.thrnum + 1; i++) {
        pthread_join(thread, NULL);
    }

    dest = g_data.opts.host_destlsthdr;
    while (dest) {
    print_scan_results(dest->results, g_data.opts.ports, g_data.opts.scan_types);
    dest = dest->next;
    }
	memfree();
	return 0;
}
