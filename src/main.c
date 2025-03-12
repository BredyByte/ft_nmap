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
        memset(dest->results, 0, sizeof(dest->results));
        for (int port = 1; port < PORTS_LEN; port++)
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

    printf("Scanning..\n");
    printf("...........................\n");

    struct timeval start, end;
    gettimeofday(&start, NULL);

    pthread_t *threads = malloc(sizeof(pthread_t) * g_data.opts.thrnum);
    if (!threads)
        exit_failure("Memory allocation failed for threads.\n");
    // Start the threads
    for (int i = 0; i < g_data.opts.thrnum; i++) {
        pthread_create(&threads[i], NULL, nmap_performance, (void*)&local_ip);
    }

    nmap_performance((void*)&local_ip);

    // Wait for all threads to finish
    for (int i = 0; i < g_data.opts.thrnum; i++) {
        pthread_join(threads[i], NULL);
    }
    free(threads);

    gettimeofday(&end, NULL);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
    printf("Scan took %.5f secs\n", elapsed);


    print_scan_results();

	memfree();
	return 0;
}
