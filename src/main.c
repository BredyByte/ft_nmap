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
        // Count active ports for this dest
        int active_count = 0;
        for (uint16_t port = 1; port < PORTS_LEN; port++) {
            if (g_data.opts.ports[port].is_active)
                active_count++;
        }

        if (active_count == 0) {
            dest = dest->next;
            continue;
        }

        // Allocate arrays for ports and results (+1 for sentinel)
        int *ports = calloc(active_count + 1, sizeof(int));
        port_result_t **results = calloc(active_count + 1, sizeof(port_result_t*));
        if (!ports || !results) {
            perror("calloc");
            exit(1);
        }

        // Fill arrays
        int idx = 0;
        for (int port = 1; port < PORTS_LEN; port++) {
            if (g_data.opts.ports[port].is_active) {
                ports[idx] = port;

                // Allocate and initialize results struct for this port
                results[idx] = calloc(1, sizeof(port_result_t));
                if (!results[idx]) {
                    perror("calloc");
                    free(ports);
                    free(results);
                    exit(1);
                }
                results[idx]->port = port;
                for (int j = 0; j < NUM_SCAN_TYPES; j++)
                    results[idx]->results[j] = SCAN_RESULT_NO_RESPONSE;

                idx++;
            }
        }
        ports[idx] = 0;       // sentinel to mark end of ports array
        results[idx] = NULL;  // sentinel to mark end of results array

        // Enqueue whole port range and results array
        enqueue(dest->dest_ip.sin_addr.s_addr, ports, results);

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


    print_scan_results(); // THIS IS FUCKED !!!!!!!!!!!!! valgrind error :(

	memfree();
	return 0;
}
