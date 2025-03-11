# ifndef UTILS_H
# define UTILS_H

void		defvals_data_opts(void);
void		free_list(t_destlst **head);
void		add_node_to_end(t_destlst **head, t_destlst *new_node);
t_destlst	*create_node(const char *hostname, struct sockaddr_in ip);
void		memfree(void);
void		exit_failure(char *str);
void		print_help(void);
const char 	*get_service_name(uint16_t port);
void		init_queue(t_queue *queue);
t_queue_node* create_queue_node(int ip, int port);
void		enqueue(int ip, int port);
t_queue_node* dequeue();
uint32_t        get_local_ip();
void            print_scan_results(port_result_t *results, uint8_t *port, int scan_types);

# endif
