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
t_queue_node* create_node(const char *ip, int port, char scan);
void		enqueue(t_queue *queue, const char *ip, int port, char scan);
t_queue_node* dequeue(t_queue *queue);

# endif
