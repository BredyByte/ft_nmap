# ifndef UTILS_H
# define UTILS_H

void		defvals_data_opts(void);
void		free_list(t_destlst **head);
void		add_node_to_end(t_destlst **head, t_destlst *new_node);
t_destlst	*create_node(const char *hostname, struct sockaddr_in ip);
void		exit_failure(char *str);
void		print_help(void);

# endif
