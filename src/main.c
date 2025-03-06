# include "defines.h"
# include "utils.h"
# include "args.h"
# include "nmap.h"

t_nmap g_data;



int	main(int argc, char **argv)
{
	if (getuid() !=  0)
		exit_failure("ft_nmap: Root privileges are required.");

	args_parser(argc, argv);

	nmap_performance();

	memfree();
	return 0;
}
