# include "defines.h"
# include "utils.h"
# include "args.h"
# include "nmap.h"

t_nmap g_data;



int	main(int argc, char **argv)
{
	args_parser(argc, argv);

	nmap_performance();
	return 0;
}
