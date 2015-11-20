#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include "debug.h"
#include "safe.h"
#include "conf.h"
#include "common.h"
#include "commandline.h"
char ** restartargv = NULL;


static void
usage(void)
{
    printf("Usage: EliteAgent [options]\n");
    printf("\n");
	printf("  -f            Run in foreground\n");//是否以deamon的形式运行
    printf("  -d <level>    Debug level\n");//debug等级
    printf("                LOG_EMERG:0,LOG_ALERT:1,LOG_CRIT:2,LOG_ERR:3");
	printf("                LOG_WARNING:4,LOG_NOTICE:5,LOG_INFO:6,LOG_DEBUG:7\n");
    printf("  -s            Log to syslog\n");
	printf("  -v            Print version information\n");
	//printf("  -t            Terminate the EliteAgent\n");
    printf("  -h            Print usage\n");
    printf("\n");
}

/** Uses getopt() to parse the command line and set configuration values
 * also populates restartargv
 */
void parse_commandline(int argc, char **argv) {
    int c;
	int skiponrestart;
	int i;

    s_config *config = config_get_config();


	debug(LOG_INFO, "Parse command line parameters");

	restartargv = safe_malloc((argc + 1) * sizeof(char*));
	i=0;
	restartargv[i++] = safe_strdup(argv[0]);
	
    while (-1 != (c = getopt(argc, argv, "c:hfd:sw:vtx:i:"))) {

		skiponrestart = 0;
		
		switch(c) {

			case 'h':
				usage();
				exit(1);
				break;
			case 'd':
				skiponrestart = 1;
				if (optarg) {
					//config->debuglevel = atoi(optarg);
					config->trapdebuglevel = atoi(optarg);
				}
				break;
			case 's':
				config->log_syslog = 1;
				break;
			case 'f':
				skiponrestart = 1;
				config->daemon = 0;
				break;
			case 'v':
				printf(VERSION"\n");
				exit(1);
				break;
			default:
				usage();
				exit(1);
				break;

		}
		
		if (!skiponrestart) {
			/* Add it to restartargv */
			safe_asprintf(&(restartargv[i++]), "-%c", c);
			if (optarg) {
				restartargv[i++] = safe_strdup(optarg);
			}
		}
		restartargv[i++] = NULL;
		

	}


}


