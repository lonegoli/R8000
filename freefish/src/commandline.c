#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include "debug.h"
#include "safe.h"
#include "conf.h"

#include "config.h"


char ** restartargv = NULL;

static void usage(void);


pid_t restart_orig_pid = 0;


static void
usage(void)
{
    printf("Usage: freefish [options]\n");
    printf("\n");
    printf("  -c [filename] Use this config file\n");//配置文件路径
    printf("  -f            Run in foreground\n");//是否以deamon的形式运行
    printf("  -d <level>    Debug level\n");//debug等级
    printf("  -s            Log to syslog\n");//是否将log写入syslog
    printf("                LOG_EMERG:0,LOG_ALERT:1,LOG_CRIT:2,LOG_ERR:3");
	printf("                LOG_WARNING:4,LOG_NOTICE:5,LOG_INFO:6,LOG_DEBUG:7");
    printf("  -w <path>     Wdctl socket path\n");
    printf("  -h            Print usage\n");
    printf("  -v            Print version information\n");
    printf("  -x pid        Used internally by FreeFish when re-starting itself *DO NOT ISSUE THIS SWITCH MANUAlLY*\n");
    printf("  -i <path>     Internal socket path used when re-starting self\n");
	printf("  -e            enable ad_redirect\n");
    printf("\n");
}


void parse_commandline(int argc, char **argv) {
    int c;
	 int skiponrestart;
	 int i;

    s_config *config = config_get_config();

	debug(LOG_INFO, "parse commandline");

	restartargv = safe_malloc((argc + 4) * sizeof(char*));
	i=0;
	restartargv[i++] = safe_strdup(argv[0]);

    while (-1 != (c = getopt(argc, argv, "c:hfd:sw:vx:i:e"))) {

		skiponrestart = 0;

		switch(c) {

			case 'h':
				usage();
				exit(1);
				break;

			case 'c':
				if (optarg) {
					strncpy(config->configfile, optarg, sizeof(config->configfile));
				}
				break;

			case 'w':
				if (optarg) {
					free(config->wdctl_sock);
					config->wdctl_sock = safe_strdup(optarg);
				}
				break;

			case 'f':
				skiponrestart = 1;
				config->daemon = 0;
				break;

			case 'd':
				if (optarg) {
					config->debuglevel = atoi(optarg);
				}
				break;

			case 's':
				config->log_syslog = 1;
				break;

			case 'v':
				printf("This is FreeFish version " VERSION "\n");
				exit(1);
				break;

			case 'x':
				skiponrestart = 1;
				if (optarg) {
					restart_orig_pid = atoi(optarg);
				}
				else {
					printf("The expected PID to the -x switch was not supplied!");
					exit(1);
				}
				break;

			case 'i':
				if (optarg) {
					free(config->internal_sock);
					config->internal_sock = safe_strdup(optarg);
				}
				break;

			case 'e':
				skiponrestart = 1;
				config->auth_self = 1;
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

	}

	
	restartargv[i++] = NULL;
	restartargv[i++] = NULL;
	restartargv[i++] = NULL;
	restartargv[i++] = NULL;

}

