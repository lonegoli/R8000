#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h>
#include <errno.h>

#include "wdctl.h"

s_config config;

static void usage(void);
static void init_config(void);
static void parse_commandline(int, char **);
static int connect_to_server(char *);
static size_t send_request(int, char *);
static void wdctl_status(void);
static void wdctl_stop(void);
static void wdctl_reset(void);
static void wdctl_debug(void);
static void wdctl_show(void);
static void wdctl_restart(void);


static void
usage(void)
{
    printf("Usage: ffctl [options] command [arguments]\n");
    printf("\n");
    printf("options:\n");
    printf("  -s <path>         Path to the socket\n");
    printf("  -h                Print usage\n");
    printf("\n");
    printf("commands:\n");
    printf("  reset [mac|ip]    Reset the specified mac or ip connection\n");
    printf("  status            Obtain the status of freefish\n");
    printf("  stop              Stop the running freefish\n");
    printf("  restart           Re-start the running freefish (without disconnecting active users!)\n");
	printf("  upgrade           upgrade the program of freefish (upgrade [url])\n");
	printf("  debug             change freefish debug level\n");
	printf("  show              show freefish debug level\n");
    printf("\n");
}


static void
init_config(void)
{

	config.socket = strdup(DEFAULT_SOCK);
	config.command = WDCTL_UNDEF;
}




void
parse_commandline(int argc, char **argv)
{
    extern int optind;
    int c;

    while (-1 != (c = getopt(argc, argv, "s:h"))) {
        switch(c) {
            case 'h':
                usage();
                exit(1);
                break;

            case 's':
                if (optarg) {
		    free(config.socket);
		    config.socket = strdup(optarg);
                }
                break;

            default:
                usage();
                exit(1);
                break;
        }
    }

    if ((argc - optind) <= 0) {
	    usage();
	    exit(1);
    }

    if (strcmp(*(argv + optind), "status") == 0) {
	    config.command = WDCTL_STATUS;
    } else if (strcmp(*(argv + optind), "stop") == 0) {
	    config.command = WDCTL_STOP;
    } else if (strcmp(*(argv + optind), "reset") == 0) {
	    config.command = WDCTL_KILL;
	    if ((argc - (optind + 1)) <= 0) {
		    fprintf(stderr, "ffctl: Error: You must specify an IP "
				    "or a Mac address to reset\n");
		    usage();
		    exit(1);
	    }
	    config.param = strdup(*(argv + optind + 1));
    } else if (strcmp(*(argv + optind), "debug") == 0) {
	    config.command = WDCTL_DEBUG;
	    if ((argc - (optind + 1)) <= 0) {
		    fprintf(stderr, "ffctl: Error: You must specify an debug level\n");
		    usage();
		    exit(1);
	    }
	    config.param = strdup(*(argv + optind + 1));
    }else if (strcmp(*(argv + optind), "restart") == 0) {
	    config.command = WDCTL_RESTART;
    } else if (strcmp(*(argv + optind), "upgrade") == 0) {
        config.command = WDCTL_UPGRADE;
		if((argc - (optind + 1)) <= 0) {
			fprintf(stderr, "ffctl: Error: You must specify an url and PATH"
				    "to upgrade\n");
		    usage();
		    exit(1);
		}
		config.param = strdup(*(argv + optind + 1));
		
		
    } else if (strcmp(*(argv + optind), "destroy") == 0) {
    	config.command = WDCTL_DESTROY;
    } else if (strcmp(*(argv + optind), "disable") == 0) {
    	config.command = WDCTL_DISABLE;
    } else if (strcmp(*(argv + optind), "enable") == 0) {
    	config.command = WDCTL_ENABLE;
    }
	 else {
	    fprintf(stderr, "ffctl: Error: Invalid command \"%s\"\n", *(argv + optind));
	    usage();
	    exit(1);
    }
}

static int
connect_to_server(char *sock_name)
{
	int sock;
	struct sockaddr_un	sa_un;
	
	/* Connect to socket */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&sa_un, 0, sizeof(sa_un));
	sa_un.sun_family = AF_UNIX;
	strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

	if (connect(sock, (struct sockaddr *)&sa_un, 
			strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
		fprintf(stderr, "ffctl: freefish probably not started (Error: %s)\n", strerror(errno));
		exit(1);
	}

	return sock;
}

static size_t
send_request(int sock, char *request)
{
	size_t	len;
        ssize_t written;
		
	len = 0;
	while (len != strlen(request)) {
		written = write(sock, (request + len), strlen(request) - len);
		if (written == -1) {
			fprintf(stderr, "Write to freefish failed: %s\n",
					strerror(errno));
			exit(1);
		}
		len += written;
	}

	return len;
}

static void
wdctl_status(void)
{
	int	sock;
	char	buffer[4096];
	char	request[16];
	int	len;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "status\r\n\r\n", 15);

	len = send_request(sock, request);
	
	while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
		buffer[len] = '\0';
		printf("%s", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}

static void
wdctl_stop(void)
{
	int	sock;
	char	buffer[4096];
	char	request[16];
	int	len;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "stop\r\n\r\n", 15);

	len = send_request(sock, request);
	
	while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
		buffer[len] = '\0';
		printf("%s", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}

static void
wdctl_reset(void)
{
	int	sock;
	char	buffer[4096];
	char	request[64];
	size_t	len;
	int	rlen;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "reset ", 64);
	strncat(request, config.param, (64 - strlen(request)));
	strncat(request, "\r\n\r\n", (64 - strlen(request)));

	len = send_request(sock, request);
	
	len = 0;
	memset(buffer, 0, sizeof(buffer));
	while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len),
				(sizeof(buffer) - len))) > 0)){
		len += rlen;
	}

	if (strcmp(buffer, "Yes") == 0) {
		printf("Connection %s successfully reset.\n", config.param);
	} else if (strcmp(buffer, "No") == 0) {
		printf("Connection %s was not active.\n", config.param);
	} else {
		fprintf(stderr, "ffctl: Error: FreeFish sent an abnormal "
				"reply.\n");
	}

	shutdown(sock, 2);
	close(sock);
}

static void
wdctl_debug(void)
{
	int	sock;
	char	buffer[4096];
	char	request[64];
	size_t	len;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "debug ", 64);
	strncat(request, config.param, (64 - strlen(request)));
	strncat(request, "\r\n\r\n", (64 - strlen(request)));

	len = send_request(sock, request);
	
	while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
		buffer[len] = '\0';
		printf("%s\r\n", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}


static void
wdctl_show(void)
{
	int	sock;
	char	buffer[4096];
	char	request[16];
	int	len;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "show\r\n\r\n", 15);

	len = send_request(sock, request);
	
	while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
		buffer[len] = '\0';
		printf("%s\r\n", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}


static void
wdctl_restart(void)
{
	int	sock;
	char	buffer[4096];
	char	request[16];
	int	len;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "restart\r\n\r\n", 15);

	len = send_request(sock, request);
	
	while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
		buffer[len] = '\0';
		printf("%s\r\n", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}


static void
wdctl_destroy(void)
{
	int	sock;
	char	buffer[4096];
	char	request[16];
	int	len;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "destroy\r\n\r\n", 15);

	len = send_request(sock, request);
	
	while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
		buffer[len] = '\0';
		printf("%s\r\n", buffer);
	}

	shutdown(sock, 2);
	close(sock);

	
}


static void
wdctl_disable(void)
{
	int	sock;
	char	buffer[4096];
	char	request[16];
	int	len;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "disable\r\n\r\n", 15);

	len = send_request(sock, request);
	
	while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
		buffer[len] = '\0';
		printf("%s\r\n", buffer);
	}

	shutdown(sock, 2);
	close(sock);

	
}


static void
wdctl_enable(void)
{
	int	sock;
	char	buffer[4096];
	char	request[16];
	int	len;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "enable\r\n\r\n", 15);

	len = send_request(sock, request);
	
	while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
		buffer[len] = '\0';		
	}
	printf("%s\n", buffer);
	shutdown(sock, 2);
	close(sock);

	
}


static void
wdctl_upgrade(void)
{
	char wget_url[1024];
	char resbuff[1024];
	pid_t resfork;
	int status;
	FILE *stream;
	if (config.param != NULL) {
		strcpy(wget_url, "wget -c -O /tmp/firmware.img ");
		strcat(wget_url, config.param);
		printf("%s....\n",wget_url);
		status = system(wget_url);
		if (status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			//if (strstr(resbuff, "100%") != NULL) {

            if((system(". /lib/functions.sh; include /lib/upgrade; platform_check_image '/tmp/firmware.img'")) == 0) {
				resfork = fork();
				if(resfork == -1) {
					perror("failed to fork");
					exit(-1);
				} 
				if(resfork == 0) {
					execlp("sysupgrade", "sysupgrade", "/tmp/firmware.img", NULL);
				}
				else {
					waitpid(resfork, &status, 0);
					if(status != -1 && WIFEXITED(status) && WEXITSTATUS(status)== 0) {
					} else {
					//abnormal termination
					}
				}
				
            } else {
            //Invalid image type
            }
			
							
		} else {
			
		}
			
	} 
	
}
int
main(int argc, char **argv)
{

	/* Init configuration */
	init_config();
	parse_commandline(argc, argv);

	switch(config.command) {
	case WDCTL_STATUS:
		wdctl_status();
		break;
	
	case WDCTL_STOP:
		wdctl_stop();
		break;

	case WDCTL_KILL:
		wdctl_reset();
		break;
		
	case WDCTL_DEBUG:
		wdctl_debug();
		break;
	case WDCTL_RESTART:
		wdctl_restart();
		break;
	case WDCTL_UPGRADE:
		wdctl_upgrade();
	case WDCTL_DESTROY:
		wdctl_destroy();
		break;
	case WDCTL_DISABLE:
		wdctl_disable();
		break;
	case WDCTL_ENABLE:
		wdctl_enable();
		break;
	case WDCTL_SHOW:
		wdctl_show();
	default:
		/* XXX NEVER REACHED */
		fprintf(stderr, "Oops\n");
		exit(1);
		break;
	}
	exit(0);
}
