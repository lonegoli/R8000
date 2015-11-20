#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

/* for strerror() */
#include <string.h>

/* for wait() */
#include <sys/wait.h>

/* for unix socket communication*/
#include <sys/socket.h>
#include <sys/un.h>

#include "common.h"
#include "httpd.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "gateway.h"
#include "firewall.h"
#include "commandline.h"
#include "auth.h"
#include "http.h"
#include "client_list.h"
#include "wdctl_thread.h"
#include "ping_thread.h"
#include "httpd_thread.h"
#include "util.h"
//#include "sqlite_util.h"
#include "threadpool.h"



static pthread_t tid_fw_counter = 0;
static pthread_t tid_ping = 0; 

/* The internal web server */
httpd * webserver = NULL;

/* from commandline.c */
extern char ** restartargv;
extern pid_t restart_orig_pid;
t_client *firstclient;

/* from client_list.c */
extern pthread_mutex_t client_list_mutex;

/* Time when freefish started        typedef long     time_t;*/
time_t started_time = 0;


void append_x_restartargv(void) {
	int i;

	for (i=0; restartargv[i]; i++);

	restartargv[i++] = safe_strdup("-x");
	safe_asprintf(&(restartargv[i++]), "%d", getpid());
	
}


void get_clients_from_parent(void) {
	int sock;
	struct sockaddr_un	sa_un;
	s_config * config = NULL;
	char linebuffer[MAX_BUF];
	int len = 0;
	char *running1 = NULL;
	char *running2 = NULL;
	char *token1 = NULL;
	char *token2 = NULL;
	char onechar;
	char *command = NULL;
	char *key = NULL;
	char *value = NULL;
	t_client * client = NULL;
	t_client * lastclient = NULL;

	config = config_get_config();
	
	debug(LOG_INFO, "Connecting to parent to download clients");

	/* Connect to socket */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&sa_un, 0, sizeof(sa_un));
	sa_un.sun_family = AF_UNIX;
	strncpy(sa_un.sun_path, config->internal_sock, (sizeof(sa_un.sun_path) - 1));

	if (connect(sock, (struct sockaddr *)&sa_un, strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
		debug(LOG_ERR, "Failed to connect to parent (%s) - client list not downloaded", strerror(errno));
		return;
	}

	debug(LOG_INFO, "Connected to parent.  Downloading clients");

	LOCK_CLIENT_LIST();

	command = NULL;
	memset(linebuffer, 0, sizeof(linebuffer));
	len = 0;
	client = NULL;

	while (read(sock, &onechar, 1) == 1) {
		if (onechar == '\n') {
	
			onechar = '\0';
		}
		linebuffer[len++] = onechar;

		if (!onechar) {
		
			debug(LOG_DEBUG, "Received from parent: [%s]", linebuffer);
			running1 = linebuffer;
			while ((token1 = strsep(&running1, "|")) != NULL) {
				if (!command) {
					
					command = token1;
				}
				else {
				
					running2 = token1;
					key = value = NULL;
					while ((token2 = strsep(&running2, "=")) != NULL) {
						if (!key) {
							key = token2;
						}
						else if (!value) {
							value = token2;
						}
					}
				}

				if (strcmp(command, "CLIENT") == 0) {
					
					if (!client) {
						
						client = safe_malloc(sizeof(t_client));
						memset(client, 0, sizeof(t_client));
					}
				}

				if (key && value) {
					if (strcmp(command, "CLIENT") == 0) {
						
						if (strcmp(key, "ip") == 0) {
							client->ip = safe_strdup(value);
						}
						else if (strcmp(key, "mac") == 0) {
							client->mac = safe_strdup(value);
						}
						else if (strcmp(key, "token") == 0) {
							client->token = safe_strdup(value);
						}
						else if (strcmp(key, "fw_connection_state") == 0) {
							client->fw_connection_state = atoi(value);
						}
						else if (strcmp(key, "fd") == 0) {
							client->fd = atoi(value);
						}
						else if (strcmp(key, "counters_incoming") == 0) {
							client->counters.incoming_history = atoll(value);
							client->counters.incoming = client->counters.incoming_history;
						}
						else if (strcmp(key, "counters_outgoing") == 0) {
							client->counters.outgoing_history = atoll(value);
							client->counters.outgoing = client->counters.outgoing_history;
						}
						else if (strcmp(key, "counters_last_updated") == 0) {
							client->counters.last_updated = atol(value);
						}
						else {
							debug(LOG_NOTICE, "I don't know how to inherit key [%s] value [%s] from parent", key, value);
						}
					}
				}
			}

			
			if (client) {
				
				if (!firstclient) {
					firstclient = client;
					lastclient = firstclient;
				}
				else {
					lastclient->next = client;
					lastclient = client;
				}
			}

			/* Clean up */
			command = NULL;
			memset(linebuffer, 0, sizeof(linebuffer));
			len = 0;
			client = NULL;
		}
	}

	UNLOCK_CLIENT_LIST();
	debug(LOG_INFO, "Client list downloaded successfully from parent");

	close(sock);
}


void
sigchld_handler(int s)
{
	int	status;
	pid_t rc;
	//不可重入
	//debug(LOG_DEBUG, "Handler for SIGCHLD called. Trying to reap a child");

	rc = waitpid(-1, &status, WNOHANG);

	//debug(LOG_DEBUG, "Handler for SIGCHLD reaped child PID %d", rc);
}


void
termination_handler(int s)
{
	static	pthread_mutex_t	sigterm_mutex = PTHREAD_MUTEX_INITIALIZER;

	debug(LOG_INFO, "Handler for termination caught signal %d", s);

	
	if (pthread_mutex_trylock(&sigterm_mutex)) {
		debug(LOG_INFO, "Another thread already began global termination handler. I'm exiting");
		pthread_exit(NULL);
	}
	else {
		debug(LOG_INFO, "Cleaning up and exiting");
	}

	debug(LOG_INFO, "Flushing firewall rules...");
	fw_destroy();

	
	if (tid_fw_counter) {
		debug(LOG_INFO, "Explicitly killing the fw_counter thread");
		pthread_kill(tid_fw_counter, SIGKILL);
	}
	if (tid_ping) {
		debug(LOG_INFO, "Explicitly killing the ping thread");
		pthread_kill(tid_ping, SIGKILL);
	}

	debug(LOG_NOTICE, "Exiting...");
	exit(s == 0 ? 1 : 0);
}


static void
init_signals(void)
{
	struct sigaction sa;

	debug(LOG_INFO, "Initializing signal handlers");
	
	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}


	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	sa.sa_handler = termination_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	/* Trap SIGTERM */
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGQUIT */
	if (sigaction(SIGQUIT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGINT */
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}
}


static void
main_loop(void)
{
	int result;
	pthread_t	tid;
	s_config *config = config_get_config();
	request *r;
	void **params;
	int stacksize = 40960;
	pthread_attr_t attr;

    /* Set the time when freefish started */
	if (!started_time) {
		debug(LOG_INFO, "Setting started_time");
		started_time = time(NULL);
	}
	else if (started_time < MINIMUM_STARTED_TIME) {
		debug(LOG_WARNING, "Detected possible clock skew - re-setting started_time");
		started_time = time(NULL);
	}

	/* If we don't have the Gateway IP address, get it. Can't fail. */
	if (!config->gw_address) {
		debug(LOG_INFO, "Finding IP address of %s", config->gw_interface);
		if ((config->gw_address = get_iface_ip(config->gw_interface)) == NULL) {
			debug(LOG_ERR, "Could not get IP address information of %s, exiting...", config->gw_interface);
			exit(1);
		}
		debug(LOG_DEBUG, "%s = %s", config->gw_interface, config->gw_address);
	}

	/* If we don't have the Gateway ID, construct it from the internal MAC address.
	 * "Can't fail" so exit() if the impossible happens. */
	 /*
	if (!config->gw_id) {
    	debug(LOG_INFO, "Finding MAC address of %s", config->external_interface);
    	if ((config->gw_id = get_iface_mac(config->external_interface)) == NULL) {
			debug(LOG_ERR, "Could not get MAC address information of %s, exiting...", config->external_interface);
			exit(1);
		}
		debug(LOG_DEBUG, "%s = %s", config->gw_interface, config->gw_id);
	}
	*/
	if (!config->gw_id) {
    	debug(LOG_INFO, "Finding MAC address of %s", DEFAULT_BASIC_MAC_INTERFACE);
    	if ((config->gw_id = get_iface_mac(DEFAULT_BASIC_MAC_INTERFACE)) == NULL) {
			debug(LOG_ERR, "Could not get MAC address information of %s, exiting...", DEFAULT_BASIC_MAC_INTERFACE);
			exit(1);
		}
		debug(LOG_DEBUG, "%s = %s", DEFAULT_BASIC_MAC_INTERFACE, config->gw_id);
	}
	/* Initializes the web server */
	debug(LOG_NOTICE, "Creating web server on %s:%d", config->gw_address, config->gw_port);
	if ((webserver = httpdCreate(config->gw_address, config->gw_port)) == NULL) {
		debug(LOG_ERR, "Could not create web server: %s", strerror(errno));
		exit(1);
	}

	debug(LOG_INFO, "Assigning callbacks to web server");
	httpdAddCContent(webserver, "/", "freefish", 0, NULL, http_callback_freefish);
	httpdAddCContent(webserver, "/freefish", "", 0, NULL, http_callback_freefish);
	httpdAddCContent(webserver, "/freefish", "about", 0, NULL, http_callback_about);
	httpdAddCContent(webserver, "/freefish", "status", 0, NULL, http_callback_status);
	httpdAddCContent(webserver, "/freefish", "auth", 0, NULL, http_callback_auth);

	httpdAddC404Content(webserver, http_callback_404);

	/* Reset the firewall (if FreeFish crashed) */
	fw_destroy();
	/* Then initialize it */
	if (!fw_init()) {
		debug(LOG_ERR, "FATAL: Failed to initialize firewall");
		exit(1);
	}
	config->auth_self = 1;

	/*
	int sockfd;
    sockfd = connect_auth_server();
	if (sockfd == -1) {
	
		return;
	}
	close(sockfd);
	*/
	
	system("ulimit -s 4096");
	
	result = pthread_attr_init(&attr);
	if(result !=0) {
		debug(LOG_ERR, "FATAL: Failed to pthread_attr_init - exiting");
	    termination_handler(0);
	}
	result = pthread_attr_setstacksize(&attr, stacksize);
	if(result !=0) {
		debug(LOG_ERR, "FATAL: Failed to pthread_attr_setstacksize - exiting");
	    termination_handler(0);
	}	
	
	
	/* Start clean up thread */
	debug(LOG_INFO, "create a new thread (thread_client_timeout_check)");
	result = pthread_create(&tid_fw_counter, NULL, (void *)thread_client_timeout_check, NULL);
	if (result != 0) {
	    debug(LOG_ERR, "FATAL: Failed to create a new thread (fw_counter) - exiting");
	    termination_handler(0);
	}
	pthread_detach(tid_fw_counter);

	/* Start control thread */
	debug(LOG_INFO, "create a new thread (thread_ffctl)");
	result = pthread_create(&tid, &attr, (void *)thread_wdctl, (void *)safe_strdup(config->wdctl_sock));
	if (result != 0) {
		debug(LOG_ERR, "FATAL: Failed to create a new thread (wdctl) - exiting");
		termination_handler(0);
	}
	pthread_detach(tid);
	
	/* Start heartbeat thread */
	debug(LOG_INFO, "create a new thread (thread_ping)");
	result = pthread_create(&tid_ping, &attr, (void *)thread_ping, NULL);
	if (result != 0) {
	    debug(LOG_ERR, "FATAL: Failed to create a new thread (ping) - exiting");
		termination_handler(0);
	}
	pthread_detach(tid_ping);
	
	pthread_attr_destroy(&attr);
	
	struct threadpool *pool = threadpool_init(5, 10);
	
	debug(LOG_NOTICE, "Waiting for connections(V1.0.12)");
	while(1) {
		r = httpdGetConnection(webserver, NULL);// listenning HTTP requse

	
		if (webserver->lastError == -1) {
			
			continue; 
		}
		else if (webserver->lastError < -1) {
			
			debug(LOG_ERR, "FATAL: httpdGetConnection returned unexpected value %d, exiting.", webserver->lastError);
			termination_handler(0);
		}
		else if (r != NULL) {
			
			debug(LOG_DEBUG, "Received connection from %s, spawning worker thread", r->clientAddr);
		
			params = safe_malloc(3 * sizeof(void *));
			*params = webserver;
			*(params + 1) = r;
			*(params + 2) = config;

			/*
			result = pthread_create(&tid, NULL, (void *)thread_httpd, (void *)params);
			if (result != 0) {
				debug(LOG_ERR, "FATAL: Failed to create a new thread (httpd) - exiting");
				termination_handler(0);
			}
			//pthread_detach(tid);
			*/
			threadpool_add_job(pool, (void *)thread_httpd, (void *)params);
		}
		else {
			
		}
	}
	threadpool_destroy(pool);
	
}

/** Reads the configuration file and then starts the main loop */
int main(int argc, char **argv) {

	s_config *config = config_get_config();
	config_init();//初始化配置文件的默认值

	parse_commandline(argc, argv);//解析命令行参数

	/* Initialize the config */
	config_read(config->configfile);

	config_validate();


	client_list_init();

	//db_init();

	init_signals();

	if (restart_orig_pid) {
		
		get_clients_from_parent();

		
		while (kill(restart_orig_pid, 0) != -1) {
			debug(LOG_INFO, "Waiting for parent PID %d to die before continuing loading", restart_orig_pid);
			sleep(1);
		}

		debug(LOG_INFO, "Parent PID %d seems to be dead. Continuing loading.");
	}

	if (config->daemon) {

		debug(LOG_INFO, "Forking into background");

		switch(safe_fork()) {
			case 0: /* child */
				setsid();
				append_x_restartargv();//将自己的PID加入保存命令行参数的restartargv中
				main_loop();
				break;

			default: /* parent */
				exit(0);
				break;
		}
	}
	else {
		append_x_restartargv();
		main_loop();
	}

	return(0); /* never reached */
}
