#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "ping_thread.h"
#include "util.h"
#include "centralserver.h"
#include "fw_iptables.h"


static void ping(void);
static void update_dns(void);


extern time_t started_time;

  
void
thread_ping(void *arg)
{
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	s_config	*config = config_get_config();
	
	while (1) {
		
		debug(LOG_INFO, "begin to resolve DNS");
		ping();
		
	/*
		if(config->pingok) {
			
			if(config->auth_self) {
				fw_clear_authservers();
				fw_set_authservers();
			}
			pthread_exit(NULL);
		
		
		}
		else {
			
			timeout.tv_sec = time(NULL) + 60;
			timeout.tv_nsec = 0;
		}
		*/
		//////////////////////////////////////////
		if(config->pingok) {
			update_dns();
		}
		else {
			timeout.tv_sec = time(NULL) + 60;
			timeout.tv_nsec = 0;
			pthread_mutex_lock(&cond_mutex);
			pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
			pthread_mutex_unlock(&cond_mutex);
			debug(LOG_INFO, "retry to resolve DNS");
		}
	}
}


static void
ping(void)
{
	ssize_t			numbytes;
        size_t	        	totalbytes;
	int			sockfd, nfds, done;
	char			request[MAX_BUF];
	fd_set			readfds;
	struct timeval		timeout;

	s_config	*config = config_get_config();
	
	t_auth_serv	*auth_server = NULL;
	auth_server = get_auth_server();
	
	debug(LOG_DEBUG, "Entering ping()");
	

	sockfd = connect_auth_server();
	if (sockfd == -1) {
		
		return;
	}
	else {
		config->pingok = 1;
	}

/*	
	snprintf(request, sizeof(request) - 1,
			"GET %s HTTP/1.0\r\n"
			"User-Agent: FreeFish\r\n"
			"Host: %s\r\n"
			"\r\n",
			auth_server->authserv_ping_script_path_fragment,
			auth_server->authserv_hostname);

	debug(LOG_DEBUG, "HTTP Request to Server: [%s]", request);
	
	send(sockfd, request, strlen(request), 0);

	debug(LOG_DEBUG, "Reading response");
	
	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; 
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);

		if (nfds > 0) {
			
			numbytes = read(sockfd, request + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
				
				close(sockfd);
				return;
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			
			close(sockfd);
			return;
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			
			close(sockfd);
			return;
		}
	} while (!done);
	close(sockfd);

	debug(LOG_DEBUG, "Done reading reply, total %d bytes", totalbytes);

	request[totalbytes] = '\0';

	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", request);
	
	if (strstr(request, "Success") == 0) {
		debug(LOG_ERR, "Auth server did NOT say Success!");
	
	}
	else {
		debug(LOG_DEBUG, "Auth Server Says: Success");
		config->pingok = 1;
	}
*/
	return;	
}


static void 
update_dns(void)
{
	struct addrinfo hints;
	struct addrinfo *res, *cur;
	struct sockaddr_in *addr;
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	char iplist[1024];
	char cmd[128];
	char *domainlist[]={"connect.facebook.net","connect.facebook.com","s-static.ak.facebook.com","static.xx.fbcdn.net","static.ak.facebook.com","fbstatic-a.akamaihd.net","m.facebook.com","graph.facebook.com"};
	int i,ret;
	char ipbuf[16];
	memset(iplist, 0, sizeof(iplist)/sizeof(iplist[0]));
	while(1) {
		timeout.tv_sec = time(NULL) + 300;
		timeout.tv_nsec = 0;
		pthread_mutex_lock(&cond_mutex);
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
		pthread_mutex_unlock(&cond_mutex);

		for(i=0; i< sizeof(domainlist)/sizeof(domainlist[0]); i++){
			 memset(&hints, 0, sizeof(struct addrinfo));
			ret = getaddrinfo(domainlist[i], NULL,&hints,&res);
			if (ret!=0) {
			}
			else {
				//debug(LOG_INFO, "%s [%s]",domainlist[i], inet_ntoa(*h_addr));
				/*
				for (cur = res; cur != NULL; cur = cur->ai_next) {
        			addr = (struct sockaddr_in *)cur->ai_addr;
        			printf("%s\n\r", inet_ntop(AF_INET, &addr->sin_addr, ipbuf, 16));
					printf("%s<%s>\n\r", domainlist[i],ipbuf);
    			}*/

			
				if(res != NULL) {
					addr = (struct sockaddr_in *)res->ai_addr;
        			inet_ntop(AF_INET, &addr->sin_addr, ipbuf, 16);
					debug(LOG_INFO,"%s<%s>",domainlist[i],ipbuf);
					if(!strstr(iplist, ipbuf)) {
						strcat(iplist, "<");
						strcat(iplist, ipbuf);
						strcat(iplist, ">");
						printf("%s\n\r",iplist);
						//sprintf(cmd, "iptables -t filter -A FF_br0_Global -d %s -j ACCEPT",ipbuf);
						iptables_do_command("-t filter -A " TABLE_FREEFISH_GLOBAL " -d %s -j ACCEPT", ipbuf);
						//printf("ssssssssssssssssss%s\n\r",cmd);
						//system(cmd);
						//sprintf(cmd, "iptables -t nat -A FF_br0_Global -d %s -j ACCEPT",ipbuf);
						iptables_do_command("-t nat -A " TABLE_FREEFISH_GLOBAL " -d %s -j ACCEPT", ipbuf);
						//printf("ssssssssssssssssss%s\n\r",cmd);
						//system(cmd);
					}
					
					freeaddrinfo(res);
				}
			
			}
			
		}
		
	}
}

