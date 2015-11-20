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
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "common.h"
#include "debug.h"
#include "agent_util.h"


static int
connect_to_agent(void)
{
	int sock;
	struct sockaddr_un	sa_un;
	char *sock_name = DEFAULT_AGENT_SOCK;
	/* Connect to socket */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&sa_un, 0, sizeof(sa_un));
	sa_un.sun_family = AF_UNIX;
	strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));
	
	if (connect(sock, (struct sockaddr *)&sa_un, 
		strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
		debug(LOG_ERR, "connect agent (Error: %s)", strerror(errno));
		return -1;
	}
	
	return sock;
}

static int 
read_socket(int sockfd, char *response)
{
	struct timeval timeout;
	fd_set rfd_set;
	
	ssize_t 		recvbytes = 0;
	int ret;
	char *p;
		
	while(1) {
		FD_ZERO(&rfd_set);
		FD_SET(sockfd, &rfd_set);
	
		timeout.tv_sec = 30;
		timeout.tv_usec = 0;
			
		ret = select(sockfd+1, &rfd_set, NULL, NULL, &timeout);
		if(ret == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from comm server");
	
			return -1;
		}
		else if(ret < 0) {
				
			debug(LOG_ERR, "Error reading data via select() from comm server: %s", strerror(errno));
			
			return -1;
				
		}
	
		else if(FD_ISSET(sockfd, &rfd_set)) {
			recvbytes = recv(sockfd, response , MAX_BUF, 0);
			if(recvbytes < 0) {
				if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
					continue;
				}
				return -1;
				debug(LOG_ERR, "An error occurred while reading from comm server: %s", strerror(errno));
			}
	
			else if(recvbytes == 0) {
				debug(LOG_ERR, "peer socket closed");
				return -1;
			}
			else {
				response[recvbytes] = '\0';
				debug(LOG_DEBUG, "Read %d bytes", recvbytes);
				debug(LOG_DEBUG, "Read is %s", response);
				return 0;
			}
				
		}
	
	}
}

	
void
interaction_agent(void)
{
	char data[MAX_BUF];
	int ret, sockfd;
		
	sockfd = connect_to_agent();
	if(sockfd > 0) {
		ret = read_socket(sockfd, data);
		close(sockfd);
	}
}
	


