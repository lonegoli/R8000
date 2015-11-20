#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <netdb.h>

#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "common.h"
#include "centralserver.h"

struct addrinfo *
lookup_host(const char *hostname, const int port) {
	struct addrinfo hints,*res;
	int errcode;
	char str_port[8];
	sprintf(str_port, "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;
	if((errcode = getaddrinfo(hostname, str_port, &hints, &res)) !=0 ) {
		return NULL;
	}
	return res;
	
}

int 
socket_setnonblock(int sockfd) {
	int flags;
	if((flags = fcntl(sockfd, F_GETFL, 0)) == -1 ||
             fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
    	return (-1);         
	}
	return 0;
	
}



int 
try_connect_to_server() {
	int count;
	int result;
	s_config *config = config_get_config();
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	
	for(count = 1; count <= config->request_retry + 1; count++) {
		//debug(LOG_INFO, "Try to connect for the %d time", count);
		debug(LOG_INFO, "Try to connect to the cloud server. Attempt times: %d", count);
		if((result = connect_to_server(count)) > 0) {
			return result;
		}
		debug(LOG_INFO, "Wait %d second,try again", config->request_timeout);
		timeout.tv_sec = time(NULL) + config->request_timeout;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	}
	debug(LOG_ERR, "Connect timeout");
	return -1;
}

int 
connect_to_server(int level) {
	int sockfd;

	sockfd = _connect_to_server(level);

	if (sockfd == -1) {
		debug(LOG_ERR, "Failed to connect to server");
		
	}
	else {
		socket_setnonblock(sockfd);
		debug(LOG_INFO, "Connected to server successfully. [sockfd:%d]",sockfd);
	}
	return (sockfd);
}






int 
_connect_to_server(int level) {
	s_config *config = config_get_config();
	t_comm_serv *comm_server = NULL;
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct sockaddr_in peer_addr;
	
	char * hostname = NULL;
    char *ip;
	
	int sockfd;
	

	comm_server = config->comm_servers;
	hostname = comm_server->commserv_hostname;
	
	if(!comm_server->commserv_hostname || !comm_server->commserv_port) {
		debug(LOG_ERR, "Hostname or port Undefine");
		return (-1);
	}
	if((sockfd = safe_socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		debug(LOG_ERR, "Failed to create socket");
		safe_close(sockfd);
		return (-1);
	}
	
	//int opt = 1;	 
	//setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt)); 
	
	res = lookup_host(comm_server->commserv_hostname, comm_server->commserv_port);
	if(!res) {
		debug(LOG_ERR, "Resolve domain to IP failed");
		safe_close(sockfd);
		return (-1);
	}
	memcpy(&peer_addr, res->ai_addr, res->ai_addrlen);
	ip = safe_strdup(inet_ntoa(peer_addr.sin_addr));
	debug(LOG_DEBUG, "Resolve  domain [%s] to IP [%s]  successfully", hostname, ip);
	freeaddrinfo(res);

	if (!comm_server->last_ip || strcmp(comm_server->last_ip, ip) != 0) {
		debug(LOG_DEBUG, "Updating last_ip IP of server [%s] to [%s]", hostname, ip);
		if (comm_server->last_ip) safe_free(comm_server->last_ip);
		comm_server->last_ip = ip;

	} else {

		safe_free(ip);
		
	}

	if(connect(sockfd, (struct sockaddr *)&peer_addr, sizeof(struct sockaddr)) == -1) {
		debug(LOG_ERR, "Failed to connect to cloud server %s:%d (%s). Marking it as bad and will retry if possible", hostname, comm_server->commserv_port, strerror(errno));
		safe_close(sockfd);
		return (-1);
	} else {
		debug(LOG_DEBUG, "Successfully connected to cloud server %s:%d", hostname, comm_server->commserv_port);
		return sockfd;
	}
	
}
