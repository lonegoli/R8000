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

#include "httpd.h"

#include "common.h"
#include "safe.h"
#include "util.h"
#include "auth.h"
#include "conf.h"
#include "debug.h"
#include "centralserver.h"
#include "firewall.h"
#include "config.h"

extern pthread_mutex_t	config_mutex;


t_authcode
auth_server_request(t_authresponse *authresponse, const char *request_type, const char *ip, const char *mac, const char *token, unsigned long long int incoming, unsigned long long int outgoing)
{
	int sockfd;
	ssize_t	numbytes;
	size_t totalbytes;
	char buf[MAX_BUF];
	char *tmp;
        char *safe_token;
	int done, nfds;
	fd_set			readfds;
	struct timeval		timeout;
	t_auth_serv	*auth_server = NULL;
	auth_server = get_auth_server();
	
	/* Blanket default is error. */
	authresponse->authcode = AUTH_ERROR;
	
	sockfd = connect_auth_server();
	if (sockfd == -1) {
		/* Could not connect to any auth server */
		return (AUTH_ERROR);
	}


	memset(buf, 0, sizeof(buf));
        safe_token=httpdUrlEncode(token);
	snprintf(buf, (sizeof(buf) - 1),
		"GET %s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&gw_id=%s HTTP/1.0\r\n"
		"User-Agent: FreeFish %s\r\n"
		"Host: %s\r\n"
		"\r\n",
		auth_server->authserv_path,
		auth_server->authserv_auth_script_path_fragment,
		request_type,
		ip,
		mac,
		safe_token,
		incoming,
		outgoing,
        config_get_config()->gw_id,
		VERSION,
		auth_server->authserv_hostname
	);

        free(safe_token);

	debug(LOG_DEBUG, "Sending HTTP request to auth server: [%s]\n", buf);
	send(sockfd, buf, strlen(buf), 0);

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
			
			numbytes = read(sockfd, buf + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return (AUTH_ERROR);
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
			/* FIXME */
			close(sockfd);
			return (AUTH_ERROR);
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return (AUTH_ERROR);
		}
	} while (!done);

	close(sockfd);

	buf[totalbytes] = '\0';
	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", buf);
	
	if ((tmp = strstr(buf, "Auth: "))) {
		if (sscanf(tmp, "Auth: %d", (int *)&authresponse->authcode) == 1) {
			debug(LOG_INFO, "Auth server returned authentication code %d", authresponse->authcode);
			return(authresponse->authcode);
		} else {
			debug(LOG_WARNING, "Auth server did not return expected authentication code");
			return(AUTH_ERROR);
		}
	}
	else {
		return(AUTH_ERROR);
	}


	return(AUTH_ERROR);
}

/*
int connect_backup_ip() {
	s_config *config = config_get_config();
	t_auth_serv *auth_server = NULL;
	FILE * fh;
	ssize_t			numbytes;
    size_t	        	totalbytes;
	int			sockfd, nfds, done;
	char			request[MAX_BUF];
	fd_set			readfds;
	struct timeval		timeout;
	int sockfd;
	struct sockaddr_in their_addr;
	
	history_ip = (char *)safe_malloc(16);
	if ((fh = fopen(TMP_HISTORY_PATH, "r"))) {
		fscanf(fh, "%s", history_ip);
		fclose(fh);
		debug(LOG_DEBUG, "Connecting to history ip %s", history_ip);

		
		auth_server = config->auth_servers;
		bzero(&their_addr, sizeof(struct sockaddr_in));
		their_addr.sin_family = AF_INET;
		their_addr.sin_port = htons(auth_server->authserv_http_port);
		their_addr.sin_addr.s_addr = inet_addr(history_ip);
		

		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			debug(LOG_ERR, "Failed to create a new SOCK_STREAM socket: %s", strerror(errno));
			return (-1);
		}

		if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
		
			debug(LOG_DEBUG, "Failed to connect to history ip %s:%d (%s)", history_ip, auth_server->authserv_http_port, strerror(errno));
			close(sockfd);
			return (-1);
		}
		else {
		
			debug(LOG_DEBUG, "Successfully connected to history ip %s:%d", history_ip, auth_server->authserv_http_port);
		
			snprintf(request, sizeof(request) - 1,
			"GET %s HTTP/1.0\r\n"
			"User-Agent: Freefish\r\n"
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
						return (-1);
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
					return (-1);
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
				
			if (strstr(request, "Pong") == 0) {
				debug(LOG_WARNING, "Auth server did NOT say pong!");
				
			}
			else {
				debug(LOG_DEBUG, "Auth Server Says: Pong");
			}




			
			close(sockfd);
			return sockfd;
		}
	}
	else {
		debug(LOG_ERR, "open %s failed.", TMP_HISTORY_PATH);
		free(history_ip);
		return (-1);
	}
		
}
*/

/* Tries really hard to connect to an auth server. Returns a file descriptor, -1 on error
 */
int connect_auth_server() {
	int sockfd;

	//LOCK_CONFIG();
	sockfd = _connect_auth_server(0);
	//UNLOCK_CONFIG();

	if (sockfd == -1) {
		debug(LOG_ERR, "Failed to connect to any of the auth servers");
		//mark_auth_offline();
		
	}
	else {
		debug(LOG_DEBUG, "Connected to auth server");
		//mark_auth_online();
	}
	return (sockfd);
}


 
int _connect_auth_server(int level) {
	s_config *config = config_get_config();
	t_auth_serv *auth_server = NULL;
	struct in_addr *h_addr;
	int num_servers = 0;
	int retry = 0;
	char * hostname = NULL;
	
	char ** popularserver;
	char * ip;
	char history_ip[16];
	struct sockaddr_in their_addr;
	int sockfd;
	FILE *fh;
	
	level++;


	for (auth_server = config->auth_servers; auth_server; auth_server = auth_server->next) {
		num_servers++;
	}
	debug(LOG_DEBUG, "Level %d: Calculated %d auth servers in list", level, num_servers);

	if (level > num_servers) {

		 
		 if ((fh = fopen(TMP_HISTORY_PATH, "r"))) {
			fscanf(fh, "%s", history_ip);
			fclose(fh);
			debug(LOG_INFO, "Connecting to history ip %s", history_ip);
		 }
		 if(config->auth_servers->authserv_hostname) {
		 	free(config->auth_servers->authserv_hostname);
		 }
		 config->auth_servers->authserv_hostname = safe_strdup(history_ip);
		//return (-1);
		
	}


	auth_server = config->auth_servers;
	hostname = auth_server->authserv_hostname;
	debug(LOG_DEBUG, "Level %d: Resolving auth server [%s]", level, hostname);
	h_addr = wd_gethostbyname(hostname);
	if (!h_addr) {
		for(retry = 0; retry <= 5 && !h_addr; retry++) {
			debug(LOG_ERR, "Level %d: try %d: Resolving auth server [%s] failes,wait 1 min try again", level, retry, hostname);
			sleep(60);
			h_addr = wd_gethostbyname(hostname);
		}
	}
	if (!h_addr) {
		/*
		 * DNS resolving it failed
		 *
		 * Can we resolve any of the popular servers ?
		 */
		debug(LOG_DEBUG, "Level %d: Resolving auth server [%s] failed", level, hostname);
		/*
		* Yes
		*
		* The auth server's DNS server is probably dead. Try the next auth server
		*/
		debug(LOG_INFO, "Level %d: Marking auth server [%s] as bad and trying next if possible", level, hostname);
		LOCK_CONFIG();
		if (auth_server->last_ip) {
			free(auth_server->last_ip);
			auth_server->last_ip = NULL;
		}
		mark_auth_server_bad(auth_server);
		UNLOCK_CONFIG();
		return _connect_auth_server(level);
	}
	else {
		/*
		 * DNS resolving was successful
		 */
		ip = safe_strdup(inet_ntoa(*h_addr));
		debug(LOG_INFO, "Level %d: Resolving auth server [%s] succeeded = [%s]", level, hostname, ip);

		if (!auth_server->last_ip || strcmp(auth_server->last_ip, ip) != 0) {
			/*
			 * But the IP address is different from the last one we knew
			 * Update it
			 */
			debug(LOG_INFO, "Level %d: Updating last_ip IP of server [%s] to [%s]", level, hostname, ip);
			LOCK_CONFIG();
			if (auth_server->last_ip) free(auth_server->last_ip);
			auth_server->last_ip = ip;
			UNLOCK_CONFIG();
			/*backup ip to localhost*/
			if ((fh = fopen(TMP_HISTORY_PATH, "w"))) {
				fprintf(fh, "%s", ip);
				fclose(fh);
			}
			
			/* Update firewall rules */
			fw_clear_authservers();
			fw_set_authservers();
		}
		else {
			/*
			 * IP is the same as last time
			 */
			free(ip);
		}
		/*
		if(level <= num_servers) {
			pthread_exit(NULL);
		}
		*/
		/*
		 * Connect to it
		 */
		debug(LOG_INFO, "Level %d: Connecting to auth server %s:%d", level, hostname, auth_server->authserv_http_port);
		their_addr.sin_family = AF_INET;
		their_addr.sin_port = htons(auth_server->authserv_http_port);
		their_addr.sin_addr = *h_addr;
		memset(&(their_addr.sin_zero), '\0', sizeof(their_addr.sin_zero));
		//free (h_addr);

		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			debug(LOG_ERR, "Level %d: Failed to create a new SOCK_STREAM socket: %s", strerror(errno));
			return(-1);
		}

		if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
			/*
			 * Failed to connect
			 * Mark the server as bad and try the next one
			 */
			debug(LOG_ERR, "Level %d: Failed to connect to auth server %s:%d (%s). Marking it as bad and trying next if possible", level, hostname, auth_server->authserv_http_port, strerror(errno));
			close(sockfd);
			LOCK_CONFIG();
			mark_auth_server_bad(auth_server);
			UNLOCK_CONFIG();
			sleep(3);
			if (level > num_servers) {
				return (-1);
			}
			return _connect_auth_server(level); 
		}
		else {
			/*
			 * We have successfully connected
			 */
			debug(LOG_INFO, "Level %d: Successfully connected to auth server %s:%d", level, hostname, auth_server->authserv_http_port);
			return sockfd;
		}
	}
}


/*
int _connect_auth_server(int level) {
	s_config *config = config_get_config();
	t_auth_serv *auth_server = NULL;
	struct in_addr *h_addr;
	int num_servers = 0;
	char * hostname = NULL;
	char * popular_servers[] = {
		  "www.google.com",
		  "www.yahoo.com",
		  NULL
	};
	char ** popularserver;
	char * ip;
	struct sockaddr_in their_addr;
	int sockfd;

	// XXX level starts out at 0 and gets incremented by every iterations. 
	level++;

	//
	// Let's calculate the number of servers we have
	//
	for (auth_server = config->auth_servers; auth_server; auth_server = auth_server->next) {
		num_servers++;
	}
	debug(LOG_DEBUG, "Level %d: Calculated %d auth servers in list", level, num_servers);

	if (level > num_servers) {
		//
		// We've called ourselves too many times
		// This means we've cycled through all the servers in the server list
		// at least once and none are accessible所有的服务器均不在线
		//
		return (-1);
	}

	//
	// Let's resolve the hostname of the top server to an IP address
	//
	auth_server = config->auth_servers;
	hostname = auth_server->authserv_hostname;
	debug(LOG_DEBUG, "Level %d: Resolving auth server [%s]", level, hostname);
	h_addr = wd_gethostbyname(hostname);//通过域名找IP 
	if (!h_addr) {
		//
		// DNS resolving it failed
		//
		// Can we resolve any of the popular servers ?
		//
		debug(LOG_DEBUG, "Level %d: Resolving auth server [%s] failed", level, hostname);

		for (popularserver = popular_servers; *popularserver; popularserver++) {
			debug(LOG_DEBUG, "Level %d: Resolving popular server [%s]", level, *popularserver);
			h_addr = wd_gethostbyname(*popularserver);
			if (h_addr) {
				debug(LOG_DEBUG, "Level %d: Resolving popular server [%s] succeeded = [%s]", level, *popularserver, inet_ntoa(*h_addr));
				break;
			}
			else {
				debug(LOG_DEBUG, "Level %d: Resolving popular server [%s] failed", level, *popularserver);
			}
		}

		//
		//If we got any h_addr buffer for one of the popular servers, in other
		// words, if one of the popular servers resolved, we'll assume the DNS
		// works, otherwise we'll deal with net connection or DNS failure.
		//
		if (h_addr) {
			free (h_addr);
			//
			// Yes
			//
			// The auth server's DNS server is probably dead. Try the next auth server
			//
			debug(LOG_DEBUG, "Level %d: Marking auth server [%s] as bad and trying next if possible", level, hostname);
			if (auth_server->last_ip) {
				free(auth_server->last_ip);
				auth_server->last_ip = NULL;
			}
			mark_auth_server_bad(auth_server);
			return _connect_auth_server(level);
		}
		else {
			//
			/// No
			//
			// It's probably safe to assume that the internet connection is malfunctioning
			// and nothing we can do will make it work
			// 可能网络出现了问题
			//
			mark_offline();
			debug(LOG_DEBUG, "Level %d: Failed to resolve auth server and all popular servers. "
					"The internet connection is probably down", level);
			return(-1);
		}
	}
	else {
		//
		// DNS resolving was successful
		//
		ip = safe_strdup(inet_ntoa(*h_addr));
		debug(LOG_DEBUG, "Level %d: Resolving auth server [%s] succeeded = [%s]", level, hostname, ip);

		if (!auth_server->last_ip || strcmp(auth_server->last_ip, ip) != 0) {
			//
			// But the IP address is different from the last one we knew
			// Update it
			//
			debug(LOG_DEBUG, "Level %d: Updating last_ip IP of server [%s] to [%s]", level, hostname, ip);
			if (auth_server->last_ip) free(auth_server->last_ip);
			auth_server->last_ip = ip;

			// Update firewall rules 
			fw_clear_authservers();
			fw_set_authservers();
		}
		else {
			//
			// IP is the same as last time
			//
			free(ip);
		}

		//
		// Connect to it
		//
		debug(LOG_DEBUG, "Level %d: Connecting to auth server %s:%d", level, hostname, auth_server->authserv_http_port);
		their_addr.sin_family = AF_INET;
		their_addr.sin_port = htons(auth_server->authserv_http_port);
		their_addr.sin_addr = *h_addr;
		memset(&(their_addr.sin_zero), '\0', sizeof(their_addr.sin_zero));
		free (h_addr);

		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			debug(LOG_ERR, "Level %d: Failed to create a new SOCK_STREAM socket: %s", strerror(errno));
			return(-1);
		}

		if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
			//
			// Failed to connect
			// Mark the server as bad and try the next one
			//
			debug(LOG_DEBUG, "Level %d: Failed to connect to auth server %s:%d (%s). Marking it as bad and trying next if possible", level, hostname, auth_server->authserv_http_port, strerror(errno));
			close(sockfd);
			mark_auth_server_bad(auth_server);
			return _connect_auth_server(level); // Yay recursion! 
		}
		else {
			//
			// We have successfully connected
			//
			debug(LOG_DEBUG, "Level %d: Successfully connected to auth server %s:%d", level, hostname, auth_server->authserv_http_port);
			return sockfd;
		}
	}
}
*/

