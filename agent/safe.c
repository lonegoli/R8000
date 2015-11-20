#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


#include "safe.h"
#include "util.h"
#include "common.h"
#include "debug.h"
#include <syslog.h>

int safe_socket (int domain, int type, int protocol) {
	int sockfd;
	sockfd = socket(domain, type, protocol);
	//LOG(__FILE__,__func__,__LINE__,"socket[%d]",sockfd);
	return sockfd;
	
}

int safe_close(int fd) {
	int ret;
	//LOG(__FILE__,__func__,__LINE__,"free socket[%d]",fd);
	ret = close(fd);
	return ret;
	
}



void * safe_malloc (size_t size) {
	void * retval = NULL;
	retval = malloc(size);
	if (!retval) {
		debug(LOG_CRIT, "Failed to malloc %d bytes of memory: %s.  Bailing out", size, strerror(errno));
		exit(1);
	}
	//LOG(__FILE__,__func__,__LINE__,"malloc[%ul]",retval);
	return (retval);
}

char * safe_strdup(const char *s) {
	char * retval = NULL;
	if (!s) {
		debug(LOG_CRIT, "safe_strdup called with NULL which would have crashed strdup. Bailing out");
		exit(1);
	}
	retval = strdup(s);
	if (!retval) {
		debug(LOG_CRIT, "Failed to duplicate a string: %s.  Bailing out", strerror(errno));
		exit(1);
	}
	//LOG(__FILE__,__func__,__LINE__,"malloc[%ul]",retval);
	return (retval);
}

void safe_free(void *ptr) {
	//LOG(__FILE__,__func__,__LINE__,"free malloc[%ul]",ptr);
	free(ptr);
}


int safe_asprintf(char **strp, const char *fmt, ...) {
	va_list ap;
	int retval;

	va_start(ap, fmt);
	retval = safe_vasprintf(strp, fmt, ap);
	va_end(ap);

	return (retval);
}

int safe_vasprintf(char **strp, const char *fmt, va_list ap) {
	int retval;

	retval = vasprintf(strp, fmt, ap);

	if (retval == -1) {
		debug(LOG_CRIT, "Failed to vasprintf: %s.  Bailing out", strerror(errno));
		exit (1);
	}
	return (retval);
}


int safe_encrypt_http_send(int sockfd, char *buff, size_t nbytes, int flags) {
	int result;
	char *p = strstr(buff, "\r\n\r\n");
	if(p != NULL)
	{
		char_encrypt(p+4, KEY);
	}
	while((result = send(sockfd, buff, nbytes, flags)) < 0) {
		if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
			continue;
		} else {
			result = -1;
			break;					
		}
	}
	if(p != NULL)
	{
		char_decrypt(p+4, KEY);
	}
	return result;

}

int safe_send(int sockfd, char *buff, size_t nbytes, int flags) {
	int result;
	while((result = send(sockfd, buff, nbytes, flags)) < 0) {
		if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
			continue;
		} else {
		return -1;				
		}
	}
	return result;
}


int safe_decrypt_http_read(int sockfd, int setimeout, char *request)
{
	struct timeval timeout;
	fd_set rfd_set;

	ssize_t			recvbytes = 0;
    size_t	        pointbytes = 0;
	int ret;
	char *p;
	
	while(1) {
		FD_ZERO(&rfd_set);
		FD_SET(sockfd, &rfd_set);

		timeout.tv_sec = setimeout;
		timeout.tv_usec = 0;
		
		ret = select(sockfd+1, &rfd_set, NULL, NULL, &timeout);
		if(ret == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from cloud server");
			return SELECT_TIMEOUT;
		}
		else if(ret < 0) {
			if(errno == EINTR) {
				continue;
			}
			debug(LOG_ERR, "Error reading data via select() from cloud server: %s", strerror(errno));	
			return SELECT_ERROR;
			
		}

		else if(FD_ISSET(sockfd, &rfd_set)) {
				recvbytes = recv(sockfd, request + pointbytes, MAX_BUF - (pointbytes + 1), 0);
				if(recvbytes < 0) {
					if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
						continue;
					}
					return SOCKET_ERROR;
					debug(LOG_ERR, "An error occurred while reading data from socket: %s", strerror(errno));
				}

				else if(recvbytes == 0) {
					debug(LOG_NOTICE, "Peer socket closed");
					return SOCKET_PIPE_BROKE;
				}
				else {
					pointbytes += recvbytes;
					request[pointbytes] = '\0';
					debug(LOG_DEBUG, "Read %d bytes, total %d", recvbytes, pointbytes);
					//debug(LOG_DEBUG, "Read is %s", response);
					if(((p = strstr(request, "\r\n\r\n")) != NULL) && (get_response_content_length(request) <= strlen(p + 4))) {
						char_decrypt(p + 4,KEY);
						debug(LOG_INFO, "Received a request:%s", request);
						return SOCKET_READ_OK;
					}
					continue;
				}
			
		}

	}
					
}


pid_t safe_fork(void) {
	pid_t result;
	result = fork();

	if (result == -1) {
		debug(LOG_CRIT, "Failed to fork: %s.  Bailing out", strerror(errno));
		exit (1);
	}
	else if (result == 0) {
		
	}

	return result;
}


