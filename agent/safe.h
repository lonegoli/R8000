#ifndef _SAFE_H_
#define _SAFE_H_

#include <stdarg.h> /* For va_list */
#include <sys/types.h> /* For fork */
#include <unistd.h> /* For fork */
//#include <sys/socket.h>

/** @brief Safe version of malloc
 */
void * safe_malloc (size_t size);

/* @brief Safe version of strdup
 */
char * safe_strdup(const char *s);

/* @brief Safe version of asprintf
 */
int safe_asprintf(char **strp, const char *fmt, ...);

/* @brief Safe version of vasprintf
 */
int safe_vasprintf(char **strp, const char *fmt, va_list ap);

/* @brief Safe version of fork
 */
int safe_encrypt_http_send(int sockfd, char *buff, size_t nbytes, int flags);
int safe_decrypt_http_read(int sockfd, int setimeout, char *request);
int safe_send(int sockfd, char *buff, size_t nbytes, int flags);
//int safe_read(int sockfd, int setimeout, char *request);


pid_t safe_fork(void);

int safe_socket (int domain, int type, int protocol);
int safe_close(int fd);
void safe_free(void *ptr);



#endif /* _SAFE_H_ */


