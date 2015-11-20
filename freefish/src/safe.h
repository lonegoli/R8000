#ifndef _SAFE_H_
#define _SAFE_H_

#include <stdarg.h> /* For va_list */
#include <sys/types.h> /* For fork */
#include <unistd.h> /* For fork */


void * safe_malloc (size_t size);


char * safe_strdup(const char *s);


int safe_asprintf(char **strp, const char *fmt, ...);


int safe_vasprintf(char **strp, const char *fmt, va_list ap);



pid_t safe_fork(void);

#endif /* _SAFE_H_ */

