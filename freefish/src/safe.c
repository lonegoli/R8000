#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "httpd.h"
#include "safe.h"
#include "debug.h"
#include <syslog.h>

/* From gateway.c */
extern httpd * webserver;

void * safe_malloc (size_t size) {
	void * retval = NULL;
	retval = malloc(size);
	if (!retval) {
		debug(LOG_CRIT, "Failed to malloc %d bytes of memory: %s.  Bailing out", size, strerror(errno));
		exit(1);
	}
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
	return (retval);
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

pid_t safe_fork(void) {
	pid_t result;
	result = fork();

	if (result == -1) {
		debug(LOG_CRIT, "Failed to fork: %s.  Bailing out", strerror(errno));
		exit (1);
	}
	else if (result == 0) {
		/* I'm the child - do some cleanup */
		if (webserver) {
			close(webserver->serverSock);
			webserver = NULL;
		}
	}

	return result;
}

