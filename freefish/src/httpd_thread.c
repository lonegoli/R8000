#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "httpd.h"

#include "config.h"
#include "conf.h"
#include "common.h"
#include "debug.h"
#include "httpd_thread.h"


void
thread_httpd(void *args)
{
	//pthread_detach(pthread_self());
	void	**params;
	httpd	*webserver;
	request	*r;
	s_config *config;
	int auth_bool;
	params = (void **)args;
	webserver = *params;
	r = *(params + 1);
	config = *(params + 2);
	free(params); 
	
	if (httpdReadRequest(webserver, r, config->auth_self) == 0) {
		
		debug(LOG_DEBUG, "Processing request from %s", r->clientAddr);
		debug(LOG_DEBUG, "Calling httpdProcessRequest() for %s", r->clientAddr);
		httpdProcessRequest(webserver, r);
		debug(LOG_DEBUG, "Returned from httpdProcessRequest() for %s", r->clientAddr);
	}
	else {
		debug(LOG_DEBUG, "No valid request received from %s", r->clientAddr);
	}
	debug(LOG_DEBUG, "Closing connection with %s", r->clientAddr);
	httpdEndRequest(r);
	//pthread_exit(NULL);
}
