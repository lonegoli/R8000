#ifndef _WDCTL_THREAD_H_
#define _WDCTL_THREAD_H_

#define DEFAULT_WDCTL_SOCK	"/tmp/wdctl.sock"

int wdctl_socket_server;


void thread_wdctl(void *arg);

#endif
