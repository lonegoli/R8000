#ifndef _CENTRALSERVER_H_
#define _CENTRALSERVER_H_

#include "auth.h"


#define REQUEST_TYPE_LOGIN     "login"

#define REQUEST_TYPE_LOGOUT    "logout"

#define REQUEST_TYPE_COUNTERS  "counters"


#define GATEWAY_MESSAGE_DENIED     "denied"

#define GATEWAY_MESSAGE_ACTIVATE_ACCOUNT     "activate"

#define GATEWAY_MESSAGE_ACCOUNT_VALIDATION_FAILED     "failed_validation"

#define GATEWAY_MESSAGE_ACCOUNT_LOGGED_OUT     "logged-out"

/***/
#define TMP_HISTORY_PATH "/tmp/history"


t_authcode auth_server_request(t_authresponse *authresponse,
			const char *request_type,
			const char *ip,
			const char *mac,
			const char *token,
			unsigned long long int incoming,
			unsigned long long int outgoing);

int connect_auth_server();


int _connect_auth_server(int level);

//int connect_backup_ip(void);
#endif /* _CENTRALSERVER_H_ */
