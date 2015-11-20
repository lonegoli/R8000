#ifndef _AUTH_H_
#define _AUTH_H_

#include "httpd.h"


typedef enum {
    AUTH_ERROR = -1, /**< An error occured during the validation process*/
    AUTH_DENIED = 0, /**< Client was denied by the auth server */
    AUTH_ALLOWED = 1, /**< Client was granted access by the auth server */
    AUTH_VALIDATION = 5, /**< A misnomer.  Client is in 15 min probation to validate his new account */
    AUTH_VALIDATION_FAILED = 6, /**< Client had X minutes to validate account by email and didn't = too late */
    AUTH_LOCKED = 254 /**< Account has been locked */
} t_authcode;


typedef struct _t_authresponse {
    t_authcode authcode; /**< Authentication code returned by the server */
} t_authresponse;



void authenticate_client(request *);


void thread_client_timeout_check(const void *arg);

#endif
