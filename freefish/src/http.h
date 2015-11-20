#ifndef _HTTP_H_
#define _HTTP_H_

#include "httpd.h"


void http_callback_404(httpd *webserver, request *r);

void http_callback_freefish(httpd *webserver, request *r);

void http_callback_about(httpd *webserver, request *r);

void http_callback_status(httpd *webserver, request *r);

void http_callback_auth(httpd *webserver, request *r);


void send_http_page(request *r, const char *title, const char* message);


void http_send_redirect(request *r, char *url, char *text);

void http_send_redirect_to_auth(request *r, char *urlFragment, char *text);
#endif /* _HTTP_H_ */
