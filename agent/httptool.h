#ifndef _HTTPTOOL_H_
#define _HTTPTOOL_H_

/*"Content-Type:application/x-www-form-urlencoded\r\n"	\*/

#define HTTPHEAD    "POST %s HTTP/1.1\r\n"    \
							"Host:%s:%d\r\n"                                   \
							"Content-Length:%d\r\n"                         \
							"Connection:Keep-Alive\r\n"                     \
							"\r\n"                                          \
							"%s"

#define RESPONSEHTTPHEAD    "HTTP/1.1 200 OK\r\n"    \
							"Content-Length:%d\r\n"                         \
							"Content-Type:text/plain;charset=ISO-8859-1\r\n"\
							"Connection:Keep-Alive\r\n"                     \
							"\r\n"                                          \
							"%s"


#define RESPONSXML 		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Envelope vendor=\"%s\">\n"                     \
						"<Transaction id=\"%s\" type=\"RESPONSE\" mac=\"%s\" operation=\"%s\" result=\"%s\" err_code=\"%d\">\n"     \
						"<valueSet/>\n"                                                                              \
						"</Transaction>\n"                                                                           \
						"</Envelope>"


#define INFORMXML		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"												\
						"<Envelope vendor=\"%s\">\n"																\
						"<Transaction id=\"%s\" type=\"INFORM\" mac=\"%s\" operation=\"%s\" result=\"%s\" err_code=\"%d\">\n"		\
						"<valueSet/>\n"																				\
						"</Transaction>\n"																			\
						"</Envelope>"


/*#define RESPONSEHTTPHEAD    "Host:%s\r\n"                                   \
							"Content-Length:%d\r\n"                         \
							"Connection:Keep-Alive\r\n"                     \
							"\r\n"                                          \
							"%s"

*/
int get_response_status_code(char *response);
int get_response_content_length(char *response);
#endif


