#ifndef _AGENT_UTIL_H_
#define _AGENT_UTIL_H_
#define DEFAULT_AGENT_SOCK "/tmp/pushdata.sock"

static int connect_to_agent(void);
static int read_socket(int sockfd, char *response);
void interaction_agent(void);


#endif /* _AGENT_UTIL_H_ */

