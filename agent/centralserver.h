#ifndef _CENTRALSERVER_H_
#define _CENTRALSERVER_H_

int connect_to_server(int level);

/** @brief Helper function called by connect_auth_server() to do the actual work including recursion - DO NOT CALL DIRECTLY */
int _connect_to_server(int level);

#endif /* _CENTRALSERVER_H_ */


