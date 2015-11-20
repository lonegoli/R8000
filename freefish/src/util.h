#ifndef _UTIL_H_
#define _UTIL_H_

#define STATUS_BUF_SIZ	16384


int execute(char *cmd_line, int quiet);
struct in_addr *wd_gethostbyname(const char *name);


char *get_iface_ip(const char *ifname);


char *get_iface_mac(const char *ifname);


char *get_ext_iface (void);


void mark_online();

void mark_offline();

int is_online();


void mark_auth_online();

void mark_auth_offline();

int is_auth_online();

void str_char_replace(char *src, char oldchar, char newchar);




char * get_status_text();

#define LOCK_GHBN() do { \
	debug(LOG_DEBUG, "Locking wd_gethostbyname()"); \
	pthread_mutex_lock(&ghbn_mutex); \
	debug(LOG_DEBUG, "wd_gethostbyname() locked"); \
} while (0)

#define UNLOCK_GHBN() do { \
	debug(LOG_DEBUG, "Unlocking wd_gethostbyname()"); \
	pthread_mutex_unlock(&ghbn_mutex); \
	debug(LOG_DEBUG, "wd_gethostbyname() unlocked"); \
} while (0)

#endif /* _UTIL_H_ */

