#ifndef _UTIL_H_
#define _UTIL_H_



/** @brief Execute a shell command
 */
int execute(char *cmd_line, int quiet);
struct in_addr *wd_gethostbyname(const char *name);

/* @brief Get IP address of an interface */
char *get_iface_ip(const char *ifname);

/* @brief Get MAC address of an interface */
char *get_iface_mac(const char *ifname);

/* @brief Get interface name of default gateway */
char *get_ext_iface (void);

char *trim(char *String);

void trimH(char *buf);

int isAffixBy(const char* srcStr , const char* subStr);

int isBefixBy(const char* srcStr , const char* subStr);
int strpos(const char*s1,const char*s2);

void get_string_uptime(char *sys_uptime);
void substr(char *szDest, const char *szSrc, size_t nPos, size_t nLen);
int char_encrypt(char *data,int key);
int char_decrypt(char *data,int key);
int str_count(char *str, char *substr);


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


