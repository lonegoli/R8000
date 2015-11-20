#ifndef _SQLITE_UTIL_H_
#define _SQLITE_UTIL_H_

#define DB_PATH_USER "/usr/cloud/db/user.db"
#define DB_TABLE_CLIENT "clientInfo"

void sqlite_replace_client(char *mac, char *ip, unsigned long stime, unsigned long etime, char *adver_id, int flag);
void sqlite_update_client(char *mac, unsigned long etime);
int sqlite_change_count(void);
void db_init(void);

#endif /* _SQLITE_UTIL_H_ */
