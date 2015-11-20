#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <sqlite3.h>
#include<sys/stat.h>

//#include "sqlite_util.h"
#include "debug.h"
#include "common.h"


void db_init(void)
{
	sqlite3 *db = NULL;
	char *zErrMsg;
	int rc;
	debug(LOG_INFO, "init database");
	unlink(DB_PATH_USER);
	rc=sqlite3_open(DB_PATH_USER, &db);
	if(rc) {
		sqlite3_close(db);
		return;
	}
	chmod(DB_PATH_USER,S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
	char *sql = "CREATE TABLE clientInfo(mac VARCHAR(18) PRIMARY KEY,ip VARCHAR(16),stime INTEGER,etime INTEGER,adID VARCHAR(32),flag INTEGER);";
	sqlite3_exec(db, sql, 0, 0, &zErrMsg);
	sqlite3_close(db);
	
}
void sqlite_replace_client(char *mac, char *ip, unsigned long stime, unsigned long etime, char *adver_id, int flag)
{
	sqlite3 *db = NULL;
	char *zErrMsg = NULL;
	char sql[MAX_BUF];
	FILE * fh;
	int rc;
	unsigned long int sys_uptime  = 0;
	if ((fh = fopen("/proc/uptime", "r"))) {
		fscanf(fh, "%lu", &sys_uptime);
		fclose(fh);
	}
	rc = sqlite3_open(DB_PATH_USER, &db);
	if(rc) {
		sqlite3_close(db);
		return;
	}
	snprintf(sql, sizeof(sql)-1,
		"REPLACE INTO \"%s\" VALUES('%s', '%s', %lu, %lu, '%s', %d);",
		DB_TABLE_CLIENT,
		mac,
		ip,
		sys_uptime,
		etime,
		adver_id,
		flag);
	debug(LOG_DEBUG, "sql[%s]",sql);
	sqlite3_exec(db, sql, 0, 0, &zErrMsg);
	sqlite3_close(db);
	
}

void sqlite_update_client(char *mac, unsigned long etime)
{
	sqlite3 *db = NULL;
	char *zErrMsg = NULL;
	char sql[MAX_BUF];
	FILE * fh;
	int rc;
	unsigned long int sys_uptime  = 0;
	if ((fh = fopen("/proc/uptime", "r"))) {
		fscanf(fh, "%lu", &sys_uptime);
		fclose(fh);
	}
	rc = sqlite3_open(DB_PATH_USER, &db);
	if(rc) {
		sqlite3_close(db);
		return;
	}
	
	snprintf(sql, sizeof(sql)-1,
		"UPDATE \"%s\" SET etime='%lu',flag='%d' where mac='%s';",
		DB_TABLE_CLIENT,
		sys_uptime,
		0,
		mac);
	debug(LOG_DEBUG, "sql[%s]",sql);
	sqlite3_exec(db, sql, 0, 0, &zErrMsg);
	sqlite3_close(db);
}


int sqlite_change_count(void)
{
	
	sqlite3 *db=NULL;
	int rc,ncols;
	char *sql="SELECT COUNT(*) FROM clientInfo where flag='0'";
	sqlite3_stmt *stmt;
	rc=sqlite3_open(DB_PATH_USER,&db);
	if(rc)
	{
		sqlite3_close(db);
		return 0;
	}
	rc = sqlite3_prepare(db,sql,strlen(sql),&stmt,0);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(db);
		return 0;
	}
	if(rc=sqlite3_step(stmt)==SQLITE_ROW)
	{
		ncols=sqlite3_column_int(stmt,0);
	}
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return ncols;
}


