#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>


#include "safe.h"
#include "conf.h"
#include "common.h"
#include "debug.h"
#include "cuci.h"
#include "cJSON.h"
#include "jsontool.h"
#include "dpopen.h"
#include "pushClients.h"

extern pthread_mutex_t hMutex;

static void push_clients(s_config *config);

void 
thread_push_clients(void *arg)
{
	s_config *config = config_get_config();
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	
	while (1) {
		/* Sleep for config.checkinterval seconds... */
		timeout.tv_sec = time(NULL) + config->push_clients_interval;
		timeout.tv_nsec = 0;

		pthread_mutex_lock(&cond_mutex);
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
		pthread_mutex_unlock(&cond_mutex);
		
		
		debug(LOG_INFO, "Push Clients start");
		if(config->socket_status) {
			push_clients(config);
		}
		else {
			debug(LOG_INFO, "Pipe error");
		}
		debug(LOG_INFO, "Push Clients end");

	}
}

static void 
push_clients(s_config *config)
{
	char request[MAX_BUF];
	char line[B_5_BUF];
	FILE *fp;
	char *p1,*p2,*s;
	int len,i;
	int sockfd = 0;
	int status = 0;
	int wifi_index = 0;
	char key[64], value[64];
	char interface_name[INTERFACELEN];
	char cmd[128];
	cJSON *valueSetObj = cJSON_CreateObject();
	cJSON *clientMacList = cJSON_CreateArray();

	
	for(wifi_index = 1; wifi_index <= INTERFACE_NUM; wifi_index++) {
		snprintf(interface_name, INTERFACELEN, "eth%d", wifi_index);
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "wl -i %s assoclist", interface_name);
		debug(LOG_INFO, "%s", cmd);
		fp = popen(cmd,"r");
		if(fp == NULL) {
			debug(LOG_ERR,"Popen faild");
		} 
		while (fgets(line, B_5_BUF, fp)) {
			s = line;
			if (s[strlen(s) - 1] == '\n')
				s[strlen(s) - 1] = '\0';
			if ((p1 = strchr(s, ' '))) {//查找字符串s中首次出现字符'    '的位置
				p1[0] = '\0';//空格替换成'\0'
			} else if ((p1 = strchr(s, '\t'))) {
				p1[0] = '\0';//tab替换成'\0'
			}
			if (p1) {
				p1++;
				len = strlen(p1);
				while (*p1 && len) {
					if (*p1 == ' ')
						p1++;
					else
						break;
					len = strlen(p1);
				}
			}
			if (p1 && p1[0] != '\0') {
				cJSON_AddStringToObject(clientMacList, "macaddress", p1);
			}
		}
		pclose(fp);
		
	}

	cJSON_AddItemToObject(valueSetObj, "macaddress", clientMacList);
	create_http_json(valueSetObj, NULL, INFORM, PUSHCLIENTS, NULL, NULL, NULL, config->sn, request);
	
	/*
	pthread_mutex_lock(&hMutex);
	safe_encrypt_http_send(config->httpfd, request, strlen(request), 0);
	safe_decrypt_http_read(config->httpfd, 15, request);
	pthread_mutex_unlock(&hMutex);  
	*/
	do{
		debug(LOG_INFO, "Push clients to server: %s", request);
		sockfd = try_connect_to_server();
		if(sockfd > 0) {
			safe_encrypt_http_send(sockfd, request, strlen(request), 0);
			status = safe_decrypt_http_read(sockfd, 15, request);
			safe_close(sockfd);
		}
	}while(status == SOCKET_PIPE_BROKE);

}



