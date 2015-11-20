#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>

#include "jsontool.h"
#include "common.h"
#include "debug.h"
#include "conf.h"
#include "httptool.h"

/*
void 
create_Request_json(cJSON *root, const char *const ctranIdV, const char *const macV, const char *const typeV, const char *const operV, cJSON *valueSetObjV)
{
	const char *const transaction_id =KEY_ID;
	const char *const mac =KEY_MAC;
	const char *const type =KEY_TYPE;
	const char *const operation =KEY_OPERATION;	
	const char *const valueSet =KEY_VALUESET;	
	cJSON_AddStringToObject(root, transaction_id,ctranIdV);
	cJSON_AddStringToObject(root, mac,macV);
	cJSON_AddStringToObject(root, type,typeV);
	cJSON_AddStringToObject(root, operation,operV);
	cJSON_AddItemToObject(root, valueSet, valueSetObjV);
	
}

void 
create_Response_json(cJSON *root, const char *const ctranIdV, const char *const typeV, const char *const operV, const char *const resultV, const char *const err_codeV ,cJSON *valueSetObjV)
{
	const char *const transaction_id =KEY_ID;
	const char *const type =KEY_TYPE;
	const char *const operation =KEY_OPERATION;	
	const char *const result =KEY_RESULT;
	const char *const err_code = KEY_ERR_CODE;
	const char *const valueSet =KEY_VALUESET;
	cJSON_AddStringToObject(root, transaction_id,ctranIdV);
	cJSON_AddStringToObject(root, type,typeV);
	cJSON_AddStringToObject(root, operation,operV);
	cJSON_AddStringToObject(root, result,resultV);
	cJSON_AddStringToObject(root, err_code,err_codeV);
	cJSON_AddItemToObject(root, valueSet, valueSetObjV);
}
*/
int 
create_http_json(cJSON *valueSetObj, const char *const id, const char *const type, const char *const operation, const char *const result, const char *const err_code, const char *const err_desc, const char *const sn, char *http_packet)
{
	cJSON *root;
	s_config *config = config_get_config();
	t_comm_serv *comm_server = NULL;
	comm_server = config->comm_servers;
	
	const char *const valueName = "valueSet";
	char id_string[64];
	//snprintf(id_string, sizeof(id_string), "%d", id);
	root = cJSON_CreateObject();
	if(!root) {
		debug(LOG_ERR, "Create json root faild.");
		return -1;
	}else debug(LOG_DEBUG, "Create json root success.");

	if(!id) {
		snprintf(id_string, sizeof(id_string), "%d", time(NULL));
	}
	//id_string ? cJSON_AddStringToObject(root, KEY_ID, id_string) : "";
	id ? cJSON_AddStringToObject(root, KEY_ID, id) : cJSON_AddStringToObject(root, KEY_ID, id_string);
	sn ? cJSON_AddStringToObject(root, KEY_MAC, sn) : "";
	type ? cJSON_AddStringToObject(root, KEY_TYPE, type) : "";
	operation ? cJSON_AddStringToObject(root, KEY_OPERATION, operation) : "";
	result ? cJSON_AddStringToObject(root, KEY_RESULT, result) : "";
	err_code ? cJSON_AddStringToObject(root, KEY_ERR_CODE, err_code) : "";
	err_desc ? cJSON_AddStringToObject(root, KEY_ERR_DESC, err_desc) : "";
	valueSetObj ? cJSON_AddItemToObject(root, KEY_VALUESET, valueSetObj) : "";
	
	char *body = cJSON_PrintUnformatted(root);
	//debug(LOG_DEBUG, "Create json[%s]", body);
	/*
	if(strcmp(type, RESPONSE) == 0) {
			snprintf(http_packet, MAX_BUF-1,
			RESPONSEHTTPHEAD,
			strlen(body),
			body);
	}
	*/
	if(strcmp(operation, PUSHMONITOR) == 0)
		snprintf(http_packet, MAX_BUF-1,
		HTTPHEAD,
		comm_server->commserv_push_moniotr_path,
		comm_server->commserv_hostname, 
		comm_server->commserv_port,
		strlen(body),
		body);

	else if(strcmp(operation, PUSHCLIENTS) == 0)
		snprintf(http_packet, MAX_BUF-1,
		HTTPHEAD,
		comm_server->commserv_push_clients_path,
		comm_server->commserv_hostname, 
		comm_server->commserv_port,
		strlen(body),
		body);
	
	else	
		snprintf(http_packet, MAX_BUF-1,
		HTTPHEAD,
		comm_server->commserv_path,
		comm_server->commserv_hostname, 
		comm_server->commserv_port,
		strlen(body),
		body);
	/*must free memory*/
	free(body);
	if(root)
    	cJSON_Delete(root);
	return 0;
	
}




