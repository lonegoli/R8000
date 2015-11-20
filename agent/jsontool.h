#ifndef _JSONTOOL_H_
#define _JSONTOOL_H_

#include "cJSON.h"
//void create_Request_json(cJSON *root, const char *const ctranIdV, const char *const macV, const char *const typeV, const char *const operV,cJSON *valueSetObjV);
//void create_Response_json(cJSON *root, const char *const ctranIdV, const char *const typeV, const char *const operV, const char *const resultV, const int err_codeV,cJSON *valueSetObjV);
int create_http_json(cJSON *valueSetObj, const char *const id, const char *const type, const char *const operation, const char *const result, const char *const err_code, const char *const err_desc, const char *const sn, char *http_packet);

#endif

