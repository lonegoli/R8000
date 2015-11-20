#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>


#include "safe.h"
#include "util.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "dpopen.h"
#include "cuci.h"

extern char ** restartargv;


static const struct {
	const char *key;
	char *value;
} radio_keywords[] = {
	{ "24",             "1" },
	{ "50",         	"0" },
	{ "51",   			"2" },
	{ NULL,				NULL},	
};


static const struct {
	const char *key;
	char *value;
} authentication_keywords[] = {
	{ "0",             	"disabled" },
	{ "16",         	"psk" },
	{ "32",   			"psk2" },
	{ "48",     		"psk\\ psk2" },
	{ NULL,				NULL},	
};


static const struct {
	const char *key;
	char *value;
} encryption_keywords[] = {
	{ "0",             	"off" },
	{ "2",         		"tkip" },
	{ "4",   			"aes" },
	{ "6",     			"tkip+aes" },
	{ NULL,				NULL},	
};

static int parse_radio_keywords(const char *cp);
static int parse_authentication_keywords(const char *cp);
static int parse_encryption_keywords(const char *cp);
static void restart(void);



static int
parse_radio_keywords(const char *cp)
{
	int i;

	for (i = 0; radio_keywords[i].key; i++)
		if (strcasecmp(cp, radio_keywords[i].key) == 0)
			return i;

	debug(LOG_ERR, "Unsupported parameter:%s", cp);
	return i;
}


static int
parse_authentication_keywords(const char *cp)
{
	int i;

	for (i = 0; authentication_keywords[i].key; i++)
		if (strcasecmp(cp, authentication_keywords[i].key) == 0)
			return i;

	debug(LOG_ERR, "Unsupported parameter:%s", cp);
	return i;
}


static int
parse_encryption_keywords(const char *cp)
{
	int i;

	for (i = 0; encryption_keywords[i].key; i++)
		if (strcasecmp(cp, encryption_keywords[i].key) == 0)
			return i;

	debug(LOG_ERR, "Unsupported parameter:%s", cp);
	return i;
}


static void
restart(void)
{
	pid_t pid;
	char * argv[] = {"/tmp/EliteAgent", 0};	
	pid = safe_fork();
	if(pid == -1) {
		debug(LOG_CRIT, "Failed to fork: %s.  Bailing out", strerror(errno));
		debug(LOG_INFO, "EXIT 8");
		exit (1);
	}
	else if(pid > 0) {
		//stop();
		debug(LOG_INFO, "EXIT 9");
		exit(0);
	}
	else {
		//safe_close(server_socket);
		sleep(1);
		debug(LOG_NOTICE, "Re-executing myself: %s", restartargv[0]);
		setsid();
		//execvp(restartargv[0], restartargv);
		execvp("/tmp/EliteAgent",argv);
		debug(LOG_ERR, "I failed to re-execute myself: %s", strerror(errno));
		debug(LOG_ERR, "Exiting without cleanup");
		debug(LOG_INFO, "EXIT 10");
		exit(1);
	}
}


static void thread_init_service(void * args)
{
	pthread_detach(pthread_self());
	s_config *config = config_get_config();
	sleep(3);
	system("nvram commit");
	system("reboot");
	config->upgrade_lock = 0;
}



void _setConfigurations(cJSON *root, s_config *config, char *http_packet)
{
	cJSON *valueSetObj= cJSON_CreateObject();
	cJSON *attribute;
	cJSON *key;
	cJSON *item;
	int array_size;
	int i;
	char cmd[MAX_BUF];
	char result[MAX_BUF];
	char ErrMesg[B_5_BUF];
	cJSON *transaction_id = cJSON_GetObjectItem(root, "transaction_id");
	char *conf_version;
	char *radio_index;
	char *profile_index;
	char *status;
	int flag =0;
	if(!transaction_id) {
		debug(LOG_ERR, "Can not find transaction_id parameter: %s", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, NULL, RESPONSE, SETCONFIGURATIONS, "failed", "3", "Missing parameter:{transaction_id}", config->sn, http_packet);
		return;

	}
	cJSON *valueSet = cJSON_GetObjectItem(root, "valueSet");
	if(!valueSet) {
		debug(LOG_ERR, "Get valueSet faild[%s]", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETCONFIGURATIONS, "failed", "3", "Missing parameter:{valueSet}", config->sn, http_packet);
		return;
	}
	/*
	if((key = cJSON_GetObjectItem(valueSet, "conf_version")) == NULL || (conf_version = key->valuestring) == NULL) {
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETCONFIGURATIONS, "failed", "3", "Missing parameter:{conf_version}", config->sn, http_packet);
		return;
	}
	*/
	ErrMesg[0]=0;
	//setDeviceInfo//
	{
		if((attribute = cJSON_GetObjectItem(valueSet, "setDeviceInfo")) != NULL) {
			if((key = cJSON_GetObjectItem(attribute, "apname")) != NULL && key->valuestring != NULL) {
					/*snprintf(cmd, MAX_BUF, "config apname %s\n", key->valuestring);
					if(set_config(cmd, result)) 
						strcpy(ErrMesg, result);
					*/
					set_apname(key->valuestring, result, sizeof(result)/sizeof(result[0]));
				}
		}
	}
	//setRadioInfo//
	{
		if((attribute = cJSON_GetObjectItem(valueSet, "setRadioInfo")) != NULL) {
			array_size = cJSON_GetArraySize(attribute);
			debug(LOG_DEBUG, "Array size of paras is %d",array_size);
 			for(i=0; i< array_size; i++) {
				item = cJSON_GetArrayItem(attribute, i);
				//debug(LOG_DEBUG, "%s\n",item->valuestring);
				if((key = cJSON_GetObjectItem(item, "radio_index")) == NULL || (radio_index = radio_keywords[parse_radio_keywords(key->valuestring)].value) == NULL) {
					create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETCONFIGURATIONS, "failed", "3", "Missing parameter:{radio_index}", config->sn, http_packet);
					return;
				}
				/*
				if((key = cJSON_GetObjectItem(item, "radio")) != NULL && key->valuestring != NULL) {
					snprintf(cmd, MAX_BUF, "config interface wlan %s radio %s\n", cJSON_GetObjectItem(item, "radio_index")->valuestring, key->valuestring);
					if(set_config(cmd, result)) 
						strcpy(ErrMesg, result);
					//debug(LOG_INFO, "result is %d", strlen(result));
				}
				*/
				if((key = cJSON_GetObjectItem(item, "mode")) != NULL && key->valuestring != NULL) {
					/*snprintf(cmd, MAX_BUF, "config interface wlan %s mode %s\n", cJSON_GetObjectItem(item, "radio_index")->valuestring, key->valuestring);
					if(set_config(cmd, result)) 
						strcpy(ErrMesg, result);
					*/
			
					set_mode(atoi(radio_index), key->valuestring, result, sizeof(result)/sizeof(result[0]));
					strcpy(ErrMesg, result);
				}
				
				if((key = cJSON_GetObjectItem(item, "power")) != NULL && key->valuestring != NULL) {
					/*
					snprintf(cmd, MAX_BUF, "config interface wlan %s power %s\n", cJSON_GetObjectItem(item, "radio_index")->valuestring, key->valuestring);
					if(set_config(cmd, result)) 
						strcpy(ErrMesg, result);
					*/
					set_power(atoi(radio_index), key->valuestring, result, sizeof(result)/sizeof(result[0]));
					strcpy(ErrMesg, result);
				}
				
				if((key = cJSON_GetObjectItem(item, "channel")) != NULL && key->valuestring != NULL) {
					/*
					snprintf(cmd, MAX_BUF, "config interface wlan %s channel %s\n", cJSON_GetObjectItem(item, "radio_index")->valuestring, key->valuestring);
					if(set_config(cmd, result)) 
						strcpy(ErrMesg, result);
					*/
					set_channel(atoi(radio_index), key->valuestring, result, sizeof(result)/sizeof(result[0]));
					strcpy(ErrMesg, result);
				}
				if((key = cJSON_GetObjectItem(item, "channelwidth")) != NULL && key->valuestring != NULL) {
					/*
					snprintf(cmd, MAX_BUF, "config interface wlan %s channelwidth %s\n", cJSON_GetObjectItem(item, "radio_index")->valuestring, key->valuestring);
					if(set_config(cmd, result)) 
						strcpy(ErrMesg, result);
					*/
					set_channelwidth(atoi(radio_index), key->valuestring, result, sizeof(result)/sizeof(result[0]));
					strcpy(ErrMesg, result);
	
				}
				if((key = cJSON_GetObjectItem(item, "max-wireless-clients")) != NULL && key->valuestring != NULL) {
					/*
					snprintf(cmd, MAX_BUF, "config interface wlan %s max-wireless-clients %s\n", cJSON_GetObjectItem(item, "radio_index")->valuestring, key->valuestring);
					if(set_config(cmd, result)) 
						strcpy(ErrMesg, result);
					*/
					set_max_assoc(atoi(radio_index), key->valuestring, result, sizeof(result)/sizeof(result[0]));
					strcpy(ErrMesg, result);
				}
				
				if((key = cJSON_GetObjectItem(item, "client-isolation")) != NULL && key->valuestring != NULL) {
					/*
					snprintf(cmd, MAX_BUF, "config interface wlan %s client-isolation %s\n", cJSON_GetObjectItem(item, "radio_index")->valuestring, key->valuestring);
					
					if(set_config(cmd, result)) 
						strcpy(ErrMesg, result);
					*/
					set_ap_isolate(atoi(radio_index), key->valuestring, result, sizeof(result)/sizeof(result[0]));
					strcpy(ErrMesg, result);
					
				}
				/*
				if((key = cJSON_GetObjectItem(item, "rate")) != NULL && key->valuestring != NULL) {
					snprintf(cmd, MAX_BUF, "config interface wlan %s rate %s\n", cJSON_GetObjectItem(item, "radio_index")->valuestring, key->valuestring);
					
					if(set_config(cmd, result)) 
						strcpy(ErrMesg, result);
				}	
				*/
 			}
		}
	}
	//setSSIDInfo//
	{
		if((attribute = cJSON_GetObjectItem(valueSet, "setSSIDInfo")) != NULL) {
			array_size = cJSON_GetArraySize(attribute);
			debug(LOG_DEBUG, "Array size of paras is %d",array_size);
 			for(i=0; i< array_size; i++) {
				item = cJSON_GetArrayItem(attribute, i);
				if((key = cJSON_GetObjectItem(item, "radio_index")) == NULL || (radio_index = radio_keywords[parse_radio_keywords(key->valuestring)].value) == NULL) {
					create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETCONFIGURATIONS, "failed", "3", "Missing parameter:{radio_index}", config->sn, http_packet);
					return;
				}
				if((key = cJSON_GetObjectItem(item, "profile_index")) == NULL || (profile_index = key->valuestring) == NULL) {
					create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETCONFIGURATIONS, "failed", "3", "Missing parameter:{profile_index}", config->sn, http_packet);
					return;
				}
				if((key = cJSON_GetObjectItem(item, "status")) == NULL || (status = key->valuestring) == NULL) {
					create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETCONFIGURATIONS, "failed", "3", "Missing parameter:{status}", config->sn, http_packet);
					return;
				}
				if(atoi(profile_index)>0) {
					char vifs[128];
					char viname[32];
					sprintf(viname, "wl%d.%d", atoi(radio_index), atoi(profile_index));
					read_vifs(atoi(radio_index), vifs, sizeof(vifs)/sizeof(vifs[0]));
	
					if(strstr(vifs, viname) && atoi(status)==0) {
						del_virtual_interface(atoi(radio_index), atoi(profile_index));
					}
					else if(!strstr(vifs, viname) && atoi(status)==1) {
						add_virtual_interface(atoi(radio_index), atoi(profile_index));
					}
					else if((!strstr(vifs, viname) && atoi(status)==0) || atoi(profile_index)>3) {
						continue;
					}
					
				}
				if((key = cJSON_GetObjectItem(item, "hide-network-name")) != NULL && key->valuestring != NULL) {
					set_status(atoi(radio_index), atoi(profile_index), key->valuestring, result, sizeof(result)/sizeof(result[0]));
					strcpy(ErrMesg, result);	
				}
				if((key = cJSON_GetObjectItem(item, "ssid")) != NULL && key->valuestring != NULL) {
					set_ssid(atoi(radio_index), atoi(profile_index), key->valuestring, result, sizeof(result)/sizeof(result[0]));
					strcpy(ErrMesg, result);
						
				}
				if((key = cJSON_GetObjectItem(item, "authentication")) != NULL && key->valuestring != NULL) {
					
					set_security_mode(atoi(radio_index), atoi(profile_index), authentication_keywords[parse_authentication_keywords(key->valuestring)].value, result, sizeof(result)/sizeof(result[0]));
					strcpy(ErrMesg, result);
				}
				
				if((key = cJSON_GetObjectItem(item, "encryption")) != NULL && key->valuestring != NULL) {
					set_crypto(atoi(radio_index), atoi(profile_index), encryption_keywords[parse_encryption_keywords(key->valuestring)].value, result, sizeof(result)/sizeof(result[0]));
					strcpy(ErrMesg, result);
				}

				if((key = cJSON_GetObjectItem(item, "presharedkey")) != NULL && key->valuestring != NULL) {
					set_wpa_psk(atoi(radio_index), atoi(profile_index), key->valuestring, result, sizeof(result)/sizeof(result[0]));
					strcpy(ErrMesg, result);
				}
				flag =1;
 			}
			
		}
		
 	}
 	{
 		//apply_setting();
 		/*
 		int result;
		pthread_t tid_init_service = 0;
		config->upgrade_lock = 1;
 		debug(LOG_INFO, "create a new thread (thread_init_service)");
		result = pthread_create(&tid_init_service, NULL, (void *)thread_init_service, NULL);
		if (result != 0) {
			debug(LOG_ERR, "FATAL: Failed to create a new thread (init_service) - exiting");
			exit(1);
		}*/
		system("nvram commit");
		
 	}
 
	if(strlen(ErrMesg)) {
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETCONFIGURATIONS, "failed", "1000", ErrMesg, config->sn, http_packet);
	}
	else {
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETCONFIGURATIONS, "success", "0", NULL, config->sn, http_packet);
	}
	if(flag) {
		safe_encrypt_http_send(config->httpfd, http_packet, strlen(http_packet), 0); 
		shutdown(config->httpfd, SHUT_RDWR);
		system("reboot");
	}
		
			
}


void _getMonitor(cJSON *root, s_config *config, char *http_packet)
{
	char tmp_value[32];
	int flag = 0;
	cJSON *valueSetObj= cJSON_CreateObject();
	cJSON *package;
	cJSON *list;
	cJSON *transaction_id = cJSON_GetObjectItem(root, "transaction_id");
	if(!transaction_id) {
		debug(LOG_ERR, "Can not find transaction_id parameter: %s", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, 0, RESPONSE, GETMONITOR, "failed", "3", "Missing parameter:{transaction_id}", config->sn, http_packet);
		return;

	}

	cJSON *valueSet = cJSON_GetObjectItem(root, "valueSet");
	if(!valueSet) {
		debug(LOG_ERR, "Can not find valueset parameter: %s", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, GETMONITOR, "failed", "3", "Missing parameter:{valueSet}", config->sn, http_packet);
		return;
	}

	cJSON *monitors = cJSON_GetObjectItem(valueSet, "monitors");
	if(!monitors) {
		debug(LOG_ERR, "Can not find monitor parameter: %s", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, GETMONITOR, "failed", "3", "Missing parameter:{monitors}", config->sn, http_packet);
		return;
	}
	

 	int array_size = cJSON_GetArraySize(monitors);
	debug(LOG_DEBUG, "Array size of monitor is %d",array_size);
 	int i = 0;
 	cJSON *item;
 	for(i=0; i< array_size; i++) {
    	item = cJSON_GetArrayItem(monitors, i);
     	debug(LOG_DEBUG, "%s\n",item->valuestring);
		if(strcmp(item->valuestring , "wireless_traffic") == 0) {
			flag = 1;
			int wifi_index = 0;
			char interface_name[INTERFACELEN];
			char ssid[SSIDLEN];
			char assoc_num[4];
			cJSON_AddItemToObject(valueSetObj, "wireless_traffic", list = cJSON_CreateArray());
			while(read_ssid(wifi_index++, ssid, sizeof(ssid)/sizeof(ssid[0]))) {
				cJSON_AddItemToArray(list, package = cJSON_CreateObject());

				sprintf(tmp_value, "%d", wifi_index-1);
				cJSON_AddStringToObject(package,"radio_index",tmp_value);
				
				snprintf(interface_name, INTERFACELEN, "eth%d", wifi_index);
				
				read_counter(tmp_value, interface_name, "Rxbytes", sizeof(tmp_value)/sizeof(tmp_value[0]));
				cJSON_AddStringToObject(package,"Rxbytes", tmp_value);
			
				read_counter(tmp_value, interface_name, "Txbytes", sizeof(tmp_value)/sizeof(tmp_value[0]));
				cJSON_AddStringToObject(package,"Txbytes", tmp_value);
			
				read_counter(tmp_value, interface_name, "Rxpkt", sizeof(tmp_value)/sizeof(tmp_value[0]));
				cJSON_AddStringToObject(package,"Rxpkt", tmp_value);
			
				read_counter(tmp_value, interface_name, "Txpkt", sizeof(tmp_value)/sizeof(tmp_value[0]));
				cJSON_AddStringToObject(package,"Txpkt", tmp_value);

				read_assoc_client_count(interface_name, assoc_num, sizeof(assoc_num)/sizeof(assoc_num[0]));
				cJSON_AddStringToObject(package,"NumberOfAssociatedClients", assoc_num);

				
			}
		}
		else if(strcmp(item->valuestring , "wired_traffic") == 0) {
			flag = 1;
			cJSON_AddItemToObject(valueSetObj, "wired_traffic", package = cJSON_CreateObject());
			
			read_counter(tmp_value, "vlan2", "Rxbytes", sizeof(tmp_value)/sizeof(tmp_value[0]));
			cJSON_AddStringToObject(package,"Rxbytes", tmp_value);
			
			read_counter(tmp_value, "vlan2", "Txbytes", sizeof(tmp_value)/sizeof(tmp_value[0]));
			cJSON_AddStringToObject(package,"Txbytes", tmp_value);
			
			read_counter(tmp_value, "vlan2", "Rxpkt", sizeof(tmp_value)/sizeof(tmp_value[0]));
			cJSON_AddStringToObject(package,"Rxpkt", tmp_value);
			
			read_counter(tmp_value, "vlan2", "Txpkt", sizeof(tmp_value)/sizeof(tmp_value[0]));
			cJSON_AddStringToObject(package,"Txpkt", tmp_value);
			/*
			read_counter(tmp_value, "vlan2", "rx_errors", sizeof(tmp_value)/sizeof(tmp_value[0]));
			cJSON_AddStringToObject(package,"rx_errors", tmp_value);

			read_counter(tmp_value, "vlan2", "tx_errors", sizeof(tmp_value)/sizeof(tmp_value[0]));
			cJSON_AddStringToObject(package,"tx_errors", tmp_value);

			read_counter(tmp_value, "vlan2", "rx_discards", sizeof(tmp_value)/sizeof(tmp_value[0]));
			cJSON_AddStringToObject(package,"rx_discards", tmp_value);

			read_counter(tmp_value, "vlan2", "tx_discards", sizeof(tmp_value)/sizeof(tmp_value[0]));
			cJSON_AddStringToObject(package,"tx_discards", tmp_value);
			*/
		}
 	}
	flag?create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, GETMONITOR, "success", "0", NULL, NULL, http_packet):create_http_json(valueSetObj, atoi(transaction_id->valuestring), RESPONSE, GETMONITOR, "failed", "4", "Unsupported value", config->sn, http_packet);
  
}


void 
_getAssociatedClients(cJSON *root, s_config *config, char *http_packet)
{
	//char *result[MAX_BUF*30];
	int wifi_index = 0;
	char interface_name[INTERFACELEN];
	char ssid[SSIDLEN];
	char channel[4],rssi[4];
	char line[B_5_BUF];
	char cmd[128];
	FILE *fp;
	char *p1,*p2,*s;
	int len,i;
	char key[64], value[64];
	char *arr_index[] = INTERFACE_INDEX;
	//char *point;
	cJSON *valueSetObj= cJSON_CreateArray();
	cJSON *list;
	cJSON *transaction_id = cJSON_GetObjectItem(root, "transaction_id");
	if(!transaction_id) {
		debug(LOG_ERR, "Can not find transaction_id parameter: %s", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, NULL, RESPONSE, GETASSOCIATEDCLIENTS, "failed", "3", "Missing parameter:{transaction_id}", config->sn, http_packet);
		return;

	}

	//while(read_ssid(wifi_index++, ssid, sizeof(ssid)/sizeof(ssid[0]))) {
	for(wifi_index = 1; wifi_index <= INTERFACE_NUM; wifi_index++) {
		/*snprintf(interface_name, INTERFACELEN, "eth%d", wifi_index);
		read_assoc_client_list(char *interface_name, assoclist,  sizeof(assoclist)/sizeof(assoclist[0]));
		//point = assoclist;
		
		for(assoclist = strchr(assoclist, '\n')){
			cJSON_AddItemToArray(valueSetObj, list = cJSON_CreateObject());
			cJSON_AddStringToObject(list, "radio_index", interface_name);
			cJSON_AddStringToObject(list, "macaddress", assoclist);
		}
		*/
		snprintf(interface_name, INTERFACELEN, "eth%d", wifi_index);
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "wl -i %s assoclist", interface_name);
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
				cJSON_AddItemToArray(valueSetObj, list = cJSON_CreateObject());
				
				//sprintf(value, "%d", wifi_index-1);
				cJSON_AddStringToObject(list, "radio_index", arr_index[wifi_index - 1]);
				cJSON_AddStringToObject(list, "macaddress", p1);

				read_channel(interface_name, channel, sizeof(channel)/sizeof(channel[0]));
				cJSON_AddStringToObject(list, "channel", channel);

				read_assoc_rssi(interface_name, p1, rssi, sizeof(rssi)/sizeof(rssi[0]));
				cJSON_AddStringToObject(list, "rssi", rssi);
			}
		}
		pclose(fp);
		
	}
	
	create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, GETASSOCIATEDCLIENTS, "success", "0", NULL, config->sn, http_packet);

}

/*
void 
_setDeviceInfo(cJSON *root, s_config *config, char *http_packet)
{

	cJSON *valueSetObj= cJSON_CreateObject();
	cJSON *transaction_id = cJSON_GetObjectItem(root, "transaction_id");

	if(!transaction_id) {
		debug(LOG_ERR, "Can not find transaction_id parameter: %s", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, NULL, RESPONSE, SETDEVICEINFO, "failed", "3", "Missing parameter:{transaction_id}", config->sn, http_packet);
		return;

	}
	cJSON *valueSet = cJSON_GetObjectItem(root, "valueSet");
	if(!valueSet) {
		debug(LOG_ERR, "Get valueSet faild[%s]", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETDEVICEINFO, "failed", "3", "Missing parameter:{valueSet}", config->sn, http_packet);
		return;
	}
	if(cJSON_GetObjectItem(valueSet, "apname") != NULL && (cJSON_GetObjectItem(valueSet, "apname")->valuestring)) {
		
		set_apname(cJSON_GetObjectItem(valueSet, "apname")->valuestring);
	}
	else {
		debug(LOG_ERR, "Get apname faild[%s]", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETDEVICEINFO, "failed", "3", "Missing parameter:{apname}", NULL, http_packet);
		return;
	}
	create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETDEVICEINFO, "success", "0", NULL, config->sn, http_packet);
}


void
_setRadioInfo(cJSON *root, s_config *config, char *http_packet)
{
	cJSON *valueSetObj= cJSON_CreateObject();
	cJSON *transaction_id = cJSON_GetObjectItem(root, "transaction_id");

	if(!transaction_id) {
		debug(LOG_ERR, "Can not find transaction_id parameter: %s", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, NULL, RESPONSE, SETRADIOINFO, "failed", "3", "Missing parameter:{transaction_id}", config->sn, http_packet);
		return;

	}
	cJSON *valueSet = cJSON_GetObjectItem(root, "valueSet");
	if(!valueSet) {
		debug(LOG_ERR, "Get valueSet faild[%s]", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETRADIOINFO, "failed", "3", "Missing parameter:{valueSet}", config->sn, http_packet);
		return;
	}
	if(cJSON_GetObjectItem(valueSet, "radio_index") != NULL && (cJSON_GetObjectItem(valueSet, "radio_index")->valuestring)) {
		
		if(cJSON_GetObjectItem(valueSet, "radio_index") != NULL && (cJSON_GetObjectItem(valueSet, "radio_index")->valuestring)) {
		
		
	}
	}
	else {
		debug(LOG_ERR, "Get apname faild[%s]", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, SETRADIOINFO, "failed", "3", "Missing parameter:{radio_index}", NULL, http_packet);
		return;
	}
}

*/


static void thread_agentUpgrade(void * args)
{
	pthread_detach(pthread_self());
	cJSON *valueSetObj= cJSON_CreateObject();
	struct upgradeArg *Pargs;
	s_config *config = config_get_config();
	int flag = 0;
	char file_name[1024], md5[64], id[32], exec[128], request[MAX_BUF];
	Pargs = (struct upgradeArg *)args;

	strcpy(file_name, Pargs->file_name);
	strcpy(md5, Pargs->md5);
	strcpy(id, Pargs->id);
	sleep(2);
	safe_free(Pargs);

	signal(SIGCHLD,SIG_DFL);
	do {
		system("mkdir /tmp/download");
		system("rm -rf /tmp/download/EliteAgent");
		if(download_file(file_name, DOWNAGENTDIR)) {
			debug(LOG_ERR,"Download file failed.");
			create_http_json(valueSetObj, id, INFORM, AGENTUPGRADESTATUS, "failed", "6", "Failed to download agent file", config->gw_mac, request);
			break;
		}
		system("chmod 777 " DOWNAGENTDIR);
		if(check_md5(DOWNAGENTDIR, md5)) {
			debug(LOG_ERR,"MD5 check failed.");
			create_http_json(valueSetObj, id, INFORM, AGENTUPGRADESTATUS, "failed", "8", "MD5 check failed", config->gw_mac, request);
			break;
		}
		system("rm -rf /tmp/EliteAgent");
		system("cp /tmp/download/EliteAgent /tmp");
		
		debug(LOG_INFO, "Upgrade EliteAgent successfully");
		flag = 1;
		create_http_json(valueSetObj, id, INFORM, AGENTUPGRADESTATUS, "success", "0", NULL, config->gw_mac, request);
		
	}while(0);

	{
		int sockfd;
		ssize_t totalbytes;
		//debug(LOG_INFO, "Begin to build the connection with the server and then send trap");
		sockfd = try_connect_to_server();
		if(sockfd == -1) {
			return;
		}
		debug(LOG_INFO, "Send agentUpgrade info: %s", request);
		totalbytes = safe_encrypt_http_send(sockfd,request,strlen(request),0);
		debug(LOG_DEBUG, "Send %d bytes",totalbytes);
		safe_decrypt_http_read(sockfd, 3,  request);
		//debug(LOG_DEBUG, "Push real time trap end");
		shutdown(sockfd, 2);
		safe_close(sockfd);
		if(flag) {
			//debug(LOG_INFO, "System reboot...");
			//system("reboot");
			debug(LOG_INFO, "EliteAgent restart...");
			restart();
		}
		config->upgrade_lock = 0;
	}
}



void 
_agentUpgrade(cJSON *root, s_config *config, char *http_packet)
{
	int result;
	pthread_t tid_agent = 0;
	cJSON *valueSetObj= cJSON_CreateObject();
	struct upgradeArg *ua = safe_malloc(sizeof(struct upgradeArg));
	memset(ua, 0, sizeof(struct upgradeArg));
	cJSON *transaction_id = cJSON_GetObjectItem(root, "transaction_id");
	if(!transaction_id) {
		debug(LOG_ERR, "Get transaction_id faild[%s]", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, "0", RESPONSE, AGENTUPGRADE, "failed", "3", "Missing parameter:{transaction_id}", NULL, http_packet);
		return;
	
	}		
	cJSON *valueSet = cJSON_GetObjectItem(root, "valueSet");
	if(!valueSet) {
		debug(LOG_ERR, "Get valueSet faild[%s]", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, AGENTUPGRADE, "failed", "3", "Missing parameter:{valueSet}", NULL, http_packet);
		return;
	}

	if(cJSON_GetObjectItem(valueSet, "file_name") == NULL || cJSON_GetObjectItem(valueSet, "md5") == NULL || !(cJSON_GetObjectItem(valueSet, "file_name")->valuestring) || !(cJSON_GetObjectItem(valueSet, "md5")->valuestring)) {
		debug(LOG_ERR, "Get file_name or md5 faild[%s]", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, AGENTUPGRADE, "failed", "4", "Unsupported value", NULL, http_packet);
		return;
	}

	strcpy(ua->file_name, cJSON_GetObjectItem(valueSet, "file_name")->valuestring);
	strcpy(ua->md5, cJSON_GetObjectItem(valueSet, "md5")->valuestring);
	strcpy(ua->id, transaction_id->valuestring);
	config->upgrade_lock = 1;
	result = pthread_create(&tid_agent, NULL, (void *)thread_agentUpgrade, (void *)ua);
	if (result != 0) {
		debug(LOG_ERR, "FATAL: Failed to create a new thread (thread_agentUpgrade");
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, AGENTUPGRADE, "failed", "4", "Unsupported value", NULL, http_packet);
		return;
	}
	
	create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, AGENTUPGRADE, "success", "0", NULL, NULL, http_packet);

}


static void thread_imageUpgrade(void * args)
{
	pthread_detach(pthread_self());
	cJSON *valueSetObj= cJSON_CreateObject();
	struct upgradeArg *Pargs;
	s_config *config = config_get_config();
	int flag = 0;
	char file_name[1024], md5[64], id[32], exec[128], request[MAX_BUF];
	Pargs = (struct upgradeArg *)args;

	strcpy(file_name, Pargs->file_name);
	strcpy(md5, Pargs->md5);
	strcpy(id, Pargs->id);
	sleep(2);
	safe_free(Pargs);

	signal(SIGCHLD,SIG_DFL);
	do {
		//system("mkdir /tmp/download");
		//system("rm -rf /tmp/download/EliteAgent");
		if(download_file(file_name, DOWNIMAGEDIR)) {
			debug(LOG_ERR,"Download file failed.");
			create_http_json(valueSetObj, id, INFORM, IMAGEUPGRADESTATUS, "failed", "6", "Failed to download agent file", config->gw_mac, request);
			break;
		}
		system("chmod 777 " DOWNIMAGEDIR);
		if(check_md5(DOWNIMAGEDIR, md5)) {
			debug(LOG_ERR,"MD5 check failed.");
			create_http_json(valueSetObj, id, INFORM, IMAGEUPGRADESTATUS, "failed", "8", "MD5 check failed", config->gw_mac, request);
			break;
		}
		flag = 1;
		create_http_json(valueSetObj, id, INFORM, IMAGEUPGRADESTATUS, "success", "0", NULL, config->gw_mac, request);
	}while(0);
	
	{
		int sockfd;
		ssize_t totalbytes;
		//debug(LOG_INFO, "Begin to build the connection with the server and then send trap");
		sockfd = try_connect_to_server();
		if(sockfd == -1) {
			return;
		}
		debug(LOG_INFO, "Send imageUpgrade info: %s", request);
		totalbytes = safe_encrypt_http_send(sockfd,request,strlen(request),0);
		debug(LOG_DEBUG, "Send %d bytes",totalbytes);
		safe_decrypt_http_read(sockfd, 3,  request);
		//debug(LOG_DEBUG, "Push real time trap end");
		shutdown(sockfd, 2);
		safe_close(sockfd);
		if(flag) {
			
			debug(LOG_INFO, "Upgrade image...");
			system("write "DOWNIMAGEDIR" linux");
			system("reboot");
		}
		system("rm -rf "DOWNIMAGEDIR);
	}
	
	config->upgrade_lock = 0;
	
}


void
_imageUpgrade(cJSON *root, s_config *config, char *http_packet)
{
	int result;
	pthread_t tid_image = 0;
	cJSON *valueSetObj= cJSON_CreateObject();
	struct upgradeArg *ua = safe_malloc(sizeof(struct upgradeArg));
	memset(ua, 0, sizeof(struct upgradeArg));
	cJSON *transaction_id = cJSON_GetObjectItem(root, "transaction_id");
	if(!transaction_id) {
		debug(LOG_ERR, "Get transaction_id faild[%s]", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, "0", RESPONSE, IMAGEUPGRADE, "failed", "3", "Missing parameter:{transaction_id}", NULL, http_packet);
		return;
	
	}		
	cJSON *valueSet = cJSON_GetObjectItem(root, "valueSet");
	if(!valueSet) {
		debug(LOG_ERR, "Get valueSet faild[%s]", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, IMAGEUPGRADE, "failed", "3", "Missing parameter:{valueSet}", NULL, http_packet);
		return;
	}

	if(cJSON_GetObjectItem(valueSet, "file_name") == NULL || cJSON_GetObjectItem(valueSet, "md5") == NULL || !(cJSON_GetObjectItem(valueSet, "file_name")->valuestring) || !(cJSON_GetObjectItem(valueSet, "md5")->valuestring)) {
		debug(LOG_ERR, "Get file_name or md5 faild[%s]", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, IMAGEUPGRADE, "failed", "4", "Unsupported value", NULL, http_packet);
		return;
	}

	strcpy(ua->file_name, cJSON_GetObjectItem(valueSet, "file_name")->valuestring);
	strcpy(ua->md5, cJSON_GetObjectItem(valueSet, "md5")->valuestring);
	strcpy(ua->id, transaction_id->valuestring);
	config->upgrade_lock = 1;
	result = pthread_create(&tid_image, NULL, (void *)thread_imageUpgrade, (void *)ua);
	if (result != 0) {
		debug(LOG_ERR, "FATAL: Failed to create a new thread (thread_imageUpgrade");
		create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, IMAGEUPGRADE, "failed", "4", "Unsupported value", NULL, http_packet);
		return;
	}
	
	create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, IMAGEUPGRADE, "success", "0", NULL, NULL, http_packet);
}



void 
_badCommand(cJSON *root, s_config *config, char *http_packet)
{
	cJSON *valueSetObj= cJSON_CreateObject();
	cJSON *transaction_id = cJSON_GetObjectItem(root, "transaction_id");
	debug(LOG_DEBUG, "Invalid operation");
	
	if(!transaction_id) {
		debug(LOG_ERR, "Can not find transaction_id parameter: %s", cJSON_GetErrorPtr());
		create_http_json(valueSetObj, NULL, RESPONSE, "unknow", "failed", "3", "Missing parameter:{transaction_id}", config->sn, http_packet);
		return;

	}
	create_http_json(valueSetObj, transaction_id->valuestring, RESPONSE, "unknow", "failed", "3", "Missing parameter:{operation}", config->sn, http_packet);
}


