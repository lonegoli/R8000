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
#include "collection.h"

extern pthread_mutex_t hMutex;

static void collection(void);

static void get_cpuoccupy (CPU_OCCUPY *cpust);
static int cal_cpuoccupy (CPU_OCCUPY *o, CPU_OCCUPY *n);
static void get_memoccupy (MEM_OCCUPY *mem);

void 
thread_monitor_collection(void *arg)
{
	s_config *config = config_get_config();
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	time_t now;
	struct tm *timenow;
	int base = config->push_monitor_interval/60;
	time(&now);
	timenow=localtime(&now);
	debug(LOG_INFO, "Local time is %s", asctime(timenow));
	debug(LOG_INFO, "Is expected to push monitor after %d minutes", base - timenow->tm_min%base);
	timeout.tv_sec = time(NULL) + (base - timenow->tm_min%base)*60;
	timeout.tv_nsec = 0;
	pthread_mutex_lock(&cond_mutex);
	pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
	pthread_mutex_unlock(&cond_mutex);	
	
	while (1) {
		debug(LOG_INFO, "Collection start");
		//if(config->socket_status) {
			collection();
		//}
		//else {
		//	debug(LOG_INFO, "Pipe error");
		//}
		debug(LOG_INFO, "Collection end");


		time(&now);
		timenow=localtime(&now);
		timeout.tv_sec = time(NULL) + (base - timenow->tm_min%base)*60 - 3;
		timeout.tv_nsec = 0;
		pthread_mutex_lock(&cond_mutex);
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
		pthread_mutex_unlock(&cond_mutex);	
	}
}





static void
collection(void)
{
	s_config *config = config_get_config();
	char tmp_value[32];
	FILE * fh;
	float sys_load    = 0;
	cJSON *valueSetObj= cJSON_CreateObject();
	cJSON *package;
	cJSON *list;
	int sockfd = 0;
	int status = 0;
	int wifi_index = 0;
	char interface_name[INTERFACELEN];
	char ssid[SSIDLEN];
	char assoc_num[4];
	CPU_OCCUPY cpu_stat1 = {.user = 0};
    CPU_OCCUPY cpu_stat2 = {.user = 0};
    MEM_OCCUPY mem_stat = {.total = 0};
	NETWORK_FLOW nflow = {.rx_bytes[0] = 0};
	int cpu_used = 0,memory_used = 0;
	char cpu_used_str[5],memory_used_str[3];
	char request[MAX_BUF];
	char *arr_index[] = INTERFACE_INDEX;
	/*wireless_traffic*/
	
	cJSON_AddItemToObject(valueSetObj, "wireless_traffic", list = cJSON_CreateArray());
	
	//while(read_ssid(wifi_index++, ssid, sizeof(ssid)/sizeof(ssid[0]))) {
	for(wifi_index = 1; wifi_index <= INTERFACE_NUM; wifi_index++) {
		cJSON_AddItemToArray(list, package = cJSON_CreateObject());
	
		//sprintf(tmp_value, "%d", (wifi_index-1)?(49+wifi_index-1):24);
		cJSON_AddStringToObject(package,"radio_index", arr_index[wifi_index - 1]);
					
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
	
	

	/*wired_traffic*/
	cJSON_AddItemToObject(valueSetObj, "wired_traffic", package = cJSON_CreateObject());
				
	read_counter(tmp_value, "vlan2", "Rxbytes", sizeof(tmp_value)/sizeof(tmp_value[0]));
	cJSON_AddStringToObject(package,"Rxbytes", tmp_value);
				
	read_counter(tmp_value, "vlan2", "Txbytes", sizeof(tmp_value)/sizeof(tmp_value[0]));
	cJSON_AddStringToObject(package,"Txbytes", tmp_value);
				
	read_counter(tmp_value, "vlan2", "Rxpkt", sizeof(tmp_value)/sizeof(tmp_value[0]));
	cJSON_AddStringToObject(package,"Rxpkt", tmp_value);
				
	read_counter(tmp_value, "vlan2", "Txpkt", sizeof(tmp_value)/sizeof(tmp_value[0]));
	cJSON_AddStringToObject(package,"Txpkt", tmp_value);
			
	/*cpu*/
	cJSON_AddItemToObject(valueSetObj, "cpu", package = cJSON_CreateObject());
	/*
	get_memoccupy((MEM_OCCUPY *)&mem_stat);
    
    //第一次获取cpu使用情况
    get_cpuoccupy((CPU_OCCUPY *)&cpu_stat1);
    sleep(3);    
    //第二次获取cpu使用情况
    get_cpuoccupy((CPU_OCCUPY *)&cpu_stat2);  
    //计算cpu使用率
    cpu_used = cal_cpuoccupy ((CPU_OCCUPY *)&cpu_stat1, (CPU_OCCUPY *)&cpu_stat2);
	snprintf(cpu_used_str, 3 , "%d", cpu_used);
	*/
	if ((fh = fopen("/proc/loadavg", "r"))) {
		fscanf(fh, "%f", &sys_load);
		fclose(fh);
	}
	else {
		debug(LOG_ERR,"Fopen faild");
	}
	snprintf(cpu_used_str, 5 , "%f", sys_load);
	
	cJSON_AddStringToObject(package, "cpu_used", cpu_used_str);

	/*memory*/
	cJSON_AddItemToObject(valueSetObj, "memory", package = cJSON_CreateObject());
	get_memoccupy((MEM_OCCUPY *)&mem_stat);
	//debug(LOG_INFO, "%d  %d", mem_stat.free,mem_stat.total);
	memory_used = 100 - (mem_stat.free * 100)/(mem_stat.total+0.001);
	snprintf(memory_used_str, 3 , "%d", memory_used);
	cJSON_AddStringToObject(package, "memory_used", memory_used_str);

		


	create_http_json(valueSetObj, NULL, INFORM, PUSHMONITOR, NULL, NULL, NULL, config->sn, request);
	
	/*
	pthread_mutex_lock(&hMutex);
	safe_encrypt_http_send(config->httpfd, request, strlen(request), 0);
	safe_decrypt_http_read(config->httpfd, 15, request);
	pthread_mutex_unlock(&hMutex);  
	*/
	do{
		debug(LOG_INFO, "Send a PushMonitor to server: %s", request);
		sockfd = try_connect_to_server();
		if(sockfd > 0) {
			safe_encrypt_http_send(sockfd, request, strlen(request), 0);
			status = safe_decrypt_http_read(sockfd, 15, request);
			safe_close(sockfd);
		}
	}while(status == SOCKET_PIPE_BROKE);
	//cJSON_AddStringToObject(root, KEY_ERR_DESC, err_desc) : "";
	//cJSON_AddItemToObject(root, "Wired_traffic", wired_traffic);
	//cJSON_AddItemToObject(root, "Wireless_traffic", wireless_traffic);

}


static void
get_memoccupy (MEM_OCCUPY *mem) //对无类型get函数含有一个形参结构体类弄的指针O
{
    FILE *fd;          
    int n;             
    char buff[256];   
                                                                                                              
    if((fd = fopen ("/proc/meminfo", "r")) == NULL) {
		debug(LOG_ERR,"Fopen faild");
		//fclose(fd);
		return;
    }

	fgets (buff, sizeof(buff), fd); 
	fgets (buff, sizeof(buff), fd); 
	fgets (buff, sizeof(buff), fd);
	
    fgets (buff, sizeof(buff), fd);  
	debug(LOG_INFO, "%s", buff);
    sscanf (buff, "%s %u", mem->name, &mem->total); 
    
    fgets (buff, sizeof(buff), fd); //从fd文件中读取长度为buff的字符串再存到起始地址为buff这个空间里 
    debug(LOG_INFO, "%s", buff);
    sscanf (buff, "%s %u", mem->name2, &mem->free); 
    
    fclose(fd);     //关闭文件fd
}

static int 
cal_cpuoccupy (CPU_OCCUPY *o, CPU_OCCUPY *n) 
{   
    unsigned long od, nd;    
    unsigned long id, sd;
    int cpu_use = 0;   
    
    od = (unsigned long) (o->user + o->nice + o->system +o->idle);//第一次(用户+优先级+系统+空闲)的时间再赋给od
    nd = (unsigned long) (n->user + n->nice + n->system +n->idle);//第二次(用户+优先级+系统+空闲)的时间再赋给od
      
    id = (unsigned long) (n->user - o->user);    //用户第一次和第二次的时间之差再赋给id
    sd = (unsigned long) (n->system - o->system);//系统第一次和第二次的时间之差再赋给sd
    if((nd-od) != 0)
    cpu_use = (int)((sd+id)*100)/(nd-od); //((用户+系统)乖100)除(第一次和第二次的时间差)再赋给g_cpu_used
    else cpu_use = 0;
    return cpu_use;
}

static void 
get_cpuoccupy (CPU_OCCUPY *cpust) //对无类型get函数含有一个形参结构体类弄的指针O
{   
    FILE *fd;         
    int n;            
    char buff[256];                                                                                                            
    if((fd = fopen ("/proc/stat", "r")) == NULL) {
		debug(LOG_ERR,"Fopen faild");
		//fclose(fd);
		return;
    }
    fgets (buff, sizeof(buff), fd);   
    sscanf (buff, "%s %u %u %u %u", cpust->name, &cpust->user, &cpust->nice,&cpust->system, &cpust->idle);   
    fclose(fd);     
}



