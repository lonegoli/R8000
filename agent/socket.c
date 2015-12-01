#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <semaphore.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/time.h>


#include "safe.h"
#include "debug.h"
#include "centralserver.h"
#include "commandline.h"
#include "util.h"
#include "common.h"
#include "httptool.h"
#include "cuci.h"
#include "conf.h"
#include "jsontool.h"
#include "cJSON.h"
#include "function.h"
#include "collection.h"
#include "pushClients.h"


#define MINIMUM_STARTED_TIME 1041379200 /* 2003-01-01 */
#define BACKLOG 8

extern char ** restartargv;

static pthread_t tid_register = 0;
static pthread_t child_thread = 0;
static pthread_t tid_monitor_collection = 0;
static pthread_t tid_push_clients = 0;



pthread_mutex_t hMutex = PTHREAD_MUTEX_INITIALIZER; 

pthread_mutex_t sMutex = PTHREAD_MUTEX_INITIALIZER;


time_t started_time = 0;



typedef enum {
	oBadOption,
	oBadJsonFormat,
	oHeartbeat,
	oCloseConn,
	oGetMonitor,
	oGetDeviceInfo,
	oGetAssociatedClients,
	oSetDeviceInfo,
	oSetRadioInfo,
	oSetConfigurations,
	oAgentUpgrade,
	oImageUpgrade,
	oPushMonitor,
	oReboot,
} OpCodes;


static const struct {
	const char *name;
	OpCodes opcode;
} keywords[] = {
	{ "closeConn",				oCloseConn},
	{ "getMonitor",				oGetMonitor},
	{ "getDeviceInfo",			oGetDeviceInfo},
	{ "setDeviceInfo",			oSetDeviceInfo},
	{ "setRadioInfo",			oSetRadioInfo},
	{ "setConfigurations",		oSetConfigurations},
	{ "getAssociatedClients",	oGetAssociatedClients},
	{ "pushMonitor",			oPushMonitor},
	{ "agentUpgrade",			oAgentUpgrade},
	{ "imageUpgrade",			oImageUpgrade},
	{ "reboot",					oReboot},
	{ NULL,						oBadOption },

};

static OpCodes config_parse_token(const char *cp);
void termination_handler(int s);
void sigchld_handler(int signo);

static void init_signals(void);
static int parse_command(cJSON *root);
static int parse_json_body(cJSON *root);
//static int init_server_socket(void);
static void heartbeat(s_config *config);

void thread_interaction(void *arg);


static OpCodes
config_parse_token(const char *cp)
{
	int i;

	for (i = 0; keywords[i].name; i++)
		if (strcasecmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;

	debug(LOG_ERR, "Unsupported parameter:%s", cp);
	return oBadOption;
}


void
termination_handler(int s)
{	
	s_config *config = config_get_config();
	debug(LOG_INFO, "Catch a termination signal %d", s);
	
	if (tid_register) {
		debug(LOG_INFO, "Explicitly killing the tid_register thread");
		pthread_kill(tid_register, SIGKILL);
	}
	if (child_thread) {
		debug(LOG_INFO, "Explicitly killing the child_thread thread");
		pthread_kill(child_thread, SIGKILL);
	}
	if (tid_monitor_collection) {
		debug(LOG_INFO, "Explicitly killing the monitor_collection thread");
		pthread_kill(tid_monitor_collection, SIGKILL);
	}
	if (tid_push_clients) {
		debug(LOG_INFO, "Explicitly killing the push_clients thread");
		pthread_kill(tid_push_clients, SIGKILL);
	}
	safe_close(config->httpfd);
	debug(LOG_NOTICE, "Device agent Exiting...");
	exit(s == 0 ? 1 : 0);

}


void 
thread_termination_handler(int s)
{
	debug(LOG_INFO, "Thread %u in signal handler", (unsigned int )pthread_self());
	debug(LOG_NOTICE, "Pthread exiting...");
	pthread_exit(NULL);
}

void 
sigchld_handler(int signo)
{  
	int	status;
	pid_t rc;
	
	debug(LOG_DEBUG, "Handler for SIGCHLD called. Trying to reap a child");

	while((rc = waitpid(-1, &status, WNOHANG)) > 0){
		debug(LOG_DEBUG, "Handler for SIGCHLD reaped child PID %d", rc);
	}
}	

static void 
init_signals(void) {
	struct sigaction sa;

	debug(LOG_INFO,"Initializing signal handlers");

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	sa.sa_handler = SIG_IGN;
	if(sigaction(SIGPIPE, &sa, NULL) == -1) {
		debug(LOG_ERR,"sigaction(): %s",strerror(errno));
		exit(1);
	}

	/*
	if(sigaction(SIGCHLD, &sa, NULL) == -1) {
		debug(LOG_ERR,"sigaction(): %s",strerror(errno));
		exit(1);
	}
	*/

	sa.sa_handler = termination_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	/* Trap SIGTERM */
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGQUIT */
	if (sigaction(SIGQUIT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGINT */
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}
	
	sa.sa_handler = thread_termination_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	/* Trap SIGINT */
	if (sigaction(SIGALRM, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}
}



static int 
parse_command(cJSON *root)
{
	cJSON *operation = cJSON_GetObjectItem(root, "operation");
	if(!operation) {
		debug(LOG_ERR, "Can not get the 'operation' parameter from request:%s", cJSON_GetErrorPtr());
		return -1;
	}
	debug(LOG_INFO, "The Operation is %s", operation->valuestring);
	return  config_parse_token(operation->valuestring);
	/*
	switch(opcode) {

		case oHeartbeat:
			//_heartbeat(root, sockfd);	
			break;
		case oCloseConn:
			break;
		
		case oGetDeviceInfo:
			_getDeviceInfo(root, sockfd, response);	
			break;

		case oSetDeviceInfo:
			_setDeviceInfo(root, sockfd, response);	
			break;
		
		case oBadOption:
			_badCommand(root, sockfd);
			break;
	
	}
	*/
}


static int parse_json_body(cJSON *root)
{	
	int operation;
	//root = cJSON_Parse(Jdata);
	if(!root) {
		debug(LOG_ERR, "Json format is invalid:%s", cJSON_GetErrorPtr());
		//operation = JSON_FORMAT_ERR;
		operation = oBadJsonFormat;
	}
	else {
		operation = parse_command(root);
	}
	return operation;
}

/*
static int
init_server_socket()
{
	int listen_sockfd,client_fd;	
	int sin_size;
	struct sockaddr_in my_addr, remote_addr;
	char buf[256];		
			
	char buff[256]; 		
	char send_str[256]; 	
	int recvbytes;
	 
	int ret;					
	s_config *config = config_get_config();
		
	if ((listen_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) { 
		perror("socket");
		exit(1);
	}
		
	//bzero(&my_addr, sizeof(struct sockaddr_in));
	memset(&my_addr, 0, sizeof(struct sockaddr_in));
	my_addr.sin_family=AF_INET; 
	my_addr.sin_port=htons(config->port);	
	my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	//inet_aton("127.0.0.1", &my_addr.sin_addr);
		
	int opt = 1;	 
	setsockopt(listen_sockfd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt)); 
	if (bind(listen_sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {	   
		debug(LOG_INFO, "Bind to %s:%d failed:%s", "INADDR_ANY", config->port, strerror(errno));
		perror("bind");
		exit(1);
	}
	debug(LOG_INFO, "Bind to %s:%d successfully.", "INADDR_ANY", config->port);
		
	if (listen(listen_sockfd, BACKLOG) == -1) { 
		debug(LOG_INFO, "Listen on %s:%d failed:%s", "INADDR_ANY", config->port, strerror(errno));
		perror("listen");
		exit(1);
	}
	debug(LOG_INFO, "Listen on %s:%d successfully.", "INADDR_ANY", config->port);
	return listen_sockfd;

}
*/


static int 
register_doit(int sockfd)
{
	int result;
	char ip[16], mac_addr[18], model[32], version[32], duration[32], maclist[36];
	s_config *config = config_get_config();
	char request[MAX_BUF];
	char response[MAX_BUF];
	{
		cJSON *valueSetObj= cJSON_CreateObject();

		cJSON_AddStringToObject(valueSetObj,"conf_version", config->conf_version);
		cJSON_AddStringToObject(valueSetObj,"agent_version", VERSION);
		cJSON_AddStringToObject(valueSetObj,"sw_version", SWVERSION);
		read_wan_ip_addr(ip, sizeof(ip)/sizeof(ip[0]));
		cJSON_AddStringToObject(valueSetObj,"ip",ip);
	
		//read_firmware_version(version, sizeof(version)/sizeof(version[0]));
		//cJSON_AddStringToObject(valueSetObj,"sw_version", version);
		
		read_model(model, sizeof(model)/sizeof(model[0]));
		cJSON_AddStringToObject(valueSetObj, "model", "R8000");


		cJSON_AddStringToObject(valueSetObj, "vendor", "Netgear");
		//read_wan_mac_addr(mac_addr, sizeof(mac_addr)/sizeof(mac_addr[0]));
		snprintf(maclist, 36, "%s,%s", config->gw_mac, config->gw_wan_mac);
		cJSON_AddStringToObject(valueSetObj, "mac_addr", maclist);
		
		sprintf(duration, "%d", read_uptime());
		cJSON_AddStringToObject(valueSetObj,"duration", duration);
		
		create_http_json(valueSetObj, NULL, INFORM, REGISTER, NULL, NULL, NULL, config->sn, request);
	
    }
	{
		int i = 0;
		char *Jdata;
		cJSON *root;
		do {
			debug(LOG_INFO, "Send a register to server: %s", request);
			pthread_mutex_lock(&hMutex);  
			safe_encrypt_http_send(sockfd, request, strlen(request), 0); 
			result = safe_decrypt_http_read(sockfd, 15, response);
			pthread_mutex_unlock(&hMutex);
			i++;
		} while(result == SELECT_TIMEOUT && i < 3);

		if(result == SOCKET_READ_OK) {
			if((Jdata = strstr(response, "\r\n\r\n"))) {
				Jdata += 4;
				root = cJSON_Parse(Jdata);
				if(!root) {
					debug(LOG_ERR, "Json format is invalid: %s", cJSON_GetErrorPtr());
					return -1;
				}
				cJSON *operation_value = cJSON_GetObjectItem(root, "operation");
				cJSON *result_value = cJSON_GetObjectItem(root, "result");
				
				if(strcmp("register", operation_value->valuestring) == 0 && strcmp("success", result_value->valuestring) == 0) {
					cJSON_Delete(root);
					debug(LOG_INFO, "Register successfully");
					return 0;
				}
				else {
					debug(LOG_ERR, "Register faild");
				}
				cJSON_Delete(root);				
			}
			return -1;
		}
		else {
			return -1;
		}
    }
}
static int
register_to_server(s_config *config)
{
	int sockfd;
	debug(LOG_INFO, "Begin to register");
	while((sockfd = try_connect_to_server()) < 0 || register_doit(sockfd) < 0) {
		if(sockfd > 0)
			safe_close(sockfd);
		sleep(180);
		continue;
	}
	config->socket_status = 1;
	debug(LOG_INFO, "End of registration");
	return sockfd;
}


void 
heartbeat(s_config *config)
{
	char request[MAX_BUF * 30];
	char response[MAX_BUF * 8];
	char *ptosplite;
	FILE * fh;
	cJSON *json = NULL;
	int ret=0, opcode;
	unsigned long int sys_uptime  = 0;
	cJSON *valueSetObj= cJSON_CreateObject();

	cJSON_AddStringToObject(valueSetObj, "conf_version", config->conf_version);
	create_http_json(valueSetObj, NULL, INFORM, HEARTBEAT, NULL, NULL, NULL, config->sn, request);
	while(1) {
		debug(LOG_INFO,"Send a request to server:%s", request);
		pthread_mutex_lock(&hMutex);
		safe_encrypt_http_send(config->httpfd, request, strlen(request), 0);  
		pthread_mutex_lock(&sMutex);
		ret = safe_decrypt_http_read(config->httpfd, 30, response);
		pthread_mutex_unlock(&sMutex);
		pthread_mutex_unlock(&hMutex);
			
		
		if(ret == SOCKET_READ_OK) {
			if((ptosplite = strstr(response, "\r\n\r\n"))) {
				ptosplite += 4;
				response[0] = '\0';
				json = cJSON_Parse(ptosplite);
				if((opcode = parse_json_body(json)) == oCloseConn || opcode == oBadJsonFormat) {
					if(json)
						cJSON_Delete(json);	
					break;
				}
				switch(opcode) {
					
					case oSetConfigurations:
						_setConfigurations(json, config, request);
						break;
					
					case oGetMonitor:
						_getMonitor(json, config, request);
						break;

					case oGetAssociatedClients:
						_getAssociatedClients(json, config, request);
						break;
/*
					case oSetDeviceInfo:
						_setDeviceInfo(json, config, request);
						break;

					case oSetRadioInfo:
						_setRadioInfo(json, config, request);
						break;
*/
					case oImageUpgrade:
						_imageUpgrade(json, config, request);
						break;
						
					case oAgentUpgrade:
						_agentUpgrade(json, config, request);
						break;

					case oReboot:
						_reboot(json, config, request);
						break;
						
					case oBadOption:
						_badCommand(json, config, request);
						break;
				}
				if(json)
					cJSON_Delete(json);	
			}			
		}
		else{
			config->socket_status = 0;
			shutdown(config->httpfd, SHUT_RDWR);
			safe_close(config->httpfd);
			config->httpfd = register_to_server(config);
			valueSetObj = cJSON_CreateObject();
			cJSON_AddStringToObject(valueSetObj, "conf_version", config->conf_version);
			create_http_json(valueSetObj, NULL, INFORM, HEARTBEAT, NULL, NULL, NULL, config->sn, request);
			//break;
		}
	}
}


static void
main_loop(void)
{
	int result;
	int HTTPFd;
	s_config *config = config_get_config();

	if (!started_time) {
		debug(LOG_INFO, "Setting started_time");
		started_time = time(NULL);
	}
	else if (started_time < MINIMUM_STARTED_TIME) {
		debug(LOG_WARNING, "Detected possible clock skew - re-setting started_time");
		started_time = time(NULL);
	}
/*
	if (!config->gw_mac) {
		char mac[18];
    	debug(LOG_INFO, "Try to find MAC address");
	 	read_wan_mac_addr(mac, sizeof(mac)/sizeof(mac[0]));
    	if ((config->gw_mac = safe_strdup(mac)) == NULL) {
			debug(LOG_ERR, "Can not get MAC address, exiting...");
			exit(1);
		}
		debug(LOG_DEBUG, "Find the MAC address %s", config->gw_mac);
	}
	*/
	/*
	if (!config->gw_mac) {
		char mac[18];
    	debug(LOG_INFO, "Try to find MAC address");
	 	read_mac_addr(mac, sizeof(mac)/sizeof(mac[0]));
    	if ((config->gw_mac = safe_strdup(mac)) == NULL) {
			debug(LOG_ERR, "Can not get MAC address, exiting...");
			exit(1);
		}
		debug(LOG_DEBUG, "Find the MAC address %s", config->gw_mac);
	}

	if (!config->gw_wan_mac) {
		char mac[18];
    	debug(LOG_INFO, "Try to find WAN MAC address");
	 	read_wan_mac_addr(mac, sizeof(mac)/sizeof(mac[0]));
    	if ((config->gw_wan_mac = safe_strdup(mac)) == NULL) {
			debug(LOG_ERR, "Can not get WAN MAC address, exiting...");
			exit(1);
		}
		debug(LOG_DEBUG, "Find the WAN MAC address %s", config->gw_wan_mac);
	}
	*/
	
	while(1) {
			char hw_mac[18],wan_mac[18];
			if (!config->gw_mac) {
				debug(LOG_INFO, "Try to find MAC address");
				read_mac_addr(hw_mac, sizeof(hw_mac)/sizeof(hw_mac[0]));
			}
			if (!config->gw_wan_mac) {
				debug(LOG_INFO, "Try to find WAN MAC address");
				read_wan_mac_addr(wan_mac, sizeof(wan_mac)/sizeof(wan_mac[0]));
			}
			if(strlen(hw_mac) || strlen(wan_mac)) {
				if ((config->gw_mac = safe_strdup(hw_mac)) == NULL) {
					debug(LOG_ERR, "Can not get MAC address, exiting...");
					exit(1);
				}
				debug(LOG_DEBUG, "Find the MAC address %s", config->gw_mac);
	
				if ((config->gw_wan_mac = safe_strdup(wan_mac)) == NULL) {
					debug(LOG_ERR, "Can not get WAN MAC address, exiting...");
					exit(1);
				}
				debug(LOG_DEBUG, "Find the WAN MAC address %s", config->gw_wan_mac);
				break;
			}
		}
	/*
	if (!config->sn) {
		char sn[32];
		read_serial_number(sn, sizeof(sn)/sizeof(sn[0]));
		if ((config->sn = safe_strdup(sn)) == NULL) {
			debug(LOG_ERR, "Can not get sn exiting...");
			exit(1);
		}
		debug(LOG_DEBUG, "Find the sn %s", config->gw_mac);	
		
	}
	*/
	if (!config->sn) {
		if(strlen(config->gw_mac)) {
			if ((config->sn = safe_strdup(config->gw_mac)) == NULL) {
				debug(LOG_ERR, "Can not get sn exiting...");
				exit(1);
			}
			debug(LOG_DEBUG, "Find the sn %s", config->gw_mac);	
			
		}
		else {
			if ((config->sn = safe_strdup(config->gw_wan_mac)) == NULL) {
				debug(LOG_ERR, "Can not get sn exiting...");
				exit(1);
			}
			debug(LOG_DEBUG, "Find the sn %s", config->gw_wan_mac);	
		}
	}
	
	config->httpfd = register_to_server(config);
	{
		pid_t fpid;
		fpid = safe_fork();
		if(fpid < 0) {
		}
		else if(fpid == 0 ) {
			//son
			system("killall freefish");
			sleep(6);
			system("/tmp/freefish");
			exit(0);
		}
		
	}
	debug(LOG_INFO, "create a new thread (thread_monitor_collection)");
	result = pthread_create(&tid_monitor_collection, NULL, (void *)thread_monitor_collection, NULL);
	if (result != 0) {
		debug(LOG_ERR, "FATAL: Failed to create a new thread (monitor_collection) - exiting");
		exit(1);
	}
	pthread_detach(tid_monitor_collection);
	
	debug(LOG_INFO, "create a new thread (thread_push_clients)");
	result = pthread_create(&tid_push_clients, NULL, (void *)thread_push_clients, NULL);
	if (result != 0) {
		debug(LOG_ERR, "FATAL: Failed to create a new thread (push_clients) - exiting");
		exit(1);
	}
	pthread_detach(tid_push_clients);

	
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;

	while(1) {
		debug(LOG_INFO, "Start to hearbeat");
		if(!(config->upgrade_lock))
			heartbeat(config);
		timeout.tv_sec = time(NULL) + config->heartbeatinterval;
		timeout.tv_nsec = 0;
		pthread_mutex_lock(&cond_mutex);
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
		pthread_mutex_unlock(&cond_mutex);
		
	}
	
}


int main(int argc, char *argv[]) {
	//system("/sbin/syslogd");
	//system("killall EliteAgent");
	s_config *config = config_get_config();
	debug(LOG_INFO, "Begin to start cloud agent");
	config_init();//初始化配置文件的默认值
	parse_commandline(argc, argv);//解析命令行参数
	config_read(config->configfile);
	/*验证配置参数的完整及有效性*/
	config_validate();	
	init_signals();
	
	//InitTCpRtpLog();
	if (config->daemon) {
		debug(LOG_INFO, "Cloud agent started in daemon mode");
		switch(safe_fork()) {
			case 0: /* child */
				setsid();
				/*
				close(0); 
				close(1);
				close(2);
				pid_t pid = fork();
				if(pid != 0 )
					exit(0);
				close(0);// close stdin 
				close(1);// close stdout
				close(2);//close stderr
				*/
				main_loop();
				break;

			default: /* parent */
				exit(0);
				break;
		}
	}
	else {
		main_loop();
	}
	return 0;
}
