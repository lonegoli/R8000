#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <pthread.h>

#include <string.h>
#include <ctype.h>

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"


/** @internal
 * Holds the current configuration of the gateway */
static s_config config;

/**
 * Mutex for the configuration file, used by the com_servers related
 * functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @internal
 * A flag.  If set to 1, there are missing or empty mandatory parameters in the config
 */
static int missing_parms;

/** @internal
 The different configuration options */
typedef enum {
	oBadOption,
	oDaemon,
	oDebugLevel,
	oGatewayInterface,
	oGatewayAddress,
	oBindPort,
	oGatewayMac,
	oCloudServer,
	oAuthServHostname,
	oAuthServSSLAvailable,
	oAuthServSSLPort,
	oAuthServAgentPort,
	oAuthServPath,
	oAuthServPushMonitorPath,
	oAuthServPushClientsPath,
	oHTTPDMaxConn,	
	oPushMonitorInterval,
	oPushClientsInterval,
	oHeartbeatInterval,
	oSyslogFacility,
	oRequest_Timeout,
	oRequest_retry,
	oConf_version,
} OpCodes;

/** @internal
 The config file keywords for the different configuration options */
static const struct {
	const char *name;
	OpCodes opcode;
} keywords[] = {
	{ "daemon",             	oDaemon },
	{ "debug_level",         	oDebugLevel },
	{ "gateway_interface",   	oGatewayInterface },
	{ "gatewayaddress",     	oGatewayAddress },
	{ "agent_service_port",		oBindPort },
	{ "gatewaymac",        	    oGatewayMac },
	{ "cloud_server",         	oCloudServer },
	{ "httpdmaxconn",       	oHTTPDMaxConn },
	{ "push_monitor_interval",	oPushMonitorInterval},
	{ "push_clients_interval",	oPushClientsInterval},
	{ "heartbeat_interval",		oHeartbeatInterval},
	{ "syslogfacility", 		oSyslogFacility },
	{ "ip/domain",				oAuthServHostname },
	{ "sslavailable",			oAuthServSSLAvailable },
	{ "sslport",				oAuthServSSLPort },
	{ "port",					oAuthServAgentPort },
	{ "path",					oAuthServPath },
	{ "push_monitor_path",		oAuthServPushMonitorPath },
	{ "push_clients_path",		oAuthServPushClientsPath},
	{ "request_timeout",		oRequest_Timeout },
	{ "request_Retry",			oRequest_retry },
	{ "conf_version",			oConf_version },
	{ NULL,						oBadOption },
};

static void config_notnull(const void *parm, const char *parmname);
static int parse_boolean_value(char *);
static void parse_auth_server(FILE *, const char *, int *);


static OpCodes config_parse_token(const char *cp, const char *filename, int linenum);

/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
s_config *
config_get_config(void)
{
    return &config;
}

/** Sets the default config parameters and initialises the configuration system */
void
config_init(void)
{
	debug(LOG_INFO, "Setting default config parameters");
	strncpy(config.configfile, DEFAULT_CONFIGFILE, sizeof(config.configfile));//配置文件路径
	
	config.debuglevel = DEFAULT_DEBUGLEVEL;//debug等级
	config.comm_servers = NULL;//认证服务器相关数据
	config.push_monitor_interval = DEFAULT_PUSH_MONITOR_INTERVAL;
	config.push_clients_interval = DEFAULT_PUSH_CLIENTS_INTERVAL;
	config.heartbeatinterval = 5;
	//config.port = DEFAULT_PORT;
	config.syslog_facility = DEFAULT_SYSLOG_FACILITY;//指定记录消息程序的类型,与syslog相关，具体可参见openlog函数的第三个参数
	config.daemon = DEFAULT_DAEMON;//是否以deamon程序运行
	config.log_syslog = DEFAULT_LOG_SYSLOG;//是否写log 到syslog中
	config.gw_interface = "brtrunk";
	config.gw_mac = NULL;
	config.gw_wan_mac = NULL;
	config.gw_address = NULL;
	config.request_timeout = 10;
	config.request_retry = 3;
	config.trapdebuglevel = 6;
	config.socket_status = 0;
	config.sn = NULL;
	config.conf_version = "0";
	config.upgrade_lock = 0;
	
}

/**
 * If the command-line didn't provide a config, use the default.
 */
void
config_init_override(void)
{
    if (config.daemon == -1) config.daemon = DEFAULT_DAEMON;
}

/** @internal
Parses a single token from the config file
*/
static OpCodes
config_parse_token(const char *cp, const char *filename, int linenum)
{
	int i;

	for (i = 0; keywords[i].name; i++)
		if (strcasecmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;

	debug(LOG_ERR, "Parse configuration failed. Error line: %d", 
			linenum);
	return oBadOption;
}

/** @internal
Parses comm server information
*/
static void
parse_auth_server(FILE *file, const char *filename, int *linenum)
{
	char		*host = NULL,
			*path = NULL,
			*push_monitor_path = NULL,
			*push_clients_path = NULL,
			*loginscriptpathfragment = NULL,
			*portalscriptpathfragment = NULL,
			*msgscriptpathfragment = NULL,
			*pingscriptpathfragment = NULL,
			*authscriptpathfragment = NULL,
			line[MAX_BUF],
			*p1,
			*p2;
	int		port,
			ssl_port,
			ssl_available,
			opcode;
	t_comm_serv	*new,
			*tmp;

	/* Defaults */
	
	port = DEFAULT_AUTHSERVPORT;
	ssl_port = DEFAULT_AUTHSERVSSLPORT;
	ssl_available = DEFAULT_AUTHSERVSSLAVAILABLE;
	
	/* Read first line */	
	memset(line, 0, MAX_BUF);
	fgets(line, MAX_BUF - 1, file);
	(*linenum)++; /* increment line counter. */

	/* Parsing loop */
	while ((line[0] != '\0') && (strchr(line, '}') == NULL)) {
		/* skip leading blank spaces */
		for (p1 = line; isblank(*p1); p1++);

		/* End at end of line */
		if ((p2 = strchr(p1, '#')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\r')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\n')) != NULL) {
			*p2 = '\0';
		}

		/* next, we coopt the parsing of the regular config */
		if (strlen(p1) > 0) {
			p2 = p1;
			/* keep going until word boundary is found. */
			//while ((*p2 != '\0') && (!isblank(*p2)))
			while ((*p2 != '\0') && ((*p2) != '='))
				p2++;

			/* Terminate first word. */
			*p2 = '\0';
			p2++;

			/* skip all further blanks. */
			while (isblank(*p2))
				p2++;
			
			/* Get opcode */
			opcode = config_parse_token(p1, filename, *linenum);
			
			switch (opcode) {
				case oAuthServHostname:
					host = safe_strdup(p2);
					break;								
				case oAuthServSSLPort:
					ssl_port = atoi(p2);
					break;
				case oAuthServAgentPort:
					port = atoi(p2);
					break;
				case oAuthServSSLAvailable:
					ssl_available = parse_boolean_value(p2);
					if (ssl_available < 0)
						ssl_available = 0;
					break;	
				case oAuthServPath:
					path = safe_strdup(p2);
					break;
				case oAuthServPushMonitorPath:
					push_monitor_path = safe_strdup(p2);
					break;
				case oAuthServPushClientsPath:
					push_clients_path = safe_strdup(p2);
					break;
				case oBadOption:
				default:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", *linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
			}
		}

		/* Read next line */
		memset(line, 0, MAX_BUF);
		fgets(line, MAX_BUF - 1, file);
		(*linenum)++; /* increment line counter. */
	}
	

	/* only proceed if we have an host and a path */
	if (host == NULL || path == NULL)
		return;
	
	debug(LOG_DEBUG, "Adding %s:%d (SSL: %d) %s to the cloud server list",
			host, port, ssl_port, path);

	/* Allocate memory */
	new = safe_malloc(sizeof(t_comm_serv));
	
	/* Fill in struct */
	memset(new, 0, sizeof(t_comm_serv)); /*< Fill all with NULL */
	new->commserv_hostname = host;
	new->commserv_use_ssl = ssl_available;
	
	new->commserv_port = port;
	new->commserv_ssl_port = ssl_port;

	new->commserv_path = path;
	new->commserv_push_moniotr_path = push_monitor_path;
	new->commserv_push_clients_path = push_clients_path;
		
	
	/* If it's the first, add to config, else append to last server */
	if (config.comm_servers == NULL) {
		config.comm_servers = new;
	} else {
		for (tmp = config.comm_servers; tmp->next != NULL;
				tmp = tmp->next);
		tmp->next = new;
	}
	
	debug(LOG_DEBUG, "cloud server added");
}


#define TO_NEXT_WORD(s, e) do { \
	while (*s != '\0' && !isblank(*s)) { \
		s++; \
	} \
	if (*s != '\0') { \
		*s = '\0'; \
		s++; \
		while (isblank(*s)) \
			s++; \
	} else { \
		e = 1; \
	} \
} while (0)


void
config_read(const char *filename)
{
	FILE *fd;
	char line[MAX_BUF], *s, *p1, *p2;
	int linenum = 0, opcode, value, len;

	debug(LOG_INFO, "Reading configuration file '%s'", filename);

	if (!(fd = fopen(filename, "r"))) {
		debug(LOG_ERR, "Can not open configuration file '%s', "
				"exiting...", filename);
		exit(1);
	}

	while (!feof(fd) && fgets(line, MAX_BUF, fd)) {//一行一行读取解析
		linenum++;
		s = line;

		if (s[strlen(s) - 1] == '\n')
			s[strlen(s) - 1] = '\0';

		if ((p1 = strchr(s, '='))) {//查找字符串s中首次出现字符'    '的位置
			p1[0] = '\0';//空格替换成'\0'
		} else if ((p1 = strchr(s, '\t'))) {
			p1[0] = '\0';//tab替换成'\0'
		}

		if (p1) {
			p1++;

			// Trim leading spaces去除字符串(value)前多余的空格
			len = strlen(p1);
			while (*p1 && len) {
				if (*p1 == ' ')
					p1++;
				else
					break;
				len = strlen(p1);
			}


			if ((p2 = strchr(p1, ' '))) {
				p2[0] = '\0';
			} else if ((p2 = strstr(p1, "\r\n"))) {
				p2[0] = '\0';
			} else if ((p2 = strchr(p1, '\n'))) {
				p2[0] = '\0';
			}
		}

		if (p1 && p1[0] != '\0') {
			/* Strip trailing spaces */

			if ((strncmp(s, "#", 1)) != 0) {
				debug(LOG_DEBUG, "Parsing token: %s, "
						"value: %s", s, p1);
				opcode = config_parse_token(s, filename, linenum);

				switch(opcode) {
				case oDaemon:
					//if (config.daemon == -1 && ((value = parse_boolean_value(p1)) != -1)) {
					if ((value = parse_boolean_value(p1)) != -1) {
						config.daemon = value;
					}
					break;	
				case oGatewayInterface:
					config.gw_interface = safe_strdup(p1);
					break;
				case oGatewayAddress: 
					config.gw_address = safe_strdup(p1);
					break;
				case oGatewayMac:
					config.gw_mac = safe_strdup(p1);
					break;					
				case oCloudServer:
					parse_auth_server(fd, filename,&linenum);
					break;									
				case oPushMonitorInterval:
					sscanf(p1, "%d", &config.push_monitor_interval);
					break;
				case oPushClientsInterval:
					sscanf(p1, "%d", &config.push_clients_interval);
					break;
				case oHeartbeatInterval:
					sscanf(p1, "%d", &config.heartbeatinterval);
					break;
				case oSyslogFacility:
					sscanf(p1, "%d", &config.syslog_facility);
					break;
				case oRequest_Timeout:
					sscanf(p1, "%d", &config.request_timeout);
					break;
				case oRequest_retry:
					sscanf(p1, "%d", &config.request_retry);
					break;
				case oDebugLevel:
					sscanf(p1, "%d", &config.debuglevel);
					break;
				case oConf_version:
					config.conf_version = safe_strdup(p1);
					break;
				case oBadOption:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
				}
			}
		}
	}


	fclose(fd);
}

/** @internal
Parses a boolean value from the config file
*/
static int
parse_boolean_value(char *line)
{
	if (strcasecmp(line, "yes") == 0) {
		return 1;
	}
	if (strcasecmp(line, "no") == 0) {
		return 0;
	}
	if (strcmp(line, "1") == 0) {
		return 1;
	}
	if (strcmp(line, "0") == 0) {
		return 0;
	}

	return -1;
}



/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
void
config_validate(void)
{
	debug(LOG_INFO, "Begin to validate the configuration parameters");
	config_notnull(config.comm_servers, "cloud_server");
	
	if (missing_parms) {
		debug(LOG_ERR, "Some required parameters is not set, exiting...");
		exit(-1);
	}
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void
config_notnull(const void *parm, const char *parmname)
{
	if (parm == NULL) {
		debug(LOG_ERR, "The required parameter %s is not set", parmname);
		missing_parms = 1;
	}
}

/**
 * This function returns the current (first auth_server)
 */
t_comm_serv *
get_comm_server(void)
{

	/* This is as good as atomic */
	return config.comm_servers;
}

