#ifndef _CONFIG_H_
#define _CONFIG_H_


#define NUM_EXT_INTERFACE_DETECT_RETRY 0

#define EXT_INTERFACE_DETECT_RETRY_INTERVAL 1


#define DEFAULT_CONFIGFILE "./EliteAgent.conf"


#define DEFAULT_DAEMON 1
#define DEFAULT_DEBUGLEVEL LOG_ERR
#define	DEFAULT_PUSH_MONITOR_INTERVAL 900
#define	DEFAULT_PUSH_CLIENTS_INTERVAL 120

#define DEFAULT_PORT 81
#define DEFAULT_LOG_SYSLOG 1
#define DEFAULT_SYSLOG_FACILITY LOG_DAEMON
#define DEFAULT_VENDOR "www.elitect.com"

#define DEFAULT_AUTHSERVPORT 8080
#define DEFAULT_AUTHSERVSSLPORT 443
/** Note that DEFAULT_AUTHSERVSSLAVAILABLE must be 0 or 1, even if the config file syntax is yes or no */
#define DEFAULT_AUTHSERVSSLAVAILABLE 0
/** Note:  The path must be prefixed by /, and must be suffixed /.  Put / for the server root.*/
#define DEFAULT_AUTHSERVPATH "/freefish/"

/*@}*/ 

/**
 * Information about the authentication server
 */
typedef struct _comm_serv_t {
    char *commserv_hostname;	
    int commserv_port;	
    int commserv_ssl_port;	
    int commserv_use_ssl;
	char *commserv_path;
	char *commserv_push_moniotr_path;
	char *commserv_push_clients_path;
    char *last_ip;	
    struct _comm_serv_t *next;
} t_comm_serv;



/**
 * Configuration structure
 */
typedef struct {
    char configfile[255];	
    int daemon;			
    int debuglevel;
	int trapdebuglevel;
    t_comm_serv	*comm_servers;	  
	int push_monitor_interval;
	int push_clients_interval;
	int heartbeatinterval;
    int log_syslog;
	int syslog_facility;
	char *gw_mac;
	char *gw_interface;
	char *gw_address;
	int request_timeout;
	int request_retry;
	int httpfd;
	int socket_status;
	char *sn;
	int upgrade_lock;
	char *conf_version;
} s_config;

/** @brief Get the current gateway configuration */
s_config *config_get_config(void);

/** @brief Initialise the conf system */
void config_init(void);

/** @brief Initialize the variables we override with the command line*/
void config_init_override(void);

/** @brief Reads the configuration file */
void config_read(const char *filename);

/** @brief Check that the configuration is valid */
void config_validate(void);

/** @brief Get the active auth server */
t_comm_serv *get_comm_server(void);

/** @brief Bump server to bottom of the list */
void mark_auth_server_bad(t_comm_serv *);



#define LOCK_CONFIG() do { \
	debug(LOG_DEBUG, "Locking config"); \
	pthread_mutex_lock(&config_mutex); \
	debug(LOG_DEBUG, "Config locked"); \
} while (0)

#define UNLOCK_CONFIG() do { \
	debug(LOG_DEBUG, "Unlocking config"); \
	pthread_mutex_unlock(&config_mutex); \
	debug(LOG_DEBUG, "Config unlocked"); \
} while (0)

#endif /* _CONFIG_H_ */
