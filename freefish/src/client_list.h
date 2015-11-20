#ifndef _CLIENT_LIST_H_
#define _CLIENT_LIST_H_


typedef struct _t_counters {
    unsigned long long	incoming;	/**< @brief Incoming data total*/
    unsigned long long	outgoing;	/**< @brief Outgoing data total*/
    unsigned long long	incoming_history;	/**< @brief Incoming data before freefish restarted*/
    unsigned long long	outgoing_history;	/**< @brief Outgoing data before freefish restarted*/
    time_t	last_updated;	/**< @brief Last update of the counters */
} t_counters;

/** Client node for the connected client linked list.
 */
typedef struct	_t_client {
  struct	_t_client *next;        /**< @brief Pointer to the next client */
	char	*ip;			/**< @brief Client Ip address */
	char	*mac;			/**< @brief Client Mac address */
	char	*token;			/**< @brief Client token */
	unsigned int fw_connection_state; /**< @brief Connection state in the
						     firewall */
	int	fd;			/**< @brief Client HTTP socket (valid only
					     during login before one of the
					     _http_* function is called */
	t_counters	counters;	/**< @brief Counters for input/output of
					     the client. */
	int warning;
} t_client;


t_client *client_get_first_client(void);


void client_list_init(void);


t_client *client_list_append(const char *ip, const char *mac, const char *token);


t_client *client_list_find(const char *ip, const char *mac);


t_client *client_list_find_by_ip(const char *ip); /* needed by fw_iptables.c, auth.c 
					     * and wdctl_thread.c */


t_client *client_list_find_by_mac(const char *mac); /* needed by wdctl_thread.c */


t_client *client_list_find_by_token(const char *token);


void client_list_delete(t_client *client);
void client_list_free(void);


#define LOCK_CLIENT_LIST() do { \
	debug(LOG_DEBUG, "Locking client list"); \
	pthread_mutex_lock(&client_list_mutex); \
	debug(LOG_DEBUG, "Client list locked"); \
} while (0)

#define UNLOCK_CLIENT_LIST() do { \
	debug(LOG_DEBUG, "Unlocking client list"); \
	pthread_mutex_unlock(&client_list_mutex); \
	debug(LOG_DEBUG, "Client list unlocked"); \
} while (0)

#endif /* _CLIENT_LIST_H_ */
