#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
//#include <sys/unistd.h>

#include <string.h>

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "client_list.h"


pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;


t_client         *firstclient = NULL;


t_client *
client_get_first_client(void)
{
    return firstclient;
}


void
client_list_init(void)
{
	debug(LOG_INFO, "init list of client");

    firstclient = NULL;
}


t_client         *
client_list_append(const char *ip, const char *mac, const char *token)
{
    t_client         *curclient, *prevclient;

    prevclient = NULL;
    curclient = firstclient;

    while (curclient != NULL) {
        prevclient = curclient;
        curclient = curclient->next;
    }

    curclient = safe_malloc(sizeof(t_client));
    memset(curclient, 0, sizeof(t_client));

    curclient->ip = safe_strdup(ip);
    curclient->mac = safe_strdup(mac);
    curclient->token = safe_strdup(token);
	curclient->warning = 0;
    curclient->counters.incoming = curclient->counters.incoming_history = curclient->counters.outgoing = curclient->counters.outgoing_history = 0;
    curclient->counters.last_updated = time(NULL);

    if (prevclient == NULL) {
        firstclient = curclient;
    } else {
        prevclient->next = curclient;
    }

    debug(LOG_INFO, "Added a new client to linked list: IP: %s Token: %s",
          ip, token);

    return curclient;
}


t_client         *
client_list_find(const char *ip, const char *mac)
{
    t_client         *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip) && 0 == strcmp(ptr->mac, mac))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}


t_client         *
client_list_find_by_ip(const char *ip)
{
    t_client         *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}


t_client         *
client_list_find_by_mac(const char *mac)
{
    t_client         *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->mac, mac))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}


t_client *
client_list_find_by_token(const char *token)
{
    t_client         *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->token, token))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}


void
_client_list_free_node(t_client * client)
{

    if (client->mac != NULL)
        free(client->mac);

    if (client->ip != NULL)
        free(client->ip);

    if (client->token != NULL)
        free(client->token);

    free(client);
}


void
client_list_delete(t_client * client)
{
    t_client         *ptr;

    ptr = firstclient;

    if (ptr == NULL) {
        debug(LOG_ERR, "Node list empty!");
    } else if (ptr == client) {
        firstclient = ptr->next;
        _client_list_free_node(client);
    } else {
       
        while (ptr->next != NULL && ptr->next != client) {
            ptr = ptr->next;
        }
       
        if (ptr->next == NULL) {
            debug(LOG_ERR, "Node to delete could not be found.");
       
        } else {
            ptr->next = client->next;
            _client_list_free_node(client);
        }
    }
}


void
client_list_free(void)
{
	t_client         *ptr; 
	while((ptr = firstclient) != NULL) {
		firstclient = firstclient->next;
    _client_list_free_node(ptr);
	}
}
