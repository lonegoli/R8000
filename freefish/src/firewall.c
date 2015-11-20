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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/time.h>

#ifdef __linux__
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#endif

#if defined(__NetBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif

#include "httpd.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "fw_iptables.h"
#include "auth.h"
#include "centralserver.h"
#include "client_list.h"
//#include "sqlite_util.h"


extern pthread_mutex_t client_list_mutex;

/* from commandline.c */
extern pid_t restart_orig_pid;




int
fw_allow(char *ip, char *mac, int fw_connection_state)
{
    debug(LOG_DEBUG, "Allowing %s %s with fw_connection_state %d", ip, mac, fw_connection_state);

    return iptables_fw_access(FW_ACCESS_ALLOW, ip, mac, fw_connection_state);
}


int
fw_deny(char *ip, char *mac, int fw_connection_state)
{
    debug(LOG_DEBUG, "Denying %s %s with fw_connection_state %d", ip, mac, fw_connection_state);

    return iptables_fw_access(FW_ACCESS_DENY, ip, mac, fw_connection_state);
}


char           *
arp_get(char *req_ip)
{
    FILE           *proc;
	 char ip[16];
	 char mac[18];
	 char * reply = NULL;

    if (!(proc = fopen("/proc/net/arp", "r"))) {
        return NULL;
    }

    /* Skip first line */
	 while (!feof(proc) && fgetc(proc) != '\n');

	 /* Find ip, copy mac in reply */
	 reply = NULL;
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", ip, mac) == 2)) {
		  if (strcmp(ip, req_ip) == 0) {
				reply = safe_strdup(mac);
				break;
		  }
    }

    fclose(proc);
    str_char_replace(reply, ':', '-');
    return reply;
}

/** Initialize the firewall rules
 */
int
fw_init(void)
{
    int flags, oneopt = 1, zeroopt = 0;
	 int result = 0;
	 t_client * client = NULL;
/*setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt):  设置套接字接收缓冲区*/
    debug(LOG_INFO, "Creating ICMP socket");
    if ((icmp_fd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1 ||
            (flags = fcntl(icmp_fd, F_GETFL, 0)) == -1 ||
             fcntl(icmp_fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
             setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) ||
             setsockopt(icmp_fd, SOL_SOCKET, SO_DONTROUTE, &zeroopt, sizeof(zeroopt)) == -1) {
        debug(LOG_ERR, "Cannot create ICMP raw socket.");
        return 0;
    }

    debug(LOG_INFO, "Initializing Firewall");
    result = iptables_fw_init();

	 if (restart_orig_pid) {
		 debug(LOG_INFO, "Restoring firewall rules for clients inherited from parent");
		 LOCK_CLIENT_LIST();
		 client = client_get_first_client();
		 while (client) {
			 fw_allow(client->ip, client->mac, client->fw_connection_state);
			 client = client->next;
		 }
		 UNLOCK_CLIENT_LIST();
	 }

	 return result;
}

/** Remove all auth server firewall whitelist rules
 */
void
fw_clear_authservers(void)
{
	debug(LOG_INFO, "Clearing the authservers list");
	iptables_fw_clear_authservers();
}

/** Add the necessary firewall rules to whitelist the authservers
 */
void
fw_set_authservers(void)
{
	debug(LOG_INFO, "Setting the authservers list");
	iptables_fw_set_authservers();
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of FreeFish.
 * @return Return code of the fw.destroy script
 */
int
fw_destroy(void)
{
    if (icmp_fd != 0) {
        debug(LOG_INFO, "Closing ICMP socket");
        close(icmp_fd);
    }

    debug(LOG_INFO, "Removing Firewall rules");
    return iptables_fw_destroy();
}

/**Probably a misnomer, this function actually refreshes the entire client list's traffic counter, re-authenticates every client with the central server and update's the central servers traffic counters and notifies it if a client has logged-out.
 * @todo Make this function smaller and use sub-fonctions
 */
void
fw_sync_with_authserver(void)
{
    t_authresponse  authresponse;
    char            *token, *ip, *mac;
    t_client        *p1, *p2;
    unsigned long long	    incoming, outgoing;
    s_config *config = config_get_config();

    if (-1 == iptables_fw_counters_update()) {/*更新每个client已使用了多少网络流量*/
        debug(LOG_ERR, "Could not get counters from firewall!");
        return;
    }

    LOCK_CLIENT_LIST();

    for (p1 = p2 = client_get_first_client(); NULL != p1; p1 = p2) {
        p2 = p1->next;

        ip = safe_strdup(p1->ip);
        token = safe_strdup(p1->token);
        mac = safe_strdup(p1->mac);
	    outgoing = p1->counters.outgoing;
	    incoming = p1->counters.incoming;

	    UNLOCK_CLIENT_LIST();
        /* Ping the client, if he responds it'll keep activity on the link.
         * However, if the firewall blocks it, it will not help.  The suggested
         * way to deal witht his is to keep the DHCP lease time extremely
         * short:  Shorter than config->checkinterval * config->clienttimeout 用ping去检测client是否在线，如果防火墙阻止
         ping,就没有办法检测，如果这样的话，建议将路由器DHCP的的租约时间设置为极短
         比config->checkinterval * config->clienttimeout还短*/
        icmp_ping(ip);
        /* Update the counters on the remote server only if we have an auth server */
        /*if (config->auth_servers != NULL) {
            auth_server_request(&authresponse, REQUEST_TYPE_COUNTERS, ip, mac, token, incoming, outgoing);
        }*/
        authresponse.authcode = AUTH_ALLOWED;
	    LOCK_CLIENT_LIST();

        if (!(p1 = client_list_find(ip, mac))) {
            debug(LOG_ERR, "Node %s was freed while being re-validated!", ip);
        } else {
        	time_t	current_time=time(NULL);
        	debug(LOG_INFO, "Checking client %s for timeout:  Last updated %ld (%ld seconds ago), timeout delay %ld seconds, current time %ld, ",
                        p1->ip, p1->counters.last_updated, current_time-p1->counters.last_updated, config->checkinterval * config->clienttimeout, current_time);
            if (p1->counters.last_updated +
				(config->checkinterval * config->clienttimeout)
				<= current_time) {//不活跃的用户
                /* Timing out user 超时不活跃的用户*/
                debug(LOG_INFO, "%s - Inactive for more than %ld seconds, removing client and denying in firewall",
                        p1->ip, config->checkinterval * config->clienttimeout);
				/*恢复不活跃用户的iptables规则*/
                fw_deny(p1->ip, p1->mac, p1->fw_connection_state);
				//sqlite_update_client(p1->mac, 0);
                client_list_delete(p1);
				
                /* Advertise the logout if we have an auth server */
                /*if (config->auth_servers != NULL) {
					UNLOCK_CLIENT_LIST();
					auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT, ip, mac, token, 0, 0);
					LOCK_CLIENT_LIST();
                               }*/
            } else {
        
                if (config->auth_servers != NULL) {
                    switch (authresponse.authcode) {
                        case AUTH_DENIED:
                            debug(LOG_NOTICE, "%s - Denied. Removing client and firewall rules", p1->ip);
                            fw_deny(p1->ip, p1->mac, p1->fw_connection_state);
                            client_list_delete(p1);
                            break;

                        case AUTH_VALIDATION_FAILED:
                            debug(LOG_NOTICE, "%s - Validation timeout, now denied. Removing client and firewall rules", p1->ip);
                            fw_deny(p1->ip, p1->mac, p1->fw_connection_state);
                            client_list_delete(p1);
                            break;

                        case AUTH_ALLOWED:
                            if (p1->fw_connection_state != FW_MARK_KNOWN) {
                                debug(LOG_INFO, "%s - Access has changed to allowed, refreshing firewall and clearing counters", p1->ip);
                                //WHY did we deny, then allow!?!? benoitg 2007-06-21
                                //fw_deny(p1->ip, p1->mac, p1->fw_connection_state);

                                if (p1->fw_connection_state != FW_MARK_PROBATION) {
     p1->counters.incoming = p1->counters.outgoing = 0;
                                }
                                else {
                                	//We don't want to clear counters if the user was in validation, it probably already transmitted data..
                                    debug(LOG_INFO, "%s - Skipped clearing counters after all, the user was previously in validation", p1->ip);
                                }
                                p1->fw_connection_state = FW_MARK_KNOWN;
                                fw_allow(p1->ip, p1->mac, p1->fw_connection_state);
                            }
                            break;

                        case AUTH_VALIDATION:
               
                            debug(LOG_INFO, "%s - User in validation period", p1->ip);
                            break;

                              case AUTH_ERROR:
                                    debug(LOG_WARNING, "Error communicating with auth server - leaving %s as-is for now", p1->ip);
                                    break;

                        default:
                            debug(LOG_ERR, "I do not know about authentication code %d", authresponse.authcode);
                            break;
                    }
                }
            }
        }

        free(token);
        free(ip);
        free(mac);
    }
    UNLOCK_CLIENT_LIST();
}

void
icmp_ping(char *host)
{
	struct sockaddr_in saddr;
#if defined(__linux__) || defined(__NetBSD__)
	struct {
		struct ip ip;
		struct icmp icmp;
	} packet;
#endif
	unsigned int i, j;
	int opt = 2000;
	unsigned short id = rand16();

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	inet_aton(host, &saddr.sin_addr);
#if defined(HAVE_SOCKADDR_SA_LEN) || defined(__NetBSD__)
	saddr.sin_len = sizeof(struct sockaddr_in);
#endif

#if defined(__linux__) || defined(__NetBSD__)
	memset(&packet.icmp, 0, sizeof(packet.icmp));
	packet.icmp.icmp_type = ICMP_ECHO;
	packet.icmp.icmp_id = id;

	for (j = 0, i = 0; i < sizeof(struct icmp) / 2; i++)
		j += ((unsigned short *)&packet.icmp)[i];

	while (j >> 16)
		j = (j & 0xffff) + (j >> 16);

	packet.icmp.icmp_cksum = (j == 0xffff) ? j : ~j;

	if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
		debug(LOG_ERR, "setsockopt(): %s", strerror(errno));

	if (sendto(icmp_fd, (char *)&packet.icmp, sizeof(struct icmp), 0,
	           (const struct sockaddr *)&saddr, sizeof(saddr)) == -1)
		debug(LOG_ERR, "sendto(): %s", strerror(errno));

	opt = 1;
	if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
		debug(LOG_ERR, "setsockopt(): %s", strerror(errno));
#endif

	return;
}

unsigned short rand16(void) {
  static int been_seeded = 0;

  if (!been_seeded) {
    unsigned int seed = 0;
    struct timeval now;

  
    gettimeofday(&now, NULL);
    seed = now.tv_sec ^ now.tv_usec ^ (getpid() << 16);

    srand(seed);
    been_seeded = 1;
    }

  
      return( (unsigned short) (rand() >> 15) );
}
