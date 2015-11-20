#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "httpd.h"
#include "client_list.h"
#include "common.h"
#include "centralserver.h"

#include "util.h"

#include "config.h"

extern pthread_mutex_t	client_list_mutex;


void
http_callback_404(httpd *webserver, request *r)
{
	char tmp_url[MAX_BUF],
			*url,
			*mac;
	s_config	*config = config_get_config();
	t_auth_serv	*auth_server = get_auth_server();
	t_client	*client;
	memset(tmp_url, 0, sizeof(tmp_url));

	// if(!config->auth_self) {
        snprintf(tmp_url, (sizeof(tmp_url) - 1), "%s%s%s%s",
                        r->request.host,
                        r->request.path,
                        r->request.query[0] ? "?" : "",
                        r->request.query);
                        
     	
	/* }
	 else {
		snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
                        r->request.host,
                        r->request.path,
                        r->request.query[0] ? "?" : "",
                        r->request.query);
		
	 }*/
	

	/*if (!is_online()) {
		//The internet connection is down at the moment  - apologize and do not redirect anywhere 网络连接已断
		char * buf;
		safe_asprintf(&buf, 
			"<p>We apologize, but it seems that the internet connection that powers this hotspot is temporarily unavailable.</p>"
			"<p>If at all possible, please notify the owners of this hotspot that the internet connection is out of service.</p>"
			"<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
			"<p>In a while please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);

                send_http_page(r, "Uh oh! Internet access unavailable!", buf);
		free(buf);
		debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server", r->clientAddr);
	}
	else if (!is_auth_online()) {
		//The auth server is down at the moment - apologize and do not redirect anywhere,授权服务器断开网络连接 
		char * buf;
		safe_asprintf(&buf, 
			"<p>We apologize, but it seems that we are currently unable to re-direct you to the login screen.</p>"
			"<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
			"<p>In a couple of minutes please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);

                send_http_page(r, "Uh oh! Login screen unavailable!", buf);
		free(buf);
		debug(LOG_INFO, "Sent %s an apology since auth server not online - no point sending them to auth server", r->clientAddr);
	}*/
	if (!(mac = arp_get(r->clientAddr))) {
			/* We could not get their MAC address */
			debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			send_http_page(r, "FreeFish Error", "Failed to retrieve your MAC address");
	} 
	else {
		char *urlFragment;
		LOCK_CLIENT_LIST();
		if(((client = client_list_find(r->clientAddr, mac)) != NULL) && (client->warning <= 3)) {
			client->warning++;
			safe_asprintf(&urlFragment,"http://%s",
				tmp_url);
			debug(LOG_INFO, "Client for %s is already register success,maybe firewall delay,re-direct to %s again", r->clientAddr, urlFragment);
			UNLOCK_CLIENT_LIST();
			http_send_redirect(r, urlFragment, "redirect to ad");
		}
		else {
			UNLOCK_CLIENT_LIST();
			/* Re-direct them to auth server */
			url = httpdUrlEncode(tmp_url);
			if (!mac) {
				/* We could not get their MAC address */
				debug(LOG_INFO, "Failed to retrieve MAC address for ip %s, so not putting in the login request", r->clientAddr);
				safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&url=%s",
					auth_server->authserv_login_script_path_fragment,
					config->gw_address,
					config->gw_port, 
					config->gw_id,
					url);
			} else if(!config->auth_self) {
				safe_asprintf(&urlFragment, "?token=%s&ad_url=http%%3A%%2F%%2F%s",
					"123456789",
					url);
			} else {			
				debug(LOG_INFO, "Got client MAC address for ip %s: %s", r->clientAddr, mac);
				/*safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&mac=%s&url=%s",
					auth_server->authserv_login_script_path_fragment,
					config->gw_address,
					config->gw_port, 
					config->gw_id,
					mac,
					url);
					*/
					safe_asprintf(&urlFragment, "?gw_address=%s&gw_port=%d&gw_id=%s&mac=%s&url=http://%s",
					config->gw_address,
					config->gw_port, 
					config->gw_id,
					mac,
					url);
			}

			debug(LOG_INFO, "Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, url);
			////////////////////////////
			/*char *url =NULL;
			safe_asprintf(&url, "%s%s://%s:%d%s%s%s",
			"<script language=\"javascript\" type=\"text/javascript\">window.location.href='",
			"http",
			auth_server->authserv_hostname,
			auth_server->authserv_http_port,
			auth_server->authserv_path,
			urlFragment,
			"';</script>");
			printf("aaaaaaaaaaa%saaaaa\n\r",url);
			send_http_page(r, "Redirect to login page", url);
			free(url);*/
			////////////////////////////////////
			http_send_redirect_to_auth(r, urlFragment, "Redirect to login page");
			free(url);
		}
		free(urlFragment);
		free(mac);
		
	}
	
	
}

void 
http_callback_freefish(httpd *webserver, request *r)
{
	send_http_page(r, "FreeFish", "Please use the menu to navigate the features of this FreeFish installation.");
}

void 
http_callback_about(httpd *webserver, request *r)
{
	send_http_page(r, "About FreeFish", "This is FreeFish version <strong>" VERSION "</strong>");
}

void 
http_callback_status(httpd *webserver, request *r)
{
	const s_config *config = config_get_config();
	char * status = NULL;
	char *buf;

	if (config->httpdusername && 
			(strcmp(config->httpdusername, r->request.authUser) ||
			 strcmp(config->httpdpassword, r->request.authPassword))) {
		debug(LOG_INFO, "Status page requested, forcing authentication");
		httpdForceAuthenticate(r, config->httpdrealm);
		return;
	}

	status = get_status_text();
	safe_asprintf(&buf, "<pre>%s</pre>", status);
	send_http_page(r, "FreeFish Status", buf);
	free(buf);
	free(status);
}

void http_send_redirect_to_auth(request *r, char *urlFragment, char *text)
{
	char *protocol = NULL;
	int port = 80;
	t_auth_serv	*auth_server = get_auth_server();
	s_config	*config = config_get_config();

	if (auth_server->authserv_use_ssl) {
		protocol = "https";
		port = auth_server->authserv_ssl_port;
	} else {
		protocol = "http";
		port = auth_server->authserv_http_port;
	}
			    		
	char *url = NULL;
	if(!config->auth_self) {
		safe_asprintf(&url, "%s://%s:%d%s%s",
		protocol,
		config->gw_address,
		config->gw_port, 
		"/freefish/auth",
		urlFragment);
		
	} else {
		safe_asprintf(&url, "%s://%s:%d%s%s",
		protocol,
		auth_server->authserv_hostname,
		port,
		auth_server->authserv_path,
		urlFragment);
	}
	
	http_send_redirect(r, url, text);
	free(url);	
}


void http_send_redirect(request *r, char *url, char *text)
{
		char *message = NULL;
		char *header = NULL;
		char *response = NULL;
							/* Re-direct them to auth server */
		debug(LOG_DEBUG, "Redirecting client browser to %s", url);
		safe_asprintf(&header, "Location: %s",
			url
		);
		if(text) {
			safe_asprintf(&response, "307 %s\n",
				text
			);	
		}
		else {
			safe_asprintf(&response, "307 %s\n",
				"Redirecting"
			);		
		}	
		httpdSetResponse(r, response);//设置返回给客户端浏览器的的响应代码
		httpdAddHeader(r, header);//增加HTTP头内容
		free(response);
		free(header);	
		safe_asprintf(&message, "Please <a href='%s'>click here</a>.", url);
		send_http_page(r, text ? text : "Redirection to message", message);
		free(message);
}

void 
http_callback_auth(httpd *webserver, request *r)
{
	t_client	*client;
	httpVar * token;
	char	*mac;
	httpVar *logout = httpdGetVariableByName(r, "logout");
	if ((token = httpdGetVariableByName(r, "token"))) {
		/* They supplied variable "token" */
		if (!(mac = arp_get(r->clientAddr))) {
			/* We could not get their MAC address */
			debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			send_http_page(r, "FreeFish Error", "Failed to retrieve your MAC address");
		} else {
			/* We have their MAC address */

			LOCK_CLIENT_LIST();
			
			if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
				debug(LOG_DEBUG, "New client for %s", r->clientAddr);
				client_list_append(r->clientAddr, mac, token->value);
			} else if (logout) {//退出处理
			    t_authresponse  authresponse;
			    s_config *config = config_get_config();
			    unsigned long long incoming = client->counters.incoming;
			    unsigned long long outgoing = client->counters.outgoing;
			    //char *ip = safe_strdup(client->ip);
			    char *urlFragment = NULL;
			    t_auth_serv	*auth_server = get_auth_server();
			    /*删除该IP的相关iptables规则*/			    	
			    fw_deny(client->ip, client->mac, client->fw_connection_state);
				/*删除链表中的相关节点*/
			    client_list_delete(client);
			    debug(LOG_DEBUG, "Got logout from %s", client->ip);
			    
			    /* Advertise the logout if we have an auth server */
			    /*if (config->auth_servers != NULL) {
					UNLOCK_CLIENT_LIST();
					auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT, ip, mac, token->value, 
									    incoming, outgoing);
					LOCK_CLIENT_LIST();
					
					// Re-direct them to auth server 
					debug(LOG_INFO, "Got manual logout from client ip %s, mac %s, token %s"
					"- redirecting them to logout message", client->ip, client->mac, client->token);
					safe_asprintf(&urlFragment, "%smessage=%s",
						auth_server->authserv_msg_script_path_fragment,
						GATEWAY_MESSAGE_ACCOUNT_LOGGED_OUT
					);
					http_send_redirect_to_auth(r, urlFragment, "Redirect to logout message");
					free(urlFragment);
			    }*/
			    //free(ip);
 			} 
 			else {
				client->warning = 0;
				debug(LOG_INFO, "Client for %s is already in the client list", client->ip);
			}
			UNLOCK_CLIENT_LIST();
			if (!logout) {
				/*到 auth server 上校验 token*/
				authenticate_client(r);
			}
			free(mac);
		}
	} else {
		/* They did not supply variable "token" */
		send_http_page(r, "FreeFish error", "Invalid token");
	}
}

void send_http_page(request *r, const char *title, const char* message)
{
    s_config	*config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;

    fd=open(config->htmlmsgfile, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written]=0;
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "nodeID", config->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}

