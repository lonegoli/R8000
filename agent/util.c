#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
//#include <sys/unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#if defined(__NetBSD__)
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <util.h>
#endif

#ifdef __linux__
#include <netinet/in.h>
#include <net/if.h>
#endif

#include <string.h>
#include <pthread.h>
#include <netdb.h>

#include "common.h"
#include "safe.h"
#include "util.h"
#include "conf.h"
#include "debug.h"

static pthread_mutex_t ghbn_mutex = PTHREAD_MUTEX_INITIALIZER;


int
execute(char *cmd_line, int quiet)
{
        int pid,
            status,
            rc;

        const char *new_argv[4];
        new_argv[0] = "/bin/sh";
        new_argv[1] = "-c";
        new_argv[2] = cmd_line;
        new_argv[3] = NULL;

        pid = safe_fork();
        if (pid == 0) {    /* for the child process:         */
                /* We don't want to see any errors if quiet flag is on */
                if (quiet) close(2);
                if (execvp("/bin/sh", (char *const *)new_argv) == -1) {    /* execute the command  */
                        debug(LOG_ERR, "execvp(): %s", strerror(errno));
                } else {
                        debug(LOG_ERR, "execvp() failed");
                }
                exit(1);
        }

        /* for the parent:      */
	debug(LOG_DEBUG, "Waiting for PID %d to exit", pid);
	rc = waitpid(pid, &status, 0);
	debug(LOG_DEBUG, "Process PID %d exited", rc);

        return (WEXITSTATUS(status));
}


/*//通过域名找IP */
	struct in_addr *
wd_gethostbyname(const char *name)
{
	struct hostent *he;
	struct in_addr *h_addr, *in_addr_temp;

	/* XXX Calling function is reponsible for free() */

	h_addr = safe_malloc(sizeof(struct in_addr));

	LOCK_GHBN();

	he = gethostbyname(name);

	if (he == NULL) {
		safe_free(h_addr);
		UNLOCK_GHBN();
		return NULL;
	}

	//in_addr_temp = (struct in_addr *)he->h_addr_list[0];
	//h_addr->s_addr = in_addr_temp->s_addr;
	h_addr = (struct in_addr *)he->h_addr;

	UNLOCK_GHBN();

	return h_addr;
}

	char *
get_iface_ip(const char *ifname)
{
#if defined(__linux__)
	struct ifreq if_data;
	struct in_addr in;
	char *ip_str;
	int sockd;
	u_int32_t ip;

	/* Create a socket */
	if ((sockd = safe_socket (AF_INET, SOCK_PACKET, htons(0x8086))) < 0) {
		debug(LOG_ERR, "socket(): %s", strerror(errno));
		return NULL;
	}

	/* Get IP of internal interface */
	strcpy (if_data.ifr_name, ifname);

	/* Get the IP address */
	if (ioctl (sockd, SIOCGIFADDR, &if_data) < 0) {
		debug(LOG_ERR, "ioctl(): SIOCGIFADDR %s", strerror(errno));
		return NULL;
	}
	memcpy ((void *) &ip, (void *) &if_data.ifr_addr.sa_data + 2, 4);
	in.s_addr = ip;

	ip_str = inet_ntoa(in);
	safe_close(sockd);
	return safe_strdup(ip_str);
#elif defined(__NetBSD__)
	struct ifaddrs *ifa, *ifap;
	char *str = NULL;

	if (getifaddrs(&ifap) == -1) {
		debug(LOG_ERR, "getifaddrs(): %s", strerror(errno));
		return NULL;
	}
	/* XXX arbitrarily pick the first IPv4 address */
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) == 0 &&
				ifa->ifa_addr->sa_family == AF_INET)
			break;
	}
	if (ifa == NULL) {
		debug(LOG_ERR, "%s: no IPv4 address assigned");
		goto out;
	}
	str = safe_strdup(inet_ntoa(
				((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));
out:
	freeifaddrs(ifap);
	return str;
#else
	return safe_strdup("0.0.0.0");
#endif
}

	char *
get_iface_mac(const char *ifname)
{
#if defined(__linux__)
	int r, s;
	struct ifreq ifr;
	char *hwaddr, mac[18];

	strcpy(ifr.ifr_name, ifname);

	s = safe_socket(PF_INET, SOCK_DGRAM, 0);
	if (-1 == s) {
		debug(LOG_ERR, "get_iface_mac socket: %s", strerror(errno));
		return NULL;
	}

	r = ioctl(s, SIOCGIFHWADDR, &ifr);
	if (r == -1) {
		debug(LOG_ERR, "get_iface_mac ioctl(SIOCGIFHWADDR): %s", strerror(errno));
		safe_close(s);
		return NULL;
	}

	hwaddr = ifr.ifr_hwaddr.sa_data;
	safe_close(s);
	snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X", 
			hwaddr[0] & 0xFF,
			hwaddr[1] & 0xFF,
			hwaddr[2] & 0xFF,
			hwaddr[3] & 0xFF,
			hwaddr[4] & 0xFF,
			hwaddr[5] & 0xFF
		);

	return safe_strdup(mac);
#elif defined(__NetBSD__)
	struct ifaddrs *ifa, *ifap;
	const char *hwaddr;
	char mac[18], *str = NULL;
	struct sockaddr_dl *sdl;

	if (getifaddrs(&ifap) == -1) {
		debug(LOG_ERR, "getifaddrs(): %s", strerror(errno));
		return NULL;
	}
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) == 0 &&
				ifa->ifa_addr->sa_family == AF_LINK)
			break;
	}
	if (ifa == NULL) {
		debug(LOG_ERR, "No MAC address assigned in interface: %s", ifname);
		goto out;
	}
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	hwaddr = LLADDR(sdl);
	snprintf(mac, sizeof(mac), "%02X-%02X-%02X-%02X-%02X-%02X",
			hwaddr[0] & 0xFF, hwaddr[1] & 0xFF,
			hwaddr[2] & 0xFF, hwaddr[3] & 0xFF,
			hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);

	str = safe_strdup(mac);
out:
	freeifaddrs(ifap);
	return str;
#else
	return NULL;
#endif
}

char *
get_ext_iface(void)
{
#ifdef __linux__
	FILE *input;
	char *device, *gw;
	int i = 1;
	int keep_detecting = 1;
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	device = (char *)malloc(16);
	gw = (char *)malloc(16);
	debug(LOG_DEBUG, "get_ext_iface(): Autodectecting the external interface from routing table");
	while(keep_detecting) {
		input = fopen("/proc/net/route", "r");
		while (!feof(input)) {
			/* XXX scanf(3) is unsafe, risks overrun */ 
			fscanf(input, "%s %s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", device, gw);
			if (strcmp(gw, "00000000") == 0) {
				safe_free(gw);
				debug(LOG_INFO, "get_ext_iface(): Detected %s as the default interface after trying %d times", device, i);
				return device;
			}
		}
		fclose(input);
		debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after trying %d times(maybe the interface is not up yet?).  Retry limit: %d", i, NUM_EXT_INTERFACE_DETECT_RETRY);
		/* Sleep for EXT_INTERFACE_DETECT_RETRY_INTERVAL seconds */
		sleep(1);
		timeout.tv_sec = time(NULL) + EXT_INTERFACE_DETECT_RETRY_INTERVAL;
		timeout.tv_nsec = 0;
		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);	
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
		//for (i=1; i<=NUM_EXT_INTERFACE_DETECT_RETRY; i++) {
		if (NUM_EXT_INTERFACE_DETECT_RETRY != 0 && i>NUM_EXT_INTERFACE_DETECT_RETRY) {
			keep_detecting = 0;
		}
		i++;
	}
	debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after %d tries, aborting", i);
	exit(1);
	safe_free(device);
	safe_free(gw);
#endif
	return NULL;
	}

#define ISSPACE(x) ((x)==' '||(x)=='\r'||(x)=='\n'||(x)=='\f'||(x)=='\b'||(x)=='\t')


char *
trim(char *String)
{
	char *Tail, *Head;
	for ( Tail = String + strlen( String ) - 1; Tail >= String; Tail -- )
		if( !ISSPACE( *Tail ) )
			break;
	Tail[1] = 0;
	
	for ( Head = String; Head <= Tail; Head ++ )
		if ( !ISSPACE( *Head ) )
			break;
		
	if ( Head != String )
		memcpy( String, Head, ( Tail - Head + 2 ) * sizeof( char ) );
	return String;

}


void 
trimH(char *buf)
{
	while(buf[0] == '\n' || buf[0] == '\r' || buf[0] == ' ') {
		memmove(buf, buf+1, strlen(buf));
	}
}
	
			
int 
isAffixBy(const char* srcStr , const char* subStr){
	int srcLen = 0;
	int subLen = 0;
	if (srcStr==NULL || subStr==NULL)
		return 0;
	/*while(subStr[strlen(subStr)-1]==' ')
	 {
		 subStr[strlen(subStr)-1]='\0';
	 }*/
	srcLen = strlen(srcStr);
	subLen = strlen(subStr);
	if (subLen > srcLen)
		return 0;
	const char* s_pos = srcStr + srcLen - subLen ;
	if (!strncmp(s_pos,subStr,subLen))
		return 1;
	return 0;
		 
}
		
int 
isBefixBy(const char* srcStr , const char* subStr){
	int srcLen = 0;
	int subLen = 0;
	if (srcStr==NULL || subStr==NULL)
		return 0;
	 
	srcLen = strlen(srcStr);
	subLen = strlen(subStr);
	if (subLen > srcLen)
		return 0;
	if (!strncmp(srcStr,subStr,subLen))
		return 1;
	return 0;
}

int
strpos(const char*s1,const char*s2)
{
const char*p = s1;
const size_t len = strlen(s2);
for(;(p=strchr(p,*s2))!=0;p++){
	if(strncmp(p,s2,len)==0)
	return p-s1;
}
return(-1);
}

void 
substr(char *szDest, const char *szSrc, size_t nPos, size_t nLen) {
	while (*szSrc && nPos--) szSrc++;
	while (*szSrc && nLen--) *szDest++=*szSrc++;
	*szDest='\0';
}


void get_string_uptime(char *sys_uptime)
{
	FILE * fh;
	if ((fh = fopen("/proc/uptime", "r"))) {
		/*系统启动到现在的时间*/
		fscanf(fh, "%s", sys_uptime);
		fclose(fh);
	}

}
int char_encrypt(char *data,int key){
	int i;
	for(i = 0; i< strlen(data); i++) {
		data[i] = data[i]^key;
	}
}
int char_decrypt(char *data,int key){
	int i;
	for(i = 0; i< strlen(data); i++) {
		data[i] = data[i]^key;
	}
}


int str_count(char *str, char *substr)
{ 
	int sum,len; 
	char *p; 
	len = strlen(substr); 
	if(len<1) 
		return 0;
	for(sum=0,p=str;;) { 
		p = strstr(p,substr);	
		if(p!=NULL) { 
			sum++; p=p+len; 
		} 
		else break; 
	} 
	return sum;
}


