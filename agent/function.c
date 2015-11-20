#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>
#include <sys/wait.h>



#include "debug.h"
#include "safe.h"
#include "dpopen.h"
#include "common.h"
#include "function.h"
#include "md5.h"


/*
void 
cli_exec(char *cmd, char *result)
{
	char line[80];
	FILE *fp;
	char *p;
	fp = dpopen("cli");
	if(fp == NULL) {
		debug(LOG_ERR, "Pipe error");
	}
	if((p = strchr(cmd, '#'))) {
		*p = 0;
		debug(LOG_INFO, "Call: %s", cmd);
		fprintf(fp, cmd);
		debug(LOG_INFO, "Call: %s", p+1);
		fprintf(fp, p+1);
		*p = '#';
	}
	else {
		debug(LOG_INFO, "Call: %s", cmd);
		fprintf(fp, cmd);
	}
	//fprintf(fp, "exit\n");
	if(dphalfclose(fp) < 0) {
		debug(LOG_ERR, "Fclose error");
	}
	result[0] = 0;
	for(;;) {
		if(fgets(line, 80, fp) == NULL)
			break;
		//fputs(line, stdout);
		strcat(result, line);
	}
	dpclose(fp);
}
*/
int
exec(char *cmd, char *res, size_t n)
{
	FILE *stream;
	debug(LOG_INFO, "Call: %s", cmd);
	stream = popen(cmd,"r");
	memset(res, 0, n);
	if(stream == NULL) {
		debug(LOG_ERR,"Popen faild");
		return -1;
	} else {
		if(res != NULL) {
			int i=fread(res, sizeof(char), n - 1, stream);
			trim(res);
			debug(LOG_INFO, " Function result: %s", res);
		}
		return pclose(stream);
			
	}
}

void 
read_wan_ip_addr(char *ip_addr, size_t n)
{
	exec("nvram get wan_ipaddr", ip_addr, n);
	ip_addr[n - 1] = '\0';
}


void 
read_lan_mac_addr(char *mac_addr, size_t n)
{
	exec("nvram get lan_hwaddr", mac_addr, n);
	mac_addr[n - 1] = '\0';
}

void 
read_wan_mac_addr(char *mac_addr, size_t n)
{
	exec("nvram get wan_hwaddr", mac_addr, n);
	mac_addr[n - 1] = '\0';
}

void 
read_mac_addr(char *mac_addr, size_t n)
{
	exec("nvram get macaddr", mac_addr, n);
	mac_addr[n - 1] = '\0';
}


void 
read_model(char *model, size_t n)
{
	exec("nvram get wl_mode", model, n);
	model[n - 1] = '\0';
}


void 
read_firmware_version(char *firmVer, size_t n)
{


}


void 
read_serial_number(char *sn, size_t n)
{


}


void
read_apname(char *apname, size_t n)
{
	
}


void
set_apname(char *apname, char *result, size_t n)
{
	char cmd[128];
	memset(result, 0 , n);
	if(!strlen(apname)) {
		debug(LOG_INFO,"Parameter apname error");
		strcpy(result, ERROR_002);
		return;
	}
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set router_name=%s", apname);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
	//system(cmd);
}


void
set_mode(int index, char *mode, char *result, size_t n)
{
	char cmd[128];
	char *arr_mode[] = RADIO_MODE;
	int mode_index;
	memset(result, 0 , n);
	if(atoi(mode) > GET_ARRAY_LEN(arr_mode)) {
		debug(LOG_INFO,"Parameter mode error");
		strcpy(result, ERROR_001);
		return;
	}
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_net_mode=%s", index, arr_mode[atoi(mode)]);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
	//system(cmd);
}


void
set_power(int index, char *power, char *result, size_t n)
{
	char cmd[128];
	memset(result, 0 , n);
	if(atoi(power) < 1 || atoi(power) > 1000) {
		debug(LOG_INFO,"Parameter mode error");
		strcpy(result, ERROR_001);
		return;
	}
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_txpwr=%s", index, power);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);

}


void
set_channel(int index, char *channel, char *result, size_t n)
{
	char cmd[128];
	memset(result, 0 , n);
	if(!strstr(SUPPORT_CHANNEL_LIST, channel)) {
		debug(LOG_INFO,"Parameter channel error");
		strcpy(result, ERROR_001);
		return;
	}		
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_channel=%s", index, channel);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
	//system(cmd);
}


void
set_channelwidth(int index, char *channelwidth, char *result, size_t n)
{
	char cmd[128];
	memset(result, 0 , n);
	if(!strstr(SUPPORT_CHANNELWIDTH_LIST, channelwidth)) {
		debug(LOG_INFO,"Parameter channelwidth error");
		strcpy(result, ERROR_001);
		return;
	}		
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_nbw=%s", index, channelwidth);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
	//system(cmd);
}


void
set_max_assoc(int index, char *max_assoc, char *result, size_t n)
{
	char cmd[128];
	memset(result, 0 , n);
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_maxassoc=%d", index, atoi(max_assoc));
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
	//system(cmd);
}


void
set_ap_isolate(int index, char *isolate, char *result, size_t n)
{
	char cmd[128];
	int closed;
	memset(result, 0 , n);
	if(atoi(isolate) == 1)
		closed = 1;
	else 
		closed = 0;
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_ap_isolate=%d", index, closed);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
}


void
set_status(int index, int profile, char *status, char *result, size_t n)
{
	char cmd[128];
	int closed;
	memset(result, 0 , n);
	if(atoi(status) == 1)
		closed = 0;
	else 
		closed = 1;
	
	if(profile == 0)
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_closed=%d", index, closed);
	else
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d.%d_closed=%d", index, profile, closed);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
	//system(cmd);
}

void
set_ssid(int index, int profile, char *ssid, char *result, size_t n)
{
	char cmd[128];
	memset(result, 0 , n);
	if(profile == 0)
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_ssid=%s", index, ssid);
	else
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d.%d_ssid=%s", index, profile, ssid);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
	//system(cmd);
}


void 
set_security_mode(int index, int profile_index, char *security_mode, char *result, size_t n)
{
	char cmd[128];
	memset(result, 0 , n);
	if(profile_index == 0)
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_security_mode=%s;nvram set wl%d_akm=%s", index, security_mode, index, security_mode);
	else
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%dX%d_security_mode=%s", index, profile_index, security_mode);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
}


void 
set_crypto(int index, int profile_index, char *crypto, char *result, size_t n)
{
	char cmd[128];
	memset(result, 0 , n);
	if(profile_index == 0)
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_crypto=%s", index, crypto);
	else
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d.%d_crypto=%s", index, profile_index, crypto);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
}


void
set_radius_key(int index, int profile_index, char *radius_key, char *result, size_t n)
{
	char cmd[128];
	memset(result, 0 , n);
	if(profile_index == 0)
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_radius_key=%s", index, radius_key);
	else
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d.%d_radius_key=%s", index, profile_index, radius_key);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
}


void 
set_wpa_psk(int index, int profile_index, char *wpa_psk, char *result, size_t n)
{
	char cmd[128];
	memset(result, 0 , n);
	if(profile_index == 0)
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_wpa_psk=%s", index, wpa_psk);
	else
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d.%d_wpa_psk=%s", index, profile_index, wpa_psk);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
}


/*
void
set_authentication(int index, int profile, char *ssid, char *result, size_t n)
{
	char cmd[128];
	if(profile == 0)
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d_ssid=%s", index, ssid);
	else
		snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram set wl%d.%d_ssid=%s", index, profile, ssid);
	debug(LOG_INFO,"Call: %s", cmd);
	exec(cmd, result, n);
	//system(cmd);
}
*/


unsigned long int
read_uptime(void)
{
	FILE * fh;
	unsigned long int sys_uptime  = 0;
	if ((fh = fopen("/proc/uptime", "r"))) {
		fscanf(fh, "%lu", &sys_uptime);
		fclose(fh);
	}
	else {
		debug(LOG_ERR,"Fopen faild");
	}
	return sys_uptime;
}


int
read_ssid(int index, char *ssid, size_t n)
{
	char cmd[128];
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram get wl%d_ssid", index);
	exec(cmd, ssid, n);
	ssid[n - 1] = '\0';
	return strlen(ssid);

}


int
read_radio_status(int index)
{
	char cmd[128];
	char result[128];
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "wl -i eth%d status", index);
	exec(cmd, result, 128);
	return isAffixBy(result, "wl");

}


int
read_assoc_client_count(char *interface_name, char *count, size_t n)
{
	char assoclist[MAX_BUF];
	char cmd[128];
	int i = 0;
	int line = 0;
	char *p;
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "wl -i %s assoclist", interface_name);
	exec(cmd, assoclist, MAX_BUF);
	/*
	if(isAffixBy(assoclist, "assoclist")) {
		line++;
		while(assoclist[i]) {
			if(assoclist[i] == '\n') {
				line++;
			}
			i++;
		}
	}
	*/
	snprintf(count, n, "%d", str_count(assoclist, "assoclist"));
	count[n - 1] = '\0';
	return line;
}


void
read_assoc_client_list(char *interface_name, char *assoclist, size_t n)
{
	char cmd[128];
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "wl -i %s assoclist", interface_name);
	exec(cmd, assoclist, n);
	assoclist[n - 1] = '\0';
}


void 
read_counter(char *counter, char *interface_name, char *type, size_t n)
{
	char cmd[128];
	char res[256];
	memset(counter, 0, n);
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "cat /proc/net/dev |grep %s", interface_name);
	exec(cmd, res, sizeof(res)/sizeof(res[0]));
	if(strcmp(type, "Rxbytes") == 0)
		sscanf(res, "%*s %s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", counter);
	else if(strcmp(type, "Txbytes") == 0)
		sscanf(res, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %s %*s %*s %*s %*s %*s %*s %*s\n", counter);
	else if(strcmp(type, "Rxpkt") == 0)
		sscanf(res, "%*s %*s %s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", counter);
	else if(strcmp(type, "Txpkt") == 0)
		sscanf(res, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %s %*s %*s %*s %*s %*s %*s\n", counter);
	else if(strcmp(type, "rx_errors") == 0)
		sscanf(res, "%*s %*s %*s %s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", counter);
	else if(strcmp(type, "tx_errors") == 0)
		sscanf(res, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %s %*s %*s %*s %*s %*s\n", counter);
	else if(strcmp(type, "rx_discards") == 0)
		sscanf(res, "%*s %*s %*s %*s %s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", counter);
	else if(strcmp(type, "tx_discards") == 0)
		sscanf(res, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %s %*s %*s %*s %*s\n", counter);
	
}


void 
read_channel(char *interface_name, char *channel, size_t n)
{
	char cmd[128];
	char result[128];
	char *p;
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "wl -i %s channel", interface_name);
	exec(cmd, result, 128);
	if(p = strstr(result, "target channel"))
		strncpy(channel, p+15, n);
	else
		strncpy(channel, "0", n);
}


void 
read_assoc_rssi(char *interface_name, char *mac, char *rssi, size_t n)
{
	char cmd[128];
	char result[128];
	char *p;
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "wl -i %s rssi %s", interface_name, mac);
	exec(cmd, result, n);
	if(p = strstr(result, "wl"))
		strncpy(rssi, "0", n);
	else
		strncpy(rssi, result, n);
}


void 
read_vifs(int index, char *vifs, size_t n)
{
	char cmd[128];
	char result[128];
	char *p;
	snprintf(cmd, sizeof(cmd)/sizeof(cmd[0]), "nvram get wl%d_vifs", index);
	exec(cmd, result, n);
	
	strncpy(vifs, result, n);
}


void
apply_setting(void)
{
	char result[128];
	exec("nvram set action_service=wireless_2\\ wireless", result, 128);
	exec("ledtool 1", result, 128);
	exec("start_single_service", result, 128);
 	exec("nvram commit", result, 128);
}


void
add_virtual_interface(int index, int profile_index)
{
/*
	char result[128];
	exec("nvram set wl0.1_wmf_bss_enable=0;
		nvram set wl0_vifs=wl0.1;
		nvram set wl0.1_dns_ipaddr=0.0.0.0;
		nvram set wl0.1_ifname=wl0.1;
		nvram set wl0.1_multicast=0;
		nvram set wl0.1_mode=ap;
		nvram set wl0.1_ap_isolate=0;
		nvram set wl0.1_radius_ipaddr=0.0.0.0;
		nvram set wl0.1_ssid=dd-wrt_vap;
		nvram set wl0.1_bss_maxassoc=128;
		nvram set wl0.1_isolation=0;
		nvram set wl0.1_gtk_rekey=3600;
		nvram set wl0.1_nat=1;
		nvram set wl0.1_wme=on;
		nvram set wl0.1_dns_redirect=0;
		nvram set wl0.1_wep=disabled", result, 128);
		wl1.3_radius_port=1812
		wl1.3_bridged=1
		wl1.1_ipaddr=0.0.0.0
		wl1.1_ipaddr=0.0.0.0
		*/
		if(0<profile_index<4) {
			char result[128];
			char cmd[1024];
			char vifs[128];
			char *wifi[4]={NULL,NULL,NULL,NULL};
			char *p1,*p2;
			int i;
			read_vifs(index, vifs, sizeof(vifs)/sizeof(vifs[0]));
			while(vifs[strlen(vifs)-1]==' ') {
				vifs[strlen(vifs)-1] = '\0';
			}
			sprintf(vifs, "%s wl%d.%d ", vifs, index, profile_index);
			//printf("aaaa%s\n\r",vifs);
			p1 = vifs;
			for(i=0;(p2=strchr(p1, ' '))&&i<3;i++) {
				*p2 = '\0';
				p2++;
				wifi[i] = p1;
				p1=p2;
			}
			
			
			sprintf(cmd, "nvram set wl%d.%d_bridged=1;nvram set wl%d.%d_radius_ipaddr=0.0.0.0;nvram set wl%d.%d_dns_ipaddr=0.0.0.0;nvram set wl%d.%d_netmask=0.0.0.0;nvram set wl%d.%d_wmf_bss_enable=0;nvram set wl%d.%d_ipaddr=0.0.0.0;nvram set wl%d.%d_radius_port=1812;nvram set wl%d.%d_ap_isolate=0;nvram set wl%d.%d_multicast=0;nvram set wl%d.%d_nat=1;nvram set wl%d.%d_dns_redirect=0;nvram set wl%d.%d_closed=0;nvram set wl%d.%d_mode=ap;nvram set wl%d.%d_isolation=0;nvram set wl%d.%d_ssid=dd-wrt_vap;nvram set wl%d.%d_gtk_rekey=3600;nvram set wl%d_vifs=",
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index, profile_index,
				index);	
			for(i=0;i<3;i++) {
				if(wifi[i]!=NULL)
					strcat(cmd, wifi[i]);
					strcat(cmd, "\\ ");
			}
			while(cmd[strlen(cmd)-1]=='\\' || cmd[strlen(cmd)-1]==' ') {
				cmd[strlen(cmd)-1] = '\0';
			}
			exec(cmd, result, 128);
		}
}


void 
del_virtual_interface(int index, int profile_index)
{
	char vifs[128];
	char *p;
	char viname[32];
	char cmd[128];
	char result[128];
	memset(vifs,0,128);
	read_vifs(index, vifs, sizeof(vifs)/sizeof(vifs[0]));
	sprintf(viname, "wl%d.%d", index, profile_index);
	if(p=strstr(vifs, viname)) {
		*p='\0';
		sprintf(cmd, "nvram set wl%d_vifs=%s\\%s", index, vifs, p+8);
		while(cmd[strlen(cmd)-1]=='\\') {
				cmd[strlen(cmd)-1] = '\0';
		}
		exec(cmd, result, 128);
	}
	
}


int 
download_file(char *Spath, char *Dpath)
{
	char wget_cmd[1024];
	/*
	strcpy(wget_cmd, "wget -c -O \0");
	strcat(wget_cmd, Dpath);
	strcat(wget_cmd, " ");
	strcat(wget_cmd, Spath);
	strcat(wget_cmd, " 2>&1");
	*/
	if(strlen(Dpath) == 0 || strlen(Spath) == 0) {
		return -1;
	}
	snprintf(wget_cmd, sizeof(wget_cmd), "rm -rf %s", Dpath);
	exec(wget_cmd, NULL, 0);
	snprintf(wget_cmd, sizeof(wget_cmd), "wget -c -O %s %s 2>&1", Dpath, Spath);
	int status = exec(wget_cmd, NULL, 0);
	if (status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		snprintf(wget_cmd, sizeof(wget_cmd), "chmod 777 %s", Dpath);
		exec(wget_cmd, NULL, 0);
		return 0;
	}
	else {
		return -1;
	}
	
}


int 
check_md5(char *path, char *Smd5)
{/*
	char res[128];
	char md5sum_cmd[128];
	char *p;
	snprintf(md5sum_cmd, sizeof(md5sum_cmd), "md5sum %s\0", path);
	exec(md5sum_cmd, res, sizeof(res));
	p = res;
	while(*p != '\0') {
		if(*p == ' ') {
			*p = '\0';
			break;
		}
		++p;
	}
	debug(LOG_DEBUG, "The caculated MD5 value is %s", res);
	if(strcasecmp(res, Smd5) == 0) {
		return 0;
	}
	else {
		return -1;
	}
	*/
	
	char data_buf[1024];  
	char res[128];
	unsigned char md5[16];  
	MD5_CTX ctx;   
	int data_fd;   
	int nread;   
	int i;       
      
	data_fd = open(path, 0);   
	if(data_fd == -1){     
		perror("open");     
		return -1;
	}       
	MD5_Init(&ctx);   
	while(nread = read(data_fd, data_buf, sizeof(data_buf)), nread > 0){     
		MD5_Update(&ctx, data_buf, nread);   
	}  
	close(data_fd);
	MD5_Final(md5, &ctx); 
	memset(res, 0 , 128);
	for(i = 0; i < sizeof(md5); ++i) {
		snprintf(res + i*2, 2+1, "%02x", md5[i]);
	}
	debug(LOG_INFO, "The caculated MD5 value is %s", res);
	if(strcasecmp(res, Smd5) == 0) {
		return 0;
	}
	else {
		return -1;
	}
}


/*

int 
set_config(char *cmd, char * result)
{
	char ErrMesg[B_5_BUF];
	char *p;
	result[0] = ErrMesg[0] = 0;
	//debug(LOG_INFO, "Call: %s", cmd);
	cli_exec(cmd, ErrMesg);
	
	debug(LOG_INFO, "Result= %s", ErrMesg);
	if(strlen(ErrMesg) > 0 && !strstr(ErrMesg, "already")) {
		if(ErrMesg[strlen(ErrMesg) -1] == '\n') {
			ErrMesg[strlen(ErrMesg) -1] = 0;
		}
		if((p = strchr(cmd, '#'))) {
			*p = 0;
			sprintf(result, "Operation:%s%s, Error:%s", cmd, p+1, ErrMesg);
		}
		else {
			sprintf(result, "Operation:%s, Error:%s", cmd, ErrMesg);
		}
		return -1;	
	}
	return 0;
	
}
*/

