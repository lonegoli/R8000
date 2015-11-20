#ifndef _FUNCTION_H_
#define _FUNCTION_H_

//void cli_exec(char *cmd, char *result);
int exec(char *cmd, char *res, size_t n);
void read_wan_ip_addr(char *ip_addr, size_t n);
void read_wan_mac_addr(char *mac_addr, size_t n);
void read_mac_addr(char *mac_addr, size_t n);

void read_model(char *model, size_t n);
void read_firmware_version(char *firmVer, size_t n);
void read_serial_number(char *sn, size_t n);
void read_apname(char *apname, size_t n);
int read_ssid(int index, char *ssid, size_t n);
int read_assoc_client_count(char *interface_name, char *count, size_t n);
void read_assoc_client_list(char *interface_name, char *assoclist, size_t n);
void read_counter(char *counter, char *interface_name, char *type, size_t n);
void read_channel(char *interface_name, char *channel, size_t n);
void  read_assoc_rssi(char *interface_name, char *mac, char *rssi, size_t n);
int read_radio_status(int index);
void  read_vifs(int index, char *vifs, size_t n);

unsigned long int read_uptime(void);
void set_apname(char *apname, char *result, size_t n);
void set_mode(int index, char *mode, char *result, size_t n);
void set_power(int index, char *power, char *result, size_t n);

void set_security_mode(int index, int profile_index, char *security_mode, char *result, size_t n);
void set_crypto(int index, int profile_index, char *crypto, char *result, size_t n);
void set_wpa_psk(int index, int profile_index, char *wpa_psk, char *result, size_t n);
void set_radius_key(int index, int profile_index, char *radius_key, char *result, size_t n);

void set_channel(int index, char *channel, char *result, size_t n);
void set_channelwidth(int index, char *channelwidth, char *result, size_t n);
void set_max_assoc(int index, char *max_assoc, char *result, size_t n);
void set_ap_isolate(int index, char *isolate, char *result, size_t n);
void set_status(int index, int profile, char *status, char *result, size_t n);
void set_ssid(int index, int profile, char *ssid, char *result, size_t n);
void apply_setting(void);
void add_virtual_interface(int index, int profile_index);
void del_virtual_interface(int index, int profile_index);
int download_file(char *Spath, char *Dpath);
int check_md5(char *path, char *Smd5);



/*Wired Traffic*/
/*
void read_Rxpkt(char *rxpkt, size_t n);
void read_Txpkt(char *txpkt, size_t n);
void read_Rxbytes(char *rxbytes, size_t n);
void read_Txbytes(char *txbytes, size_t n);
/*Wireless Traffic*/
/*
void read_Pxpkt(char *pxpkt, size_t n);
void read_Pxpkt(char *pxpkt, size_t n);
*/





//int set_config(char *cmd, char * result);
/*
void set_radio_index(char *value, char * result);
void set_radio(char *value, char * result);
void set_mode(char *value, char * result);
void set_power(char *value, char * result);
void set_channel(char *value, char * result);
void set_channelwidth(char *value, char * result);
void set_max_wireless_clients(char *value, char * result);
void set_client_isolation(char *value, char * result);
*/

#endif
