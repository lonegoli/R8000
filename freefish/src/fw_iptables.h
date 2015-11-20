#ifndef _FW_IPTABLES_H_
#define _FW_IPTABLES_H_

#include "firewall.h"

/*@{*/ 
/**Iptable table names used by FreeFish,注意，iptables的表名不能大于28个字符，所以不用FreeFish而用FF */
#define TABLE_FREEFISH_OUTGOING  "FF_$ID$_Outgoing"
#define TABLE_FREEFISH_WIFI_TO_INTERNET "FF_$ID$_WIFI2Internet"
#define TABLE_FREEFISH_WIFI_TO_ROUTER "FF_$ID$_WIFI2Router"
#define TABLE_FREEFISH_INCOMING  "FF_$ID$_Incoming"
#define TABLE_FREEFISH_AUTHSERVERS "FF_$ID$_AuthServers"
#define TABLE_FREEFISH_GLOBAL  "FF_$ID$_Global"
#define TABLE_FREEFISH_VALIDATE  "FF_$ID$_Validate"
#define TABLE_FREEFISH_KNOWN     "FF_$ID$_Known"
#define TABLE_FREEFISH_UNKNOWN   "FF_$ID$_Unknown"
#define TABLE_FREEFISH_LOCKED    "FF_$ID$_Locked"
#define TABLE_FREEFISH_TRUSTED    "FF_$ID$_Trusted"
/*@}*/ 

/** Used by iptables_fw_access to select if the client should be granted of denied access */
typedef enum fw_access_t_ {
    FW_ACCESS_ALLOW,
    FW_ACCESS_DENY
} fw_access_t;

/** @brief Initialize the firewall */
int iptables_fw_init(void);

/** @brief Initializes the authservers table */
void iptables_fw_set_authservers(void);

/** @brief Clears the authservers table */
void iptables_fw_clear_authservers(void);

/** @brief Destroy the firewall */
int iptables_fw_destroy(void);

/** @brief Helper function for iptables_fw_destroy */
int iptables_fw_destroy_mention( const char * table, const char * chain, const char * mention);

/** @brief Define the access of a specific client */
int iptables_fw_access(fw_access_t type, const char *ip, const char *mac, int tag);

/** @brief All counters in the client list */
int iptables_fw_counters_update(void);
int iptables_do_command(const char *format, ...);

#endif /* _IPTABLES_H_ */
