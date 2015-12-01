#ifndef _COMMON_H_
#define _COMMON_H_

#define VERSION "V1.0.30"
#define SWVERSION "V1.0.0.1"

#define MAX_BUF 4096
#define INTERFACELEN 32
#define SSIDLEN 128
//#define ASSOCLISTLEN 4096
#define B_5_BUF 512
#define KEY 1234



#define INFORM "INFORM"
#define RESPONSE "RESPONSE"
#define REGISTER "register"
#define HEARTBEAT "heartbeat"
#define GETMONITOR "getMonitor"
#define PUSHMONITOR "pushMonitor"
#define PUSHCLIENTS "pushClients"


#define GETDEVICEINFO "getDeviceInfo"
#define SETDEVICEINFO "setDeviceInfo"
#define SETCONFIGURATIONS "setConfigurations"
#define SETCONFIGURATIONS "setConfigurations"
#define SETRADIOINFO "setRadioInfo"

#define GETASSOCIATEDCLIENTS "getAssociatedClients"
#define AGENTUPGRADE "agentUpgrade"
#define IMAGEUPGRADE "imageUpgrade"
#define IMAGEUPGRADESTATUS "imageUpgradeStatus"
#define REBOOT "reboot"

#define AGENTUPGRADESTATUS "agentUpgradeStatus"


#define KEY_ID "transaction_id"
#define KEY_MAC "sn"
#define KEY_TYPE "type"
#define KEY_OPERATION "operation"
#define KEY_RESULT "result"
#define KEY_ERR_CODE "err_code"
#define KEY_ERR_DESC "err_desc"
#define KEY_VALUESET "valueSet"



#define JSON_FORMAT_ERR	-1
#define CLOSE_CONNECT 2
#define SELECT_TIMEOUT -2
#define SELECT_ERROR -3
#define SOCKET_PIPE_BROKE -4
#define SOCKET_ERROR -5
#define SOCKET_READ_OK 0
#define REGISTER_FAILED -1
#define REGISTER_SUCCESS 0

#define DOWNAGENTDIR "/tmp/download/EliteAgent"
#define DOWNIMAGEDIR "/tmp/imageXXXX"


#define GET_ARRAY_LEN(array) (sizeof(array)/sizeof(array[0]))


#define ERROR_001 "parameter error" 
#define ERROR_002 "parameter is null" 


#define RADIO_MODE {"disabled", "b-only", "bg-mixed", "ng-only", "a-only", "na-only", "mixed"}
#define INTERFACE_INDEX {"50", "24", "51"}

#define SUPPORT_CHANNEL_LIST "0,36,40,44,48,52,56,60,64,100,104,108,112,116,132,136,140,144,149,153,157,161,165"
#define SUPPORT_CHANNELWIDTH_LIST "0,20,40,80"
int server_socket;
#define INTERFACE_NUM 3

#endif 

