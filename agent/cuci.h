#ifndef _CUCI_H_
#define _CUCI_H_
#include "cJSON.h"
#include "conf.h"

struct upgradeArg {
	char id[32];
	char file_name[1024];
	char md5[64];
};


//void _getDeviceInfo(cJSON *root, const int sockfd, char *http_packet);
//void _setDeviceInfo(cJSON *root, const int sockfd, char *http_packet);
void _setConfigurations(cJSON *root, s_config *config, char *http_packet);
void _getMonitor(cJSON *root, s_config *config, char *http_packet);
void _getAssociatedClients(cJSON *root, s_config *config, char *http_packet);
void _setDeviceInfo(cJSON *root, s_config *config, char *http_packet);
void _setRadioInfo(cJSON *root, s_config *config, char *http_packet);
//void test(void);
void _agentUpgrade(cJSON *root, s_config *config, char *http_packet);
void _imageUpgrade(cJSON *root, s_config *config, char *http_packet);
void _badCommand(cJSON *root, s_config *config, char *http_packet);

#endif /* _CUCI_H_ */


