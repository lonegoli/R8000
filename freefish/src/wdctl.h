#ifndef _WDCTL_H_
#define _WDCTL_H_

#define DEFAULT_SOCK	"/tmp/wdctl.sock"

#define WDCTL_UNDEF		0
#define WDCTL_STATUS		1
#define WDCTL_STOP		2
#define WDCTL_KILL		3
#define WDCTL_DEBUG		4

#define WDCTL_RESTART	5
#define WDCTL_UPGRADE	6
#define WDCTL_DESTROY	7
#define WDCTL_DISABLE	8
#define WDCTL_ENABLE	9
#define WDCTL_SHOW	10

typedef struct {
	char	*socket;
	int	command;
	char	*param;
} s_config;
#endif
