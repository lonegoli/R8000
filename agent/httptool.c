#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "httptool.h"

int get_response_status_code(char *response)
{
	int scode;
	sscanf(response, "%*s %d %*s", &scode);
	return scode;
	
}


int get_response_content_length(char *response)
{
	char *p;
	int len;
	p = strstr(response, "\r\nContent-Length");
	if(p == NULL) {
		return -1;
	}
	sscanf(p, "%*[^0-9]%d%*[^0-9]", &len);
	return len;
}



