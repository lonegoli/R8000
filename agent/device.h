static const struct {
	const char *key;
	const char *value;
} radio_keywords[] = {
	{ "24",             "0" },
	{ "50",         	"1" },
	{ "51",   			"2" },
	{ NULL,				NULL},	
};


static const struct {
	const char *key;
	const char *value;
} authentication_keywords[] = {
	{ "0",             	"disabled" },
	{ "16",         	"wpa" },
	{ "32",   			"wpa2" },
	{ "48",     		"wpa wpa2" },
	{ NULL,				NULL},	
};


static const struct {
	const char *key;
	const char *value;
} encryption_keywords[] = {
	{ "0",             	"off" },
	{ "2",         		"tkip" },
	{ "4",   			"aes" },
	{ "6",     			"tkip+aes" },
	{ NULL,				NULL},	
};


static int
parse_radio_keywords(const char *cp)
{
	int i;

	for (i = 0; radio_keywords[i].key; i++)
		if (strcasecmp(cp, radio_keywords[i].key) == 0)
			return i;

	debug(LOG_ERR, "Unsupported parameter:%s", cp);
	return -1;
}


static int
parse_authentication_keywords(const char *cp)
{
	int i;

	for (i = 0; authentication_keywords[i].key; i++)
		if (strcasecmp(cp, authentication_keywords[i].key) == 0)
			return i;

	debug(LOG_ERR, "Unsupported parameter:%s", cp);
	return -1;
}


static int
parse_encryption_keywords(const char *cp)
{
	int i;

	for (i = 0; encryption_keywords[i].key; i++)
		if (strcasecmp(cp, encryption_keywords[i].key) == 0)
			return i;

	debug(LOG_ERR, "Unsupported parameter:%s", cp);
	return -1;
}


