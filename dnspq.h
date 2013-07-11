
int init(void);
int adddnsserver(const char *server);
int dnsq(const char *a, struct in_addr *ret, unsigned int *ttl, char *serverid);
