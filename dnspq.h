
#define VERSION "1.0"

int dnsq(
		struct sockaddr_in* const dnsservers[],
		const char *a,
		struct in_addr *ret,
		unsigned int *ttl,
		char *serverid);
