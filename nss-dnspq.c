
/* GLIBC nss module */

#include <string.h>
#include <errno.h>
#include <nss.h>
#include <netdb.h>

#include "dnspq.h"

enum nss_status _nss_dnspq_gethostbyname3_r(const char *name, int af,
		struct hostent *host, char *buf, size_t buflen,
		int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
	unsigned int ttl;

	if (buflen >= 6 + 2 * sizeof(void *) + sizeof(struct in_addr) &&
			af == AF_INET && dnsq(name, (struct in_addr *)buf, &ttl) == 0)
	{
		init();

		host->h_name = buf + sizeof(struct in_addr);
		memcpy(host->h_name, "dnspq", 6);
		host->h_aliases = (char **)buf + sizeof(struct in_addr) + 6;
		host->h_aliases[0] = buf;
		host->h_aliases[1] = NULL;
		host->h_addrtype = af;
		host->h_length = sizeof(struct in_addr);
		if (ttlp != NULL)
			*ttlp = (int32_t)ttl;
		if (*canonp != NULL)
			*canonp = buf + sizeof(struct in_addr);

		*errnop = 0;
		*h_errnop = 0;
		return NSS_STATUS_SUCCESS;
	}

	*errnop = EINVAL;
	*h_errnop = NO_RECOVERY;
	return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_dnspq_gethostbyname2_r(const char *name, int af,
		struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop)
{
	return _nss_dnspq_gethostbyname3_r(name, af, host, buffer, buflen,
			errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_dnspq_gethostbyname_r(const char *name,
		struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop)
{
	return _nss_dnspq_gethostbyname3_r(name, AF_INET, host, buffer, buflen,
			errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_dnspq_gethostbyaddr2_r(const void* addr, socklen_t len,
		int af, struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop, int32_t *ttlp)
{
	/* pacify compiler */
	(void) addr;
	(void) len;
	(void) af;
	(void) host;
	(void) buffer;
	(void) buflen;
	(void) ttlp;

	*errnop = EINVAL;
	*h_errnop = NO_RECOVERY;
	return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_dnspq_gethostbyaddr_r(const void* addr, socklen_t len,
		int af, struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop)
{
	/* pacify compiler */
	(void) addr;
	(void) len;
	(void) af;
	(void) host;
	(void) buffer;
	(void) buflen;

	*errnop = EINVAL;
	*h_errnop = NO_RECOVERY;
	return NSS_STATUS_UNAVAIL;
}

