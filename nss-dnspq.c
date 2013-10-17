/*
 *  This file is part of dnspq.
 *
 *  dnspq is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  dnspq is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with dnspq.  If not, see <http://www.gnu.org/licenses/>.
 */


/* GLIBC nss module */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <nss.h>
#include <netdb.h>
#include <arpa/inet.h>

#ifdef LOGGING
#include <syslog.h>
#endif

#include "dnspq.h"

#ifndef RESOLV_CONF
#define RESOLV_CONF "/etc/resolv-dnspq.conf"
#endif

typedef struct _domaingroup {
	char *domain;
	struct _domaingroup *next;
	size_t poolcount;
	struct sockaddr_in **dnsservers;
} domaingroup;

static domaingroup *rpool = NULL;

#ifdef DEBUG
void debugconfig(void) {
	domaingroup *walk;
	struct sockaddr_in *swalk;
	int i;

	for (walk = rpool; walk != NULL; walk = walk->next) {
		printf("\"%s\": %zd\n",
				walk->domain ? walk->domain : "(cont)", walk->poolcount);
		for (i = 0, swalk = walk->dnsservers[i]; swalk != NULL; swalk = walk->dnsservers[++i]) {
			printf("    %s:%d\n", inet_ntoa(swalk->sin_addr), htons(swalk->sin_port));
		}
	}
}
#endif

/* library init */
/* read the config file and build up the structure per domain */
#ifndef DEBUG
__attribute__((constructor))
#endif
void readconfig(void) {
	FILE *resolvconf = NULL;
	int j, k;
	char buf[1024];
	domaingroup *tdg = NULL;
	domaingroup *ndg = NULL;
	char *p = NULL;
	struct sockaddr_in *dnsservers[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	struct sockaddr_in *dnsserver = NULL;
	int dnsi = 0;
	char *fps[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	int port;

#ifdef LOGGING
	openlog("dnspq", LOG_PID, LOG_USER);
	syslog(LOG_INFO, "nss-dnspq.so.2 v" VERSION " (" GIT_VERSION ") has been invoked");
#endif

	/* don't use time to avoid same sequence when multiple processes
	 * start at the same time */
	srand(getpid());

	/* .domain ip:port ip:port ...
	 * or
	 * nameserver ip 
	 *
	 * The first form creates a group of DNS servers to query for the
	 * domain.  The leading . is mandatory here (to distinguish easily).
	 * The second form is to facilitate traditional /etc/resolv.conf
	 * files.  Interleaving both forms is NOT supported.
	 */

	if ((resolvconf = fopen(RESOLV_CONF, "r")) == NULL)
		return;
	while (fgets(buf, sizeof(buf), resolvconf) != NULL)
		if (
				buf[0] == 'n' &&
				buf[1] == 'a' &&
				buf[2] == 'm' &&
				buf[3] == 'e' &&
				buf[4] == 's' &&
				buf[5] == 'e' &&
				buf[6] == 'r' &&
				buf[7] == 'v' &&
				buf[8] == 'e' &&
				buf[9] == 'r' &&
				buf[10] == ' ')
		{ /* traditional /etc/resolv.conf mode */
			if (dnsi == sizeof(dnsservers) - 1)
				continue;
			if ((p = strchr(buf + 11, '\n')) != NULL)
				*p = '\0';
			dnsserver = dnsservers[dnsi++] = malloc(sizeof(*dnsserver));
			if (inet_pton(AF_INET, buf + 11, &(dnsserver->sin_addr)) <= 0) {
				free(dnsserver);
				dnsserver = dnsservers[dnsi--] = NULL;
				continue;
			}
			dnsserver->sin_family = AF_INET;
			dnsserver->sin_port = htons(53);
		} else if (buf[0] == '.') { /* group mode */
			p = buf + 1;
			dnsi = 0;
			while (dnsi < sizeof(fps) && (p = strchr(p, ' ')) != NULL) {
				*p++ = '\0';
				fps[dnsi] = p;
				dnsi++;
			}
			if (dnsi == 0)
				continue;
			if ((p = strchr(fps[dnsi - 1], '\n')) != NULL)
				*p = '\0';
			k = 0;
			if (rpool == NULL) {
				tdg = rpool = malloc(sizeof(domaingroup));
				tdg->next = NULL;
			} else {
				for (tdg = rpool; ; tdg = tdg->next) {
					if (tdg->domain != NULL &&
							strcmp(tdg->domain, buf + 1) == 0)
					{
						/* randomise insertion */
						if ((k = tdg->poolcount++) > 1) {
							for (j = rand() % k; j > 0; j--)
								tdg = tdg->next;
						}
						break;
					}
					if (tdg->next == NULL)
						break;
				}
				ndg = malloc(sizeof(domaingroup));
				ndg->next = tdg->next;
				tdg = tdg->next = ndg;
			}
			if (k == 0) {
				tdg->domain = strdup(buf + 1);
				tdg->poolcount = 1;
			} else {
				tdg->domain = NULL;
				tdg->poolcount = 0;
			}
			tdg->dnsservers = malloc(sizeof(*dnsserver) * (dnsi + 1));
			for (j = 0, k = 0; j < dnsi; j++) {
				dnsserver = tdg->dnsservers[k++] = malloc(sizeof(*dnsserver));
				port = 0;
				if ((p = strchr(fps[j], ':')) != NULL) {
					*p++ = '\0';
					port = atoi(p);
				}
				if (inet_pton(AF_INET, fps[j], &(dnsserver->sin_addr)) <= 0) {
					free(dnsserver);
					dnsserver = tdg->dnsservers[--k] = NULL;
					continue;
				}
				dnsserver->sin_family = AF_INET;
				dnsserver->sin_port = htons(port == 0 ? 53 : port);
			}
			tdg->dnsservers[k] = NULL;
			dnsi = 0;
		}
	fclose(resolvconf);

	if (dnsi > 0) {
		/* create fallback group for traditional mode */
		if (rpool == NULL) {
			tdg = rpool = malloc(sizeof(domaingroup));
		} else {
			for (tdg = rpool; tdg->next != NULL; tdg = tdg->next)
				;
			tdg = tdg->next = malloc(sizeof(domaingroup));
		}
		tdg->domain = NULL;
		tdg->next = NULL;
		tdg->dnsservers = malloc(sizeof(*dnsserver) * (dnsi + 1));
		memcpy(tdg->dnsservers, dnsservers, sizeof(*dnsserver) * (dnsi + 1));
	}
}

/* strcmp at the tail of a string, either start, or from a dot */
static inline int tailcmp(const char *haystack, const char *needle) {
	size_t nl = strlen(needle);
	size_t hl = strlen(haystack);
	const char *p;
	if (nl < hl) {
		p = haystack + hl - nl - 1;
		if (*p++ == '.') {
			for (; *p != '\0' && *p == *needle; p++, needle++)
				;
			if (*p == '\0')
				return 0;
		}
	}
	return 1;
}

/* helper function to locate the set of nameservers for the given domain */
static inline char get_dnss_for_domain(
		struct sockaddr_in ***dnsservers,
		const char *name)
{
	domaingroup *w = rpool;
	int i;

	while (w != NULL) {
		if (w->domain == NULL) {
			*dnsservers = w->dnsservers;
			return 1;
		} else if (tailcmp(name, w->domain) == 0) {
			if (w->poolcount > 1) {
				i = w->next->poolcount;
				w->next->poolcount = (w->next->poolcount + 1) % w->poolcount;
				for (; i > 0; i--)
					w = w->next;
			}
			*dnsservers = w->dnsservers;
			return 1;
		} else {
			/* skip over entire pool */
			for (i = w->poolcount; i > 0; i--)
				w = w->next;
		}
	}
	return 0;

}

enum nss_status _nss_dnspq_gethostbyname3_r(const char *name, int af,
		struct hostent *host, char *buf, size_t buflen,
		int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
	unsigned int ttl;
	char sid;
	struct sockaddr_in **dnsservers = NULL;
	size_t nlen = 0;

	if (af == AF_INET &&
			(nlen = strlen(name)) > 0 &&
			buflen >= nlen + 1 + 2 * sizeof(void *) + sizeof(struct in_addr) + sizeof(void *) &&
			get_dnss_for_domain(&dnsservers, name) &&
			dnsq(dnsservers, name, (struct in_addr *)buf, &ttl, &sid) == 0)
	{
		host->h_addrtype = af;
		host->h_length = sizeof(struct in_addr);
		host->h_addr_list = (char **)buf + sizeof(struct in_addr);
		host->h_addr_list[0] = buf;
		host->h_addr_list[1] = NULL;
		host->h_aliases = (char **)&host->h_addr_list[2];
		host->h_aliases[0] = NULL;
		host->h_name = (char *)&host->h_aliases[1];
		memcpy(host->h_name, name, nlen + 1);
		if (ttlp != NULL)
			*ttlp = (int32_t)ttl;
		if (canonp != NULL)
			*canonp = host->h_name;

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

