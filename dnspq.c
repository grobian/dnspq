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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <arpa/inet.h>

#ifdef LOGGING
#include <syslog.h>
#endif

#include "dnspq.h"

/* http://www.freesoft.org/CIE/RFC/1035/40.htm */

#define ID(buf)      (ntohs(*(uint16_t*)(buf)))
#define QR(buf)      ((buf[2] >> 7) & 0x01)
#define OPCODE(buf)  ((buf[2] >> 3) & 0x0F)
#define AA(buf)      ((buf[2] >> 2) & 0x01)
#define TC(buf)      ((buf[2] >> 1) & 0x01)
#define RD(buf)      ((buf[2]     ) & 0x01)
#define RA(buf)      ((buf[3] >> 7) & 0x01)
#define Z(buf)       ((buf[3] >> 4) & 0x07)
#define RCODE(buf)   ((buf[3]     ) & 0x0F)
#define QDCOUNT(buf) (ntohs(*(uint16_t*)(buf+4)))
#define ANCOUNT(buf) (ntohs(*(uint16_t*)(buf+6)))
#define NSCOUNT(buf) (ntohs(*(uint16_t*)(buf+8)))
#define ARCOUNT(buf) (ntohs(*(uint16_t*)(buf+10)))

#define SET_ID(buf, val)      (*(uint16_t*)(buf) = htons(val))
#define SET_QR(buf, val)      (buf[2] |= ((val & 0x01) << 7))
#define SET_OPCODE(buf, val)  (buf[2] |= ((val & 0x0F) << 3))
#define SET_AA(buf, val)      (buf[2] |= ((val & 0x01) << 2))
#define SET_TC(buf, val)      (buf[2] |= ((val & 0x01) << 1))
#define SET_RD(buf, val)      (buf[2] |= ((val & 0x01)     ))
#define SET_RA(buf, val)      (buf[3] |= ((val & 0x01) << 7))
#define SET_Z(buf, val)       (buf[3] |= ((val & 0x07) << 4))
#define SET_RCODE(buf, val)   (buf[3] |= ((val & 0x0F)     ))
#define SET_QDCOUNT(buf, val) (*(uint16_t*)(buf+4) = htons(val))
#define SET_ANCOUNT(buf, val) (*(uint16_t*)(buf+6) = htons(val))
#define SET_NSCOUNT(buf, val) (*(uint16_t*)(buf+8) = htons(val))
#define SET_ARCOUNT(buf, val) (*(uint16_t*)(buf+10) = htons(val))


#ifndef MAXSERVERS
# define MAXSERVERS  8
#endif
#ifndef MAX_RETRIES
# define MAX_RETRIES  1
#endif
#ifndef MAX_TIMEOUT
# define MAX_TIMEOUT  500 * 1000  /* 500ms, the max time we want to wait */
#endif
#ifndef RETRY_TIMEOUT
# define RETRY_TIMEOUT  300 * 1000  /* 300ms, time to wait for answers */
#endif

typedef enum {
	NOERR = 0,
	NODATA = 1,
	SENDFAIL = 2,
	QTOOLONG = 3,
	NOHDR = 4,
	SOCKFAIL = 5,
	INVALIDID = 7,
	DNSNOQR = 8,
	DNSNOSQ = 9,
	DNSRFAIL = 10,
	DNSFUTURE = 11,
	DNSEMPTY = 12,
	DNSNXDOMAIN = 13,
	INCOMPLETE = 14,
	DNSAINVALIDLEN = 15,
	DNSNOA = 16,
	DNSNOIN = 17
} dnspq_errno;

#if defined(LOGGING) || defined(DNSPQ_TOOL)
static const char *dnspq_errcodes[] = {
	/*  0 */ "Success",
	/*  1 */ "No data received from server",
	/*  2 */ "Input query too long (exceeds 255 characters)",
	/*  3 */ "Failed to create socket",
	/*  4 */ "Server sent incomplete data, expected header",
	/*  5 */ "Failed to send data to server",
	/*  6 */ NULL,
	/*  7 */ "Server sent invalid ID (not matching our request)",
	/*  8 */ "DNS answer is not a response message",
	/*  9 */ "DNS answer is not a standard query",
	/* 10 */ "DNS answer is: format error, server failure, not implemented, or refused",
	/* 11 */ "DNS answer is: attempt to use future feature",
	/* 12 */ "DNS answer doesn't have address answers",
	/* 13 */ "DNS answer is: no such domain",
	/* 14 */ "Received data is incomplete",
	/* 15 */ "DNS answer has invalid length for IP response",
	/* 16 */ "DNS answer isn't for type A",
	/* 17 */ "DNS answer isn't for class IN"
};

static const char *
dnspq_strerror(dnspq_errno err)
{
	return dnspq_errcodes[err];
}
#endif

static uint16_t cntr = 0;

#define timediff(X, Y) \
	(Y.tv_sec > X.tv_sec ? (Y.tv_sec - X.tv_sec) * 1000 * 1000 + ((Y.tv_usec - X.tv_usec)) : Y.tv_usec - X.tv_usec)

int dnsq(
		struct sockaddr_in* const dnsservers[],
		const char *a,
		struct in_addr *ret,
		unsigned int *ttl,
		char *serverid)
{
	unsigned char dnspkg[512];
	unsigned char *p = dnspkg;
	char *ap;
	size_t len;
	int saddr_buf_len;
	int fd;
	struct timeval tv;
	struct timeval begin, end;
	int i;
	int nums = 0;
	uint16_t qid;
	char retries = MAX_RETRIES;
	suseconds_t maxtime = MAX_TIMEOUT;
	suseconds_t waittime = 0;
	dnspq_errno err = NOERR;

	if (++cntr == 0)  /* next sequence number, start at 1 (detect errs)  */
		cntr++;
	if (USHRT_MAX - MAXSERVERS < cntr)  /* avoid having to deal with overflow */
		cntr = 1;

	/* header */
	p += 12;

	/* question section */
	while ((ap = strchr(a, '.')) != NULL) {
		len = ap - a;
		if (len > 255)  /* proto spec */
			return QTOOLONG;
		*p++ = (unsigned char)len;
		memcpy(p, a, len);
		p += len;
		a = ap + 1;
	}
	len = strlen(a);
	*p++ = len;
	memcpy(p, a, len + 1);  /* always fits: 512 - 12 > 255 */
	p += len + 1;  /* including the trailing null label */
	SET_ID(p, 1 /* QTYPE == A */);
	p += 2;
	SET_ID(p, 1 /* QCLASS == IN */);
	p += 2;

	/* answer sections not necessary */
	len = p - dnspkg;

	tv.tv_sec = 0;
	gettimeofday(&begin, NULL);
	end.tv_sec = begin.tv_sec;
	end.tv_usec = begin.tv_usec;
	do {
		p = dnspkg;
		memset(p, 0, 4); /* need zeros; macros below do or-ing due to bits */
		/* SET_ID is done per server */
		SET_QR(p, 0 /* query */);
		SET_OPCODE(p, 0 /* standard query */);
		SET_AA(p, 0);
		SET_TC(p, 0);
		SET_RD(p, 0);
		SET_RA(p, 0);
		SET_Z(p, 0);
		SET_RCODE(p, 0);
		SET_QDCOUNT(p, 1 /* one question */);
		SET_ANCOUNT(p, 0);
		SET_NSCOUNT(p, 0);
		SET_ARCOUNT(p, 0);

		if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
			return SOCKFAIL;

		/* wait at most half of RETRY_TIMOUT */
		tv.tv_usec = maxtime - timediff(begin, end);
		if (tv.tv_usec > RETRY_TIMEOUT / 2)
			tv.tv_usec = RETRY_TIMEOUT / 2;
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

		for (i = 0; i < MAXSERVERS && dnsservers[i] != NULL; i++) {
			SET_ID(p, cntr + i);
			if (sendto(fd, dnspkg, len, 0,
						(struct sockaddr *)dnsservers[i],
						sizeof(*dnsservers[i])) != len) {
				close(fd);
				return SENDFAIL;  /* TODO: fail only when all fail? */
			}
		}

		/* this can be off by RETRY_TIMOUT / 2 * i, but saves us a
		 * gettimeofday() call */
		waittime = timediff(begin, end) + RETRY_TIMEOUT;
		if (waittime > maxtime)
			waittime = maxtime;
		nums = i;
		i = 0;
		do {
			gettimeofday(&end, NULL);
			tv.tv_usec = waittime - timediff(begin, end);
			if (tv.tv_usec <= 0)
				break;
			setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
			saddr_buf_len = recvfrom(fd, dnspkg, sizeof(dnspkg),
					0, NULL, NULL);

			if (saddr_buf_len < 0) {
				err = NODATA;
				if (errno == EINTR)
					continue;
				break;  /* read timeout, retry sending */
			} else if (saddr_buf_len < 12) { /* must have header */
				err = NOHDR;
				continue;
			}

			p = dnspkg;
			qid = ID(p);
			if (qid < cntr || qid > cntr + nums) {
				err = INVALIDID; /* message not matching our request id */
				continue;
			}
			/* ID matches, assume from a server we sent to */
			i++;
			*serverid = qid - cntr;
			if (QR(p) != 1) {
				err = DNSNOQR; /* not a response */
				continue;
			}
			if (OPCODE(p) != 0) {
				err = DNSNOSQ; /* not a standard query */
				continue;
			}
			switch (RCODE(p)) {
				case 0: /* no error */
					break;
				case 1: /* format error */
				case 2: /* server failure */
				case 4: /* not implemented */
				case 5: /* refused */
					/* haproxy returns server failure for empty pools */
#if LOGGING > 2
					syslog(LOG_INFO, "serv fail: %d/%d, %x %x %x %x",
							qid, i, p[0], p[1], p[2], p[3]);
#endif
					err = DNSRFAIL;
					continue;
				case 3:
					/* NXDOMAIN */
					err = DNSNXDOMAIN;
					continue;
				default: /* reserved for future use */
					err = DNSFUTURE;
					continue;
			}
			if (ANCOUNT(p) < 1) {
				err = DNSEMPTY; /* we only support non-empty answers */
				continue;
			}

			if (saddr_buf_len <= len) {
				err = INCOMPLETE;
				continue;
			}

			/* skip header + request */
			p += len;

			if ((*p | 3 << 6) == 3 << 6) {
				/* compression pointer, skip two octets */
				p += 2;
			} else {
				/* read labels */
				while (*p != 0)
					p += 1 + *p;
				p++;
			}
			if (ID(p) != 1 /* QTYPE == A */) {
				err = DNSNOA;
				continue;
			}
			p += 2;
			if (ID(p) != 1 /* QCLASS == IN */) {
				err = DNSNOIN;
				continue;
			}
			p += 2;
			*ttl = ntohs(*(uint32_t*)p);
			p += 4;
			if (ID(p) != 4) {
				err = DNSAINVALIDLEN;
				continue;
			}
			p += 2;

			err = NOERR;
			memcpy(ret, p, 4);

			break;
		} while (err != NOERR && i < nums);
#if LOGGING > 2
		if (err != NOERR) {
			gettimeofday(&end, NULL);
			syslog(LOG_INFO, "retrying due to error, code %d (%s), time spent: %zd, time left: %zd, nums: %d, i: %d, retries: %d, tv: %zd %zd, %zd %zd",
					err, dnspq_strerror(err),
					timediff(begin, end), maxtime - timediff(begin, end),
					nums, i, retries,
					begin.tv_sec, begin.tv_usec,
					end.tv_sec, end.tv_usec);
		}
#endif
		close(fd);
	} while (err != NOERR && err != DNSNXDOMAIN &&
	 		retries-- > 0 &&
			gettimeofday(&end, NULL) == 0 &&
			maxtime - timediff(begin, end) > 0);

#ifdef LOGGING
	if (err != NOERR)
		syslog(LOG_INFO, "error while resolving %s, code %d (%s)",
				a, err, dnspq_strerror(err));
#endif

	return (char)err;
}

static void
do_version(void)
{
	printf("DNS Parallel Query v" VERSION " (" GIT_VERSION ")\n");
}

#ifdef DNSPQ_TOOL
static void
do_usage(void)
{
	do_version();
	printf("diagnostic tool to test using/with dnspq against DNS servers\n");
	printf("options:\n");
	printf("  -v                  print version\n");
	printf("  -h                  this screen\n");
	printf("  -s <server[:port]>  server to query, multiple -s options are allowed\n");
	printf("all further arguments (or those after --) are being queried against\n");
	printf("the servers given, at least one server must be supplied\n");
}

int main(int argc, char *argv[]) {
	struct in_addr ip;
	unsigned int ttl;
	char serverid;
	dnspq_errno err;
	int ret;
	char *p;
	char *q;
	char *r;
	int i;
	int a;
	struct sockaddr_in *dnsservers[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	struct sockaddr_in *dnsserver;
	int dnsi = 0;

	if (argc == 1) {
		do_version();
		return 0;
	}

	for (a = i = 1; i < argc; i++) {
		p = argv[i];
		if (p == NULL)
			continue;
		if (*p == '-') {
			p++;
			switch (*p) {
				case 's':
					/* -s: server */
					if (*++p == '\0')
						p = argv[++i];
					if (dnsi == sizeof(dnsservers) - 1) {
						fprintf(stderr, "not adding server '%s', "
								"too many already (%zu)\n",
								p, sizeof(dnsservers) - 1);
						break;
					}
					r = NULL;
					for (q = p; *q != '\0'; q++) {
						if (*q == ':') {
							*q = '\0';
							r = q + 1;
						}
					}

					dnsserver = dnsservers[dnsi++] = malloc(sizeof(*dnsserver));
					dnsserver->sin_family = AF_INET;
					if (inet_pton(dnsserver->sin_family, p,
								&(dnsserver->sin_addr)) <= 0)
					{
						fprintf(stderr, "failed to parse IP address '%s'\n", p);
						return 1;
					}
					if (r != NULL) {
						dnsserver->sin_port = htons(atoi(r));
					} else {
						dnsserver->sin_port = htons(53);
					}
					a = i + 1;
					break;
				case 'v':
					/* -v: version */
					do_version();
					return 0;  /* yes, just quit */
				case 'h':
					/* -h: help */
					do_usage();
					return 0;  /* yes, just quit */
				case '-':
					/* --: end of arguments marker */
					a = i + 1;
					i = argc;
					break;
				default:
					/* unknown argument */
					fprintf(stderr, "unknown argument -%c\n", *p);
					return 1;
			}
		} else {
			a = i;
			break;
		}
	}

	if (dnsi == 0) {
		do_usage();
		return 1;
	}

	ret = 0;
	for (i = a; i < argc; i++) {
		if ((err = (dnspq_errno)dnsq(dnsservers, argv[i], &ip, &ttl, &serverid)) == NOERR) {
			printf("%-15s (TTL: %us, ",
					inet_ntoa(ip), ttl);
			dnsserver = dnsservers[(int)serverid];
			printf("responder %d: %15s:%d)  %s\n",
					serverid,
					inet_ntoa(dnsserver->sin_addr),
					ntohs(dnsserver->sin_port),
					argv[i]);
		} else {
			printf("failed to resolve %s: %s\n", argv[i], dnspq_strerror(err));
			ret = 1;
		}
	}
	return ret;
}
#endif
