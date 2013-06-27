#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <arpa/inet.h>


/* http://www.freesoft.org/CIE/RFC/1035/40.htm */

#define ID(buf)      (ntohs(*(uint16_t*)(buf)))
#define QR(buf)      ((buf[2] >> 7) & 0x01)
#define OPCODE(buf)  ((buf[2] >> 3) & 0x0F)
#define AA(buf)      ((buf[2] >> 2) & 0x01)
#define TC(buf)      ((buf[2] >> 1) & 0x01)
#define RD(buf)      ((buf[2]     ) & 0x01)
#define RA(buf)      ((buf[3] >> 7) & 0x01)
#define Z(buf)       ((buf[3] >> 4) & 0x07)
#define RCODE(buf)   ((buf[3]     ) & 0x0f)
#define QDCOUNT(buf) (ntohs(*(uint16_t*)(buf+4)))
#define ANCOUNT(buf) (ntohs(*(uint16_t*)(buf+6)))
#define NSCOUNT(buf) (ntohs(*(uint16_t*)(buf+8)))
#define ARCOUNT(buf) (ntohs(*(uint16_t*)(buf+10)))

#define SET_ID(buf, val)      (*(uint16_t*)(buf) = htons(val))
#define SET_QR(buf, val)      (buf[2] |= ((val & 0x01) << 7))
#define SET_OPCODE(buf, val)  (buf[2] |= ((val & 0x0f) << 3))
#define SET_AA(buf, val)      (buf[2] |= ((val & 0x01) << 2))
#define SET_TC(buf, val)      (buf[2] |= ((val & 0x01) << 1))
#define SET_RD(buf, val)      (buf[2] |= ((val & 0x01)     ))
#define SET_RA(buf, val)      (buf[3] |= ((val & 0x01) << 7))
#define SET_Z(buf, val)       (buf[3] |= ((val & 0x07) << 4))
#define SET_RCODE(buf, val)   (buf[3] |= ((val & 0x0f)     ))
#define SET_QDCOUNT(buf, val) (*(uint16_t*)(buf+4) = htons(val))
#define SET_ANCOUNT(buf, val) (*(uint16_t*)(buf+6) = htons(val))
#define SET_NSCOUNT(buf, val) (*(uint16_t*)(buf+8) = htons(val))
#define SET_ARCOUNT(buf, val) (*(uint16_t*)(buf+10) = htons(val))


#define MAXSERVERS  8

static uint16_t cntr = 0;
static struct sockaddr_in *dnsservers[MAXSERVERS] = { 0, 0, 0, 0, 0, 0, 0, 0 };

int adddnsserver(const char *server) {
	int i;
	struct sockaddr_in *dnsserver;

	/* find free slot */
	for (i = 0; i < MAXSERVERS && dnsservers[i] != NULL; i++)
		;
	if (i == MAXSERVERS)
		return 1;

	dnsserver = dnsservers[i] = malloc(sizeof(*dnsserver));
	if (inet_pton(AF_INET, server, &(dnsserver->sin_addr)) <= 0)
		return 2;
	dnsserver->sin_family = AF_INET;
	dnsserver->sin_port = htons(53);

	return 0;
}

int dnsq(const char *a, struct in_addr *ret) {
	unsigned char dnspkg[512];
	unsigned char *p = dnspkg;
	char *ap;
	unsigned char len;
	int saddr_buf_len;
	fd_set fds;
	int fd;
	struct timeval tv;
	int i;

	/* header */
	memset(p, 0, 4);  /* need zeros; macros below do or-ing due to bits */
	SET_ID(p, ++cntr);
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
	p += 12;

	/* question section */
	while ((ap = strchr(a, '.')) != NULL) {
		len = (unsigned char)(ap - a);
		*p++ = len;
		memcpy(p, a, len);
		p += len;
		a = ap + 1;
	}
	len = (unsigned char)strlen(a);  /* truncation, hmm ... */
	*p++ = len;
	memcpy(p, a, len + 1);
	p += len + 1;  /* including the trailing null label */
	SET_ID(p, 1 /* QTYPE == A */);
	p += 2;
	SET_ID(p, 1 /* QCLASS == IN */);
	p += 2;

	/* answer sections not necessary */

	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		return 1;
	len = (unsigned char)(p - dnspkg);  /* should always fit */
	for (i = 0; i < MAXSERVERS && dnsservers[i] != NULL; i++) {
		if (sendto(fd, dnspkg, len, 0,
					(struct sockaddr *)dnsservers[i], sizeof(*dnsservers[i])) != len)
			return 2;  /* TODO: fail only when all fail? */
	}

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	/* wait 300ms, then retry */
	tv.tv_sec = 0;
	tv.tv_usec = 300000;
	if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0) {
		/* retry, just once */
		for (i = 0; i < MAXSERVERS && dnsservers[i] != NULL; i++) {
			if (sendto(fd, dnspkg, len, 0,
						(struct sockaddr *)dnsservers[i], sizeof(*dnsservers[i])) != len)
				return 2;  /* TODO: fail only when all fail? */
		}
		tv.tv_sec = 0;
		tv.tv_usec = 200000;
		if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0)
			return 3;  /* nothing happened */
	}

	saddr_buf_len = recvfrom(fd, dnspkg, sizeof(dnspkg), 0, NULL, 0);
	if (saddr_buf_len == -1)
		return 4;

	/* close, we don't need the rest */
	close(fd);

	p = dnspkg;
	if (ID(p) != cntr)
		return 7; /* message not matching our request id */
	if (QR(p) != 1)
		return 8; /* not a response */
	if (OPCODE(p) != 0)
		return 9; /* not a standard query */
	switch (RCODE(p)) {
		case 0: /* no error */
			break;
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
			/* we likely did something wrong */
			return 10;
		default:
			return 11;
	}
	if (ANCOUNT(p) < 1)
		return 12; /* we only support non-empty answers */

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
	if (ID(p) != 1 /* QTYPE == A */)
		return 13;
    p += 2;
	if (ID(p) != 1 /* QCLASS == IN */)
		return 14;
	p += 2;
	p += 4; /* TTL */
	len = ID(p);
	p += 2;
	if (len != 4)
		return 15;
	memcpy(ret, p, 4);

	return 0;
}

int main(int argc, char *argv[]) {
	struct in_addr ip;
	if (adddnsserver("10.146.68.140") != 0)
		return 1;
	if (adddnsserver("10.196.69.200") != 0)
		return 1;
	//dnsq("elasticsearch-autocomplete-lhr4.lb-pool");
	if (dnsq(argv[1], &ip) == 0) {
		printf("%s\n", inet_ntoa(ip));
		return 0;
	}
	return 1;
}
