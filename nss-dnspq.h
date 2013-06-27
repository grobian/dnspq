
enum nss_status _nss_dnspq_gethostbyname3_r(const char *name, int af,
		struct hostent *host, char *buf, size_t buflen,
		int *errnop, int *h_errnop, int32_t *ttlp, char **canonp);
enum nss_status _nss_dnspq_gethostbyname2_r(const char *name, int af,
		struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop);
enum nss_status _nss_dnspq_gethostbyname_r(const char *name,
		struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop);
enum nss_status _nss_dnspq_gethostbyaddr2_r(const void* addr, socklen_t len,
		int af, struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop, int32_t *ttlp);
enum nss_status _nss_dnspq_gethostbyaddr_r(const void* addr, socklen_t len,
		int af, struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop);
