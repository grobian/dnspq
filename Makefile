CFLAGS ?= -O2 -Wall -fPIC -DNSS_DNSPQ_RESTRICT_DOMAIN=\"lb-pool\"

GIT_VERSION := $(shell git describe --abbrev=6 --dirty --always)
CFLAGS += -DGIT_VERSION=\"$(GIT_VERSION)\"

dnspq: dnspq.o
	$(CC) -o $@ $(LDFLAGS) $<

nss: libnss_dnspq.so.2

libnss_dnspq.so.2: dnspq.o nss-dnspq.o
	$(CC) -o $@ $(LDFLAGS) -shared -Wl,-soname,$@ $^

clean:
	rm -f dnspq dnspq.o nss-dnspq.o libnss_dnspq.so.2
