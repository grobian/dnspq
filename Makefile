CFLAGS ?= -O2 -Wall -fPIC

dnspq: dnspq.o
	$(CC) -o $@ $(LDFLAGS) $<

nss: libnss_dnspq.so.2

libnss_dnspq.so.2: dnspq.o nss-dnspq.o
	$(CC) -o $@ $(LDFLAGS) -shared -Wl,-soname,$@ $<

clean:
	rm -f dnspq dnspq.o nss-dnspq.o libnss_dnspq.so.2
