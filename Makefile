CFLAGS ?= -O2 -Wall

dnspq: dnspq.o
	$(CC) -o $@ $(LDFLAGS) $<

libnss_dnspq.so.2: nss-dnspq.o
	$(CC) -o $@ $(LDFLAGS) -shared -Wl,-soname,$@ $<

clean:
	rm -f dnspq dnspq.o
