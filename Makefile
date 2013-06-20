CFLAGS ?= -O2 -Wall

dnspq: dnspq.o
	$(CC) -o $@ $(LDFLAGS) $<

clean:
	rm -f dnspq dnspq.o
