
dnspq: dnspq.o
	$(CC) -o $@ $(LDFLAGS) $<

clean:
	rm dnspq dnspq.o
