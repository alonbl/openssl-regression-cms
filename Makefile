OPENSSL_CFLAGS ?= $(shell pkg-config --cflags libcrypto)
OPENSSL_LIBS ?= $(shell pkg-config --libs libcrypto)

TARGETS = cms-simple cms-add cms-dec
VALGRIND = valgrind -q --leak-check=full --leak-resolution=high --show-leak-kinds=all --error-exitcode=99

all:	$(TARGETS)

clean:
	rm -f $(TARGETS)
	rm -f tmp.*

check:	all
	rm -f tmp.*
	$(VALGRIND) ./cms-simple cms.der tmp.cms-out1.der
	$(VALGRIND) ./cms-add cms.der tmp.cms-out.der test1.key test1.crt test3.crt
	$(VALGRIND) ./cms-dec tmp.cms-out.der test1.key test1.crt data.ct tmp.data.pt.test1
	$(VALGRIND) ./cms-dec tmp.cms-out.der test3.key test3.crt data.ct tmp.data.pt.test3
	cmp data.pt tmp.data.pt.test1
	cmp data.pt tmp.data.pt.test3

.c:
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o$@ $< $(OPENSSL_LIBS) $(LDFLAGS)
