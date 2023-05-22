OPENSSL_CFLAGS ?= $(shell pkg-config --cflags libcrypto)
OPENSSL_LIBS ?= $(shell pkg-config --libs libcrypto)

TARGETS = cms-simple cms-add cms-dec
VALGRIND = valgrind -q --leak-check=full --leak-resolution=high --show-leak-kinds=all --error-exitcode=99

WRAPPER :=
SKIP := 0

all:	$(TARGETS)

clean:
	rm -f $(TARGETS)
	rm -f tmp.*

check:	all
	$(MAKE) check1 WRAPPER="$(VALGRIND)"

check-workaround:	all
	@echo
	@echo "this works in >=openssl-3 fails with =openssl-1.1"
	@echo
	$(MAKE) check1 SKIP=1

	@echo
	@echo but leaks
	@echo
	$(MAKE) check1 WRAPPER="$(VALGRIND)" SKIP=1

check1:
	rm -f tmp.*
	$(WRAPPER) ./cms-simple cms.der tmp.cms-out1.der $(SKIP)
	$(WRAPPER) ./cms-add cms.der tmp.cms-out.der test1.key test1.crt test3.crt $(SKIP)
	$(WRAPPER) ./cms-dec tmp.cms-out.der test1.key test1.crt data.ct tmp.data.pt.test1
	$(WRAPPER) ./cms-dec tmp.cms-out.der test3.key test3.crt data.ct tmp.data.pt.test3
	cmp data.pt tmp.data.pt.test1
	cmp data.pt tmp.data.pt.test3

.c:
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o$@ $< $(OPENSSL_LIBS) $(LDFLAGS)
