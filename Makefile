
RTE_SDK=$(CURDIR)/DPDK
MAKE_PARAMS=EXTRA_LDLIBS="-lqatzip -lz" RTE_SDK=$(RTE_SDK) RTE_TARGET=build

all: dpdk test

dpdk:
	make -C DPDK $(MAKE_PARAMS) -j8 >/dev/null

test:
	./test_pmd_pcap_dc.sh > test_pmd_pcap_dc.sh.stdout 2>&1 && echo Done.
