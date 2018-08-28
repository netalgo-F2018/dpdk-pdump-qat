
RTE_SDK=$(CURDIR)/DPDK
MAKE_PARAMS=EXTRA_LDLIBS="-lqatzip -lz" RTE_SDK=$(RTE_SDK) RTE_TARGET=build

all: dpdk test

dpdk:
	make -C $(RTE_SDK) config T=x86_64-native-linuxapp-gcc
	make -C $(RTE_SDK) $(MAKE_PARAMS) -j8 >/dev/null

test:
	bash test_pmd_pcap_dc.sh > test_pmd_pcap_dc.sh.stdout 2>&1 && echo Done.
