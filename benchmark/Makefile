
RTE_SDK=$(CURDIR)/../DPDK
MAKE_PARAMS=EXTRA_LDLIBS="-lqatzip -lz" RTE_SDK=$(RTE_SDK) RTE_TARGET=build

PKTGEN=$(CURDIR)/dpdk-pktgen

all: dpdk pktgen

dpdk:
	make -C $(RTE_SDK) $(MAKE_PARAMS) -j8 > /dev/null

pktgen:
	make -C $(PKTGEN) $(MAKE_PARAMS) > /dev/null
