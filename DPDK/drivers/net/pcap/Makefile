# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation.
# Copyright(c) 2014 6WIND S.A.
# All rights reserved.

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_pcap.a

ifeq ($(CONFIG_RTE_LIBRTE_PMD_PCAP_COMP),y)
# \begin QAT-related CFLAGS & LDLIBS
QAT_INCLUDE	= -I$(ICP_ROOT)/quickassist/include 		\
		  -I$(ICP_ROOT)/quickassist/include/dc 		\
		  -I$(ICP_ROOT)/quickassist/lookaside/access_layer/include
USDM_INCLUDE	= -I$(ICP_ROOT)/quickassit/utilities/libusdm_drv
QATZIP_INCLUDE	= -I$(QATZIP_ROOT)/include -I$(QATZIP_ROOT)/src
CFLAGS		+= $(QAT_INCLUDE) $(USDM_INCLUDE) $(QATZIP_INCLUDE)
LDLIBS		+= -lqatzip -lz
# \end QAT-related CFLAGS & LDLIBS
endif

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
LDLIBS += -lpcap
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs
LDLIBS += -lrte_bus_vdev

EXPORT_MAP := rte_pmd_pcap_version.map

LIBABIVER := 1

#
# all source are stored in SRCS-y
#
ifeq ($(CONFIG_RTE_LIBRTE_PMD_PCAP_COMP),y)
SRCS-$(CONFIG_RTE_LIBRTE_PMD_PCAP) += qc/qzip_cookie.c
endif

SRCS-$(CONFIG_RTE_LIBRTE_PMD_PCAP) += rte_eth_pcap.c

#
# Export include files
#
SYMLINK-y-include +=

include $(RTE_SDK)/mk/rte.lib.mk
