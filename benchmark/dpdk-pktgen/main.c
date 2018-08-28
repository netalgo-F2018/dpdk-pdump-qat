/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   Copyright(c) 2014-2016 Tiwei Bie (btw@FreeBSD.org). All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/mman.h>

#include <pcap/pcap.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>

//#define DEBUG_CONFIG_FILE

static bool build_udp_packet(char *buf, int *pkt_size, uint64_t *seed);
static bool build_tcp_packet(char *buf, int *pkt_size,
			     __attribute__((unused)) uint64_t *seed);

#ifndef __FAVOR_BSD
#define __FAVOR_BSD /* For uh_ prefix in struct udphdr */
#endif
//#include <net/ethernet.h> /* conflict with rte_ether.h */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1
#define FATAL_ERROR(fmt, args...)	rte_exit(EXIT_FAILURE, fmt "\n", ##args)
#define PRINT_INFO(fmt, args...)	RTE_LOG(INFO, APP, fmt "\n", ##args)

/* Max ports that can be used (each port is associated with at least one lcore) */
#define MAX_PORTS		RTE_MAX_LCORE

/* Max queues that can be used (each queue is associated with exactly one lcore) */
#define MAX_QUEUES		16

/* Number of mbufs in mempool that is created */
#define NB_MBUF			8192

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ		32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MBUF_CACHE_SIZE		250

/* Number of RX ring descriptors */
#define NB_RXD			512

/* Number of TX ring descriptors */
#define NB_TXD			512

/* Options for configuring ethernet port */
static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.header_split   = 0,   /* Header Split disabled */
		.hw_ip_checksum = 0,   /* IP checksum offload disabled */
		.hw_vlan_filter = 0,   /* VLAN filtering disabled */
		.jumbo_frame    = 0,   /* Jumbo Frame Support disabled */
		.hw_strip_crc   = 0,   /* CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IPV4,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

/* Mempool for mbufs */
static struct rte_mempool *pktmbuf_pool = NULL;

static uint64_t cores_mask = 0;
static uint64_t ports_mask = 0;
static uint64_t queues_masks[MAX_PORTS] = { 0 };

struct core_conf {
	uint8_t core_id;
	uint8_t port_id;
	uint8_t queue_id;
};

/* Array storing port_id and queue_id that are associated with each lcore */
static struct core_conf cores_conf[MAX_PORTS * MAX_QUEUES];
static int nb_cores_conf = 0;

#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))

/* Structure type for recording lcore-specific stats */
struct stats {
	uint64_t rx_pkts;
	uint64_t rx_bytes;

	uint64_t tx_pkts;
	uint64_t tx_bytes;

	uint64_t tx_total_pkts;
	uint64_t tx_total_bytes;

	uint64_t rx_total_pkts;
	uint64_t rx_total_bytes;
} __attribute__((aligned(64)));;

/* Array of lcore-specific stats */
static struct stats lcore_stats[RTE_MAX_LCORE];
static short port_ids[RTE_MAX_LCORE];
static short queue_ids[RTE_MAX_LCORE];

static enum {
	TX = 0,
	RX
} func;

static struct timeval last_time[RTE_MAX_LCORE] __attribute__((aligned(64)));

static int32_t opt_pkt_size   = 60;
static int32_t opt_burst_size = 3;
static int32_t opt_loop_count = 0;
static int32_t opt_interval   = 3000000;

typedef bool (*build_packet_t)(char *buf, int *pkt_size, uint64_t *seed);
static build_packet_t build_packet = build_udp_packet;

struct file_cache {
	char filename[MAXPATHLEN];
	char *fcache;
	uint64_t offset;
	uint64_t size;
	struct pcap_file_header hdr;
	struct file_cache *next;
} __attribute__((aligned(64)));;

struct file_cache *lcore_file_cache[RTE_MAX_LCORE] = { NULL };
static char tracefilelist[MAXPATHLEN] = { 0 };

#define MAX_PKT_LEN	(1512 + 4)

/* Print out statistics on packets handled */
static void
print_stats(void)
{
	unsigned i;
	uint64_t total_pkts = 0;
	uint64_t total_bytes = 0;

	if (func == RX) {
		printf("\n**Pktgen statistics**\n"
		       "=======  ======  ======= ============  ==============\n"
		       " Lcore    Port    Queue   RX Packets        RX Bytes \n"
		       "-------  ------  ------- ------------  --------------\n");
		RTE_LCORE_FOREACH(i) {
			if (!((1ULL << i) & cores_mask)) {
				printf("%6u %7c %8c %12c %15c\n",
				       i, '-', '-', '-', '-');
				continue;
			}
			lcore_stats[i].rx_total_pkts  += lcore_stats[i].rx_pkts;
			lcore_stats[i].rx_total_bytes += lcore_stats[i].rx_bytes;

			printf("%6u %7d %8d %12"PRIu64" %15"PRIu64"\n",
			       i, port_ids[i], queue_ids[i],
			       lcore_stats[i].rx_total_pkts,
			       lcore_stats[i].rx_total_bytes);

			total_pkts  += lcore_stats[i].rx_total_pkts;
			total_bytes += lcore_stats[i].rx_total_bytes;
		}
	} else {
		printf("\n**Pktgen statistics**\n"
		       "=======  ======  ======= ============  ==============\n"
		       " Lcore    Port    Queue   TX Packets        TX Bytes \n"
		       "-------  ------  ------- ------------  --------------\n");
		RTE_LCORE_FOREACH(i) {
			if (!((1ULL << i) & cores_mask)) {
				printf("%6u %7c %8c %12c %15c\n",
				       i, '-', '-', '-', '-');
				continue;
			}
			lcore_stats[i].tx_total_pkts  += lcore_stats[i].tx_pkts;
			lcore_stats[i].tx_total_bytes += lcore_stats[i].tx_bytes;

			printf("%6u %7d %8d %12"PRIu64" %15"PRIu64"\n",
			       i, port_ids[i], queue_ids[i],
			       lcore_stats[i].tx_total_pkts,
			       lcore_stats[i].tx_total_bytes);

			total_pkts  += lcore_stats[i].tx_total_pkts;
			total_bytes += lcore_stats[i].tx_total_bytes;
		}
	}
	printf("%6s %7c %8c %12"PRIu64" %15"PRIu64"\n", "Total",
	       '-', '-', total_pkts, total_bytes);
	printf("=======  ======  ======= ============  ==============\n");
}

static void
update_rx_stats(int count)
{
	unsigned int lcore_id = rte_lcore_id();
	struct timeval tv;
	double sec_diff;
	double bps, pps;
	uint64_t rx_pkts = lcore_stats[lcore_id].rx_pkts;
	uint64_t rx_bytes = lcore_stats[lcore_id].rx_bytes;

	gettimeofday(&tv, NULL);

	sec_diff  = tv.tv_sec  - last_time[lcore_id].tv_sec;
	sec_diff += (tv.tv_usec - last_time[lcore_id].tv_usec) / 1000000.0;
	assert(sec_diff != 0);

	/*
	 * Raw packets have 4 bytes crc + 20 bytes framing, this is
	 * where '+ rx_pkts * 24' comes from. Note, This is only used
	 * to calculate the transmit speed. And it is not counted into
	 * the total bytes in final statistics in print_stats(), which
	 * only contains the total bytes of ether header, ip header,
	 * tcp/udp header, and payload.
	 */
	pps = rx_pkts / sec_diff;
	bps = ((rx_bytes + rx_pkts * 24) * 8.0) / sec_diff;

	printf("Lcore %2u: %2.3f Mpps, %3.3f Gbps "
	       "(%ld packets per chunk) in %6.4f sec\n",
	       lcore_id, pps / 1000000.0, bps / 1000000000.0,
	       lcore_stats[lcore_id].rx_pkts / count, sec_diff);

	last_time[lcore_id] = tv;
}

static void
update_tx_stats(int count)
{
	unsigned int lcore_id = rte_lcore_id();
	struct timeval tv;
	double sec_diff;
	double bps, pps;
	uint64_t tx_pkts = lcore_stats[lcore_id].tx_pkts;
	uint64_t tx_bytes = lcore_stats[lcore_id].tx_bytes;

	gettimeofday(&tv, NULL);

	sec_diff  = tv.tv_sec  - last_time[lcore_id].tv_sec;
	sec_diff += (tv.tv_usec - last_time[lcore_id].tv_usec) / 1000000.0;
	assert(sec_diff != 0);

	/*
	 * Raw packets have 4 bytes crc + 20 bytes framing, this is
	 * where '+ tx_pkts * 24' comes from. Note, This is only used
	 * to calculate the transmit speed. And it is not counted into
	 * the total bytes in final statistics in print_stats(), which
	 * only contains the total bytes of ether header, ip header,
	 * tcp/udp header, and payload.
	 */
	pps = tx_pkts / sec_diff;
	bps = ((tx_bytes + tx_pkts * 24) * 8.0) / sec_diff;

	printf("Lcore %2u: %2.3f Mpps, %3.3f Gbps "
	       "(%ld packets per chunk) in %6.4f sec\n",
	       lcore_id, pps / 1000000.0, bps / 1000000000.0,
	       lcore_stats[lcore_id].tx_pkts / count, sec_diff);

	last_time[lcore_id] = tv;
}

/* Custom handling of signals to handle stats */
static void
signal_handler(int signum)
{
	/* When we receive a USR1 signal, print stats */
	if (signum == SIGUSR1) {
		print_stats();
	}

	if (signum == SIGINT) {
		print_stats();
		exit(EXIT_SUCCESS);
	}

	/* When we receive a USR2 signal, reset stats */
	if (signum == SIGUSR2) {
		memset(&lcore_stats, 0, sizeof(lcore_stats));
		printf("\n**Statistics have been reset**\n");
		return;
	}
}

static inline uint32_t
myrand(uint64_t *seed)
{
	*seed = *seed * 1103515245 + 12345;
	return (uint32_t)(*seed >> 32);
}

#if 0
static void
dump_packet(char *buf, int pkt_size)
{
	struct ether_hdr *eh = (struct ether_hdr *)buf;
	struct ip *ip = (struct ip *)(eh + 1);
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	char *payload = (char *)(udp + 1);

	(void)pkt_size; // Check with ip->ip_len.

	printf("---------------------------------------\n");

#define TEST_INT(m) printf("%s: %d\n", #m, m)
	TEST_INT(ip->ip_v);
	TEST_INT(ip->ip_hl);
	TEST_INT(ntohs(ip->ip_len));
	TEST_INT(ip->ip_id);
	TEST_INT(ip->ip_off);
	TEST_INT(ip->ip_ttl);

	printf("ip->ip_p: %s\n", ip->ip_p == IPPROTO_UDP ? "udp" :
			(ip->ip_p == IPPROTO_TCP ? "tcp" : "unknown"));

#define TEST_IP(m) printf("%s: %d.%d.%d.%d\n", #m, \
		(m & 0xff000000) >> 24, (m & 0x00ff0000) >> 16, \
		(m & 0x0000ff00) >>  8, (m & 0x000000ff) >>  0);

	TEST_IP(ntohl(ip->ip_dst.s_addr));
	TEST_IP(ntohl(ip->ip_src.s_addr));
	TEST_INT(ip->ip_sum);

	TEST_INT(udp->uh_sport);
	TEST_INT(udp->uh_dport);
	TEST_INT(ntohs(udp->uh_ulen));
	TEST_INT(udp->uh_sum);

	printf("payload: %s\n", payload);
}
#endif

static bool
build_udp_packet(char *buf, int *pkt_size, uint64_t *seed)
{
	//struct ether_header *eh = (struct ether_header *)buf;
	struct ether_hdr *eh = (struct ether_hdr *)buf;
	struct ip *ip = (struct ip *)(eh + 1);
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	char *payload = (char *)(udp + 1);

	eh->d_addr.addr_bytes[0] = 0x00;
	eh->d_addr.addr_bytes[1] = 0x00;
	eh->d_addr.addr_bytes[2] = 0x00;
	eh->d_addr.addr_bytes[3] = 0x00;
	eh->d_addr.addr_bytes[4] = 0x00;
	eh->d_addr.addr_bytes[5] = 0x01;

	eh->s_addr.addr_bytes[0] = 0x00;
	eh->s_addr.addr_bytes[1] = 0x00;
	eh->s_addr.addr_bytes[2] = 0x00;
	eh->s_addr.addr_bytes[3] = 0x00;
	eh->s_addr.addr_bytes[4] = 0x00;
	eh->s_addr.addr_bytes[5] = 0x02;

	eh->ether_type = htons(ETHER_TYPE_IPv4);

	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;
	ip->ip_tos = IPTOS_LOWDELAY;
	/*
	 * x86/endian.h:
	 *
	 * #define __htonl(x)      __bswap32(x)
	 * #define __htons(x)      __bswap16(x)
	 * #define __ntohl(x)      __bswap32(x)
	 * #define __ntohs(x)      __bswap16(x)
	 *
	 * htonX() and ntohX() is same, so, it's easy to understand
	 * the ntohs() here.
	 */
	ip->ip_len = ntohs(*pkt_size - sizeof(*eh));
	ip->ip_id = 0;
	ip->ip_off = htons(IP_DF); /* Don't fragment */
	ip->ip_ttl = IPDEFTTL;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_dst.s_addr = htonl(0x0a0a0a01);
	ip->ip_src.s_addr = htonl(myrand(seed));
	ip->ip_sum = 0;

	udp->uh_sport = htons(myrand(seed));
	udp->uh_dport = htons(myrand(seed));
	udp->uh_ulen = htons(*pkt_size - sizeof(*eh) - sizeof(*ip));
	udp->uh_sum = 0;

	*(payload +  0) = 'h';
	*(payload +  1) = 'e';
	*(payload +  2) = 'l';
	*(payload +  3) = 'l';
	*(payload +  4) = 'o';
	*(payload +  5) = ',';
	*(payload +  6) = ' ';
	*(payload +  7) = 'w';
	*(payload +  8) = 'o';
	*(payload +  9) = 'r';
	*(payload + 10) = 'l';
	*(payload + 11) = 'd';
	*(payload + 12) = '.';
	*(payload + 13) = '\0';

	//dump_packet(buf, *pkt_size);

	return (true);
}

static bool
build_tcp_packet(char *buf, int *pkt_size,
		 __attribute__((unused)) uint64_t *seed)
{
	const unsigned lcore_id = rte_lcore_id();
	struct file_cache *fc = lcore_file_cache[lcore_id];

	struct pcap_pkthdr_ondisk {
		uint32_t ts_sec;
		uint32_t ts_usec;
		uint32_t caplen;
		uint32_t len;
	} *pcap_hdr;

	int32_t caplen;
	char *pktdata;

	if (fc->offset == fc->size) {
		printf("Send file %s complete\n", fc->filename);

		if (munmap(fc->fcache, fc->size) == -1) {
			fprintf(stderr, "munmap: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		fc = fc->next;
		if (fc == NULL) {
			printf("All trace files assigned to Lcore %u "
			       "are sent.\n", lcore_id);
			return (false);
		}

		lcore_file_cache[lcore_id] = fc;
	}

	pcap_hdr = (struct pcap_pkthdr_ondisk *)(fc->fcache + fc->offset);
	caplen = pcap_hdr->caplen;
	pktdata = (char *)(pcap_hdr + 1);

	fc->offset += sizeof(*pcap_hdr) + caplen;

	if (caplen > MAX_PKT_LEN) {
		fprintf(stderr, "Wrong packet length %u at offset %lu in %s\n",
			caplen, fc->offset, fc->filename);
		exit(EXIT_FAILURE);
	}

	if (fc->offset > fc->size) {
		fprintf(stderr, "Last packet is thrown away in %s\n",
			fc->filename);
		exit(EXIT_FAILURE);
	}

	*pkt_size = caplen;
	memcpy(buf, pktdata, caplen);

	return (true);
}

static inline void
ia32_pause(void)
{
	__asm __volatile("pause");
}

/* Main processing loop */
static int
main_loop(__attribute__((unused)) void *arg)
{
	const unsigned lcore_id = rte_lcore_id();
	int port_id = -1, queue_id = -1;
	int i;
	int num_cnt = 0;
	uint64_t seed = time(NULL) + lcore_id;
	bool looping = true;

	if (!((1ULL << lcore_id) & cores_mask)) {
		PRINT_INFO("Lcore %u has nothing to do (not configured)",
			   lcore_id);
		return (0);
	}

	if (func == TX && build_packet == build_tcp_packet &&
	    lcore_file_cache[lcore_id] == NULL) {
		PRINT_INFO("Lcore %u has nothing to do (no trace file "
			   "assigned)", lcore_id);
		return (0);
	}

	for (i = 0; i < nb_cores_conf; i++) {
		if (lcore_id == cores_conf[i].core_id) {
			port_id = cores_conf[i].port_id;
			queue_id = cores_conf[i].queue_id;
			break;
		}
	}

	if (port_id == -1)
		FATAL_ERROR("Configurations for lcore %u is not found",
			    lcore_id);

	port_ids[lcore_id] = port_id;
	queue_ids[lcore_id] = queue_id;

	gettimeofday(&last_time[lcore_id], NULL);

	if (func == RX) {
		PRINT_INFO("Lcore %u is reading from port %u, queue %u",
			   lcore_id, port_id, queue_id);
		fflush(stdout);
		/* Loop forever reading from NIC */
		for (;;) {
			struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
			unsigned i;
			const unsigned nb_rx =
				rte_eth_rx_burst(port_id, queue_id,
						 pkts_burst, PKT_BURST_SZ);
			lcore_stats[lcore_id].rx_pkts += nb_rx;
			for (i = 0; likely(i < nb_rx); i++) {
				struct rte_mbuf *m = pkts_burst[i];
				uint64_t len = rte_pktmbuf_data_len(m);
				lcore_stats[lcore_id].rx_bytes += len;
				//dump_packet(rte_pktmbuf_mtod(m, void *), len);
				rte_pktmbuf_free(m);
			}

			if (nb_rx != 0 && ++num_cnt == opt_interval) {
				lcore_stats[lcore_id].rx_total_pkts +=
					lcore_stats[lcore_id].rx_pkts;
				lcore_stats[lcore_id].rx_total_bytes +=
					lcore_stats[lcore_id].rx_bytes;
				update_rx_stats(num_cnt);
				lcore_stats[lcore_id].rx_pkts = 0;
				lcore_stats[lcore_id].rx_bytes = 0;
				num_cnt = 0;
			}
		}
	} else {
		PRINT_INFO("Lcore %u is writing to port %u, queue %u",
			   lcore_id, port_id, queue_id);
		fflush(stdout);
		/* Loop writing to NIC */
		while (likely(looping)) {
			int ret;
			int32_t burst_size = opt_burst_size;
			int32_t pkt_size = opt_pkt_size;
			struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
			struct rte_mbuf *m;
			struct rte_mbuf **mm;
			for (i = 0; i < burst_size; i++) {
				do {
					m = rte_pktmbuf_alloc(pktmbuf_pool);
				} while (unlikely(m == NULL));

				if (unlikely(!((*build_packet)(
						rte_pktmbuf_mtod(m, void *),
						&pkt_size, &seed)))) {
					rte_pktmbuf_free(m);
					burst_size = i;
					looping = false;
					break;
				}

				m->nb_segs = 1;
				m->next = NULL;
				m->pkt_len  = pkt_size;
				m->data_len = pkt_size;

				pkts_burst[i] = m;
				lcore_stats[lcore_id].tx_bytes += pkt_size;
			}
			lcore_stats[lcore_id].tx_pkts += burst_size;

			mm = pkts_burst;
			while (1) {
				/*
				 * Failed packets has to been resent.
				 * Because when sending pcap files,
				 * all packets should be sent correctly
				 * in order.
				 */
				ret = rte_eth_tx_burst(port_id, queue_id, mm,
						       burst_size);
				if (likely(ret == burst_size))
					break;
				mm += ret;
				burst_size -= ret;
				//lcore_stats[lcore_id].dropped++;
			}

			if (++num_cnt == opt_interval) {
				lcore_stats[lcore_id].tx_total_pkts +=
					lcore_stats[lcore_id].tx_pkts;
				lcore_stats[lcore_id].tx_total_bytes +=
					lcore_stats[lcore_id].tx_bytes;
				update_tx_stats(num_cnt);
				lcore_stats[lcore_id].tx_pkts = 0;
				lcore_stats[lcore_id].tx_bytes = 0;
				num_cnt = 0;
			}

			for (i = 0; unlikely(i < opt_loop_count); i++)
				ia32_pause();
		}
	}

	PRINT_INFO("Lcore %u has done the job, exiting.", lcore_id);
	return (0);
}

/* Display usage instructions */
static void
print_usage(const char *prgname)
{
	PRINT_INFO("\nUsage: %s [EAL options] -- -c config [-f tx|rx]\n"
		   "    -b burst size  : burst size\n"
		   "    -c config      : config file\n"
		   "    -f tx|rx       : tx or rx\n"
		   "    -h             : help\n"
		   "    -i interval    : interval between two stats updating\n"
		   "    -l loop count  : number of loops to loop after each tx\n"
		   "    -p packet size : packet size (udp only)\n"
		   "    -t tracelist   : trace file list\n",
		   prgname);
}

static bool
check_pcap(struct file_cache *fc)
{
	uint32_t *magic;

	magic = (uint32_t *)fc->fcache;
	if (*magic != 0xa1b2c3d4) {
		fprintf(stderr, "Magic number not match %x:%x\n",
			*magic, 0xa1b2c3d4);
		return (false);
	}

	memcpy(&fc->hdr, fc->fcache + fc->offset, sizeof(fc->hdr));
	fc->offset += sizeof(fc->hdr);

	if (fc->offset > fc->size) {
		fprintf(stderr, "Pcap file header is bigger than file size\n");
		return (false);
	}

	return (true);
}

static void
init_trace_file_cache(const char *tracefilelist)
{
	FILE *fp;
	char tracefilename[MAXPATHLEN];
	int rr = -1; /* Make sure rr begins from 0 */

	fp = fopen(tracefilelist, "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open %s: %s\n",
			tracefilelist, strerror(errno));
		exit(EXIT_FAILURE);
	}

	while (fgets(tracefilename, MAXPATHLEN, fp) != NULL) {
		struct file_cache *fc;
		int64_t size; /* XXX 'int' will overflow for 3GB files. */
		tracefilename[strlen(tracefilename)-1] = '\0'; /* strip '\n' */
		int fd = open(tracefilename, O_RDONLY);
		if (fd == -1) {
			fprintf(stderr, "Failed to open %s: %s\n",
				tracefilename, strerror(errno));
			exit(EXIT_FAILURE);
		}

		size = lseek(fd, 0, SEEK_END);
		if (size == -1) {
			fprintf(stderr, "Failed to seek to end %s: %s\n",
				tracefilename, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (lseek(fd, 0, SEEK_SET) == -1) {
			fprintf(stderr, "Failed to seek to 0 %s: %s\n",
				tracefilename, strerror(errno));
			exit(EXIT_FAILURE);
		}

		fc = malloc(sizeof(*fc));
		if (fc == NULL) {
			fprintf(stderr, "Failed to malloc filecache: %s\n",
				strerror(errno));
			exit(EXIT_FAILURE);
		}

		strcpy(fc->filename, tracefilename);

		fc->offset = 0;
		fc->size = size;

		fc->fcache = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (fc->fcache == MAP_FAILED) {
			fprintf(stderr, "Failed to mmap %s: %s\n",
				tracefilename, strerror(errno));
			exit(EXIT_FAILURE);
		}

		do {
			rr = (rr + 1) % RTE_MAX_LCORE;
		} while (!((1ULL << rr) & cores_mask));

		fc->next = lcore_file_cache[rr];
		lcore_file_cache[rr] = fc;

		printf("Load tracefile: %s done, which assigned to Lcore %d\n",
		       tracefilename, rr);

		if (!check_pcap(fc)) {
			fprintf(stderr, "Check pcap failed: %s\n",
				tracefilename);
			exit(EXIT_FAILURE);
		}

		close(fd);
	}

	fclose(fp);
}

static void
parse_config_file(const char *filename)
{
	FILE *fp;
	char buf[BUFSIZ];
	int i;

	if (access(filename, R_OK) == -1) {
		fprintf(stderr, "Failed to read from file %s: %s\n",
			filename, strerror(errno));
		exit(EXIT_FAILURE);
	}

	fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr," Failed to open %s: %s\n", filename,
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	while (fgets(buf, BUFSIZ, fp) != NULL) {
		int core_id, port_id, queue_id;
		int ret;

		char *p = strchr(buf, '#');
		if (p != NULL)
			*p = '\0';
#ifdef DEBUG_CONFIG_FILE
		printf("------------------------------\n");
		printf("parsed line: %s\n", buf);
#endif
		ret = sscanf(buf, "core_id=%d,port_id=%d,queue_id=%d",
			     &core_id, &port_id, &queue_id);
		if (ret != 3)
			continue;
#ifdef DEBUG_CONFIG_FILE
		printf("core_id = %d, port_id = %d, queue_id = %d\n",
		       core_id, port_id, queue_id);
#endif
		cores_conf[nb_cores_conf].core_id  = core_id;
		cores_conf[nb_cores_conf].port_id  = port_id;
		cores_conf[nb_cores_conf].queue_id = queue_id;

		nb_cores_conf++;
	}

	/* Parse cores and queues configuration */
	for (i = 0; i < nb_cores_conf; i++) {
		uint8_t core_id  = cores_conf[i].core_id;
		uint8_t port_id  = cores_conf[i].port_id;
		uint8_t queue_id = cores_conf[i].queue_id;

		cores_mask |= (1 << core_id);
		ports_mask |= (1 << port_id);
		queues_masks[port_id] |= (1 << queue_id);
	}
}

static void
dump_args(void)
{
	int i;

	putchar('\n');
	for (i = 0; i < 80; i++) putchar('#');
	putchar('\n');


	printf("burst size    : %d\n", opt_burst_size);
	printf("packet size   : %d\n", opt_pkt_size);

	if (func == RX)
		printf("function      : %s\n", "RX");
	else
		printf("function      : %s (%s)\n", "TX",
		       (build_packet == build_tcp_packet) ? "TCP" : "UDP");

	/*
	 * Dump configurations.
	 */
	printf("nb_cores_conf : %d\n", nb_cores_conf);
	printf("cores_conf    :");

	for (i = 0; i < nb_cores_conf; i++) {
		printf("%s{ .core_id = %d, .port_id = %d, .queue_id = %d }%s\n",
		       i == 0 ? " " : "                ",
		       cores_conf[i].core_id,
		       cores_conf[i].port_id,
		       cores_conf[i].queue_id,
		       i != nb_cores_conf - 1 ? "," : " }");
	}

	for (i = 0; i < 80; i++) putchar('#');
	putchar('\n');
	putchar('\n');
}

static void
sanity_check(void)
{
	bool failed = false;

	if (nb_cores_conf == 0) {
		fprintf(stderr, "Cores configuration file must be specified"
			" by '-c config'.\n");
		failed = true;
	}

	if (failed)
		exit(EXIT_FAILURE);
}

/* Parse the arguments given in the command line of the application */
static void
parse_args(int argc, char **argv)
{
	int opt;
	const char *prgname = argv[0];

	/* Disable printing messages within getopt() */
	opterr = 0;

	/* Parse command line */
	while ((opt = getopt(argc, argv, "b:c:f:i:l:p:t:h")) != -1) {
		switch (opt) {
		case 'b':
			sscanf(optarg, "%d", &opt_burst_size);
			break;

		case 'c':
			parse_config_file(optarg);
			if (tracefilelist[0] != '\0')
				init_trace_file_cache(tracefilelist);
			break;

		case 'f':
			if (strcmp(optarg, "tx") == 0)
				func = TX;
			else if (strcmp(optarg, "rx") == 0)
				func = RX;
			else {
				print_usage(prgname);
				FATAL_ERROR("Invalid option for -f specified");
			}
			break;

		case 'h':
			print_usage(prgname);
			exit(EXIT_SUCCESS);
			break;

		case 'i':
			sscanf(optarg, "%d", &opt_interval);
			break;

		case 'l':
			sscanf(optarg, "%d", &opt_loop_count);
			break;

		case 'p':
			sscanf(optarg, "%d", &opt_pkt_size);
			break;

		case 't':
			build_packet = build_tcp_packet;
			strcpy(tracefilelist, optarg);

			/*
			 * Assign trace file to cpu needs
			 * cores be configured.
			 */
			if (nb_cores_conf != 0)
				init_trace_file_cache(tracefilelist);
			break;

		default:
			print_usage(prgname);
			FATAL_ERROR("Invalid option %s specified", optarg);
		}
	}

	sanity_check();
	dump_args();
}

/* Initialise a single port on an Ethernet device */
static void
init_port(uint8_t port, uint8_t nb_queues)
{
	int ret;
	uint8_t queue;

	/* Initialise device and RX/TX queues */
	PRINT_INFO("Initialising port %u ...", (unsigned)port);
	fflush(stdout);

	ret = rte_eth_dev_configure(port, nb_queues, nb_queues, &port_conf);
	if (ret < 0)
		FATAL_ERROR("Could not configure port%u (%d)",
			    (unsigned)port, ret);

	for (queue = 0; queue < nb_queues; queue++) {
		if (!((1ULL << queue) & queues_masks[port]))
			FATAL_ERROR("Discrete queue configuration");

		ret = rte_eth_rx_queue_setup(port, queue, NB_RXD,
					     rte_eth_dev_socket_id(port),
					     NULL, pktmbuf_pool);
		if (ret < 0)
			FATAL_ERROR("Could not setup up RX queue for "
				    "port%u queue%u (%d)",
				    (unsigned)port, (unsigned)queue, ret);
	}

	for (queue = 0; queue < nb_queues; queue++) {
		if (!((1ULL << queue) & queues_masks[port]))
			FATAL_ERROR("Discrete queue configuration");

		ret = rte_eth_tx_queue_setup(port, queue, NB_TXD,
					     rte_eth_dev_socket_id(port),
					     NULL);
		if (ret < 0)
			FATAL_ERROR("Could not setup up TX queue for "
				    "port%u queue%u (%d)",
				    (unsigned)port, (unsigned)queue, ret);
	}

	ret = rte_eth_dev_start(port);
	if (ret < 0)
		FATAL_ERROR("Could not start port%u (%d)", (unsigned)port, ret);

	rte_eth_promiscuous_enable(port);
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
					       "Mbps - %s\n", (uint8_t)portid,
					       (unsigned)link.link_speed,
					       (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
							("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
					       (uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

/* Initialise ports/queues etc. and start main loop on each core */
int
main(int argc, char *argv[])
{
	int ret;
	int i;
	uint8_t nb_sys_ports, nb_queues;
	uint8_t port;
	uint8_t bit;

	/* Associate signal_hanlder function with USR signals */
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);
	signal(SIGINT, signal_handler);

	/* Initialise EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		FATAL_ERROR("Could not initialise EAL (%d)", ret);
	argc -= ret;
	argv += ret;

	rte_pdump_init(NULL);

	/* Parse application arguments (after the EAL ones) */
	parse_args(argc, argv);

	/* Create the mbuf pool */
	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
					       MBUF_CACHE_SIZE, 0,
					       RTE_MBUF_DEFAULT_BUF_SIZE,
					       rte_socket_id());
	if (pktmbuf_pool == NULL) {
		FATAL_ERROR("Could not initialise mbuf pool");
		return (-1);
	}

	/* Get number of ports found in scan */
	nb_sys_ports = rte_eth_dev_count();
	if (nb_sys_ports == 0)
		FATAL_ERROR("No supported Ethernet devices found");
	printf("number of ports: %d\n", nb_sys_ports);

	/* Initialise each port */
	for (port = 0; port < nb_sys_ports; port++) {
		/* Skip ports that are not enabled */
		if ((ports_mask & (1 << port)) == 0) {
			continue;
		}

		nb_queues = 0;
		for (bit = 0; bit < 8*sizeof(uint64_t); bit++)
		     nb_queues += ((queues_masks[port] >> bit) & 1);
		printf("number of queues enabled for port%u: %d\n",
		       port, nb_queues);

		init_port(port, nb_queues);
	}
	check_all_ports_link_status(nb_sys_ports, ports_mask);

	/* Launch per-lcore function on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(i) {
		if (rte_eal_wait_lcore(i) < 0)
			return (-1);
	}

	print_stats();

	rte_pdump_uninit();

	return (1);
}

