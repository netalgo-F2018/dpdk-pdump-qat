#!/bin/bash

set -euo pipefail

RTE_TARGET=build
RTE_SDK=$(pwd)/DPDK
PCAP_CALGARY_1G=calgary1G.pcap
TESTPMD=$RTE_SDK/$RTE_TARGET/app/testpmd 
CALGARY_URL=http://www.data-compression.info/files/corpora/largecalgarycorpus.zip

function gen_calgary3M
{
    local temp_calgary_zip=$(mktemp)
    wget -O $temp_calgary_zip $CALGARY_URL && \
        unzip -c $temp_calgary_zip "*" > calgary3M && \
        rm -f $temp_calgary_zip
}

function gen_calgary1G
{
    test -e gen_calgary3M || gen_calgary3M

    local calgary_sz=$(du calgary3M | awk '{ print $1 }')
    local nr_repeats=$(($((1*1024*1024)) / calgary_sz))

    for _ in $(seq 1 $nr_repeats); do
        cat calgary3M >> calgary1G
    done
}

# Convert raw data into pcap file through `lo`
function gen_pcap
{
    local dataset_id=$1

    test -e ${dataset_id} || echo "${dataset_id} doesn't exist"

    ip link set dev lo mtu 1500

    python -m SimpleHTTPServer 65535 --bind 127.0.0.1 & http_server_pid=$!
    # Refer to https://askubuntu.com/questions/746029/how-to-start-and-kill-tcpdump-within-a-script
    rm -f ${dataset_id}.pcap
    tcpdump -U -i lo -s 1500 -w ${dataset_id}.pcap 'port 65535' & tcpdump_pid=$!
    sleep 3

    wget -qO /dev/null http://127.0.0.1:65535/${dataset_id}
    sleep 10

    kill $http_server_pid
    sleep 5
    kill -INT $tcpdump_pid
}

test -e $PCAP_CALGARY_1G || ((test -e calgary1G || gen_calgary1G) && gen_pcap calgary1G)

$TESTPMD -c 0xf -n 4 --no-pci --vdev 'eth_pcap0,rx_pcap=calgary1G.pcap,tx_pcap=calgary1G.pcap.gz' -- --port-topology=chained --stats-period=1 & testpmd_pid=$!
#$TESTPMD -c 0xf -n 4 --vdev 'eth_pcap0,rx_pcap=calgary1G.pcap,tx_pcap=calgary1G.pcap.gz' -- --portmask=0x1 --port-topology=chained --stats-period=1 & testpmd_pid=$!
sleep 10
kill -INT $testpmd_pid

(test -e calgary1G.pcap.gz && zcat calgary1G.pcap.gz > calgary1G.pcap.gz.pcap && capinfos calgary1G.pcap.gz.pcap) || echo Failed to unzip calgary1G.pcap.gz

exit 0
