#!/bin/bash

#PKTGEN_DIR=/root/workspace/dpdk-pktgen/
PKTGEN_DIR=/opt/dpdk-pktgen/

NR_LOOP=${1:-0}

function app_echo
{
    local msg=${1:-}
    echo "$(hostname): ISSUE_TRAFFIC.SH: $msg"
}

cd $PKTGEN_DIR

stdbuf -o0 ./build/pktgen -- -c config -f tx -b 5 -p 60 -l $NR_LOOP > /var/log/pktgen_tx.log 2>&1 & pktgen_pid=$!
stdbuf -i0 tail -f /var/log/pktgen_tx.log & tail_pid=$!

app_echo "Sending packets over UDP..." && sleep 30 && kill -INT $pktgen_pid && kill $tail_pid
app_echo "Done!"

exit 0
