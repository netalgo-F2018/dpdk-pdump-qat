#!/bin/bash
#
# Architecture overview:
#
#   ALICE (remote)                          BOB (local)
# |---------------|                     |--------|-------|
# |     PKTGEN    |-10Gbps UDP traffic->| RECVER + PDUMP |
# |---------------|                     |--------^-------|
#         ^                             | ./this_script  |
#         |                             |--------|-------|
#         |--------------------------------------|
#

set -ueo pipefail

NR_LOOP=${NR_LOOP:-0}
CMD=${1:-test}
ALICE=${2:-qat0}
BOB=${3:-qat1}

function app_echo
{
    local msg=${1:-}
    echo "$(hostname): TEST_DPDK_PDUMP.SH: $msg"
}

function print_usage_then_die
{
    app_echo "Usage: $0 <command> <sender> <receiver>"
    exit 1
}

app_echo "Do execute cmd: env NR_LOOP=$NR_LOOP $0 $CMD $ALICE $BOB"

mkdir -p output

function tell_synopsis
{
    test -e output/pktgen_tx.log && test -e output/pktgen_rx.log && test -e output/pdump.log

    echo -e "Total sent:     $(cat output/pktgen_tx.log | grep "Total" | tail -n1 | awk -F' ' '{ print $4 }')"
    echo -e "Total received: $(cat output/pktgen_rx.log | grep "Total" | tail -n1 | awk -F' ' '{ print $4 }')"
    cat output/pdump.log | grep -A4 "STATS" | tail -n4

}

function tell_performance
{
    echo -n "Flow speed: "
    echo -e $(cat output/pktgen_tx.log | grep -Eo "[0-9]+.[0-9]+ Gbps" | tail -n1)

    local total_received=$(cat output/pktgen_rx.log | grep "Total" | tail -n1 | awk -F' ' '{ print $4 }')
    local total_dequeued=$(cat output/pdump.log | grep dequeued | tail -n1 | grep -Eo "[0-9]+")
    local loss=$(awk "BEGIN { print ($total_received - $total_dequeued) / $total_received }")
    echo -e "Total received: $total_received"
    echo -e "Total dequeued: $total_dequeued"
    echo -e "Loss: $loss"
    [[ "$loss" = "0" ]] && echo Great! || echo Try more parameters...
}

function run_test
{
    echo -e "\n\n\n===STAGE X: benchmark start"

    # \begin test
    test -e remote_run && test -e pdumpd.sh && test -e receiverd.sh && test -e issue_traffic.sh

    echo -e "\n\n\n===STAGE 0: run receiverd"
    bash receiverd.sh restart
    echo -e "\n\n\n===STAGE 1: run pdumpd"
    bash pdumpd.sh restart /dev/null
    echo -e "\n\n\n===STAGE 2: issue traffic"
    bash remote_run $ALICE issue_traffic.sh $NR_LOOP
    # \end test

    # \begin clean resources
    echo -e "\n\n\n===STAGE 3: kill all detached jobs"
    bash  pdumpd.sh stop
    bash  receiverd.sh stop
    # \end clean resources

    # \begin collect log and then do some analysis
    echo -e "\n\n\n===STAGE 4: collect logs"
    scp $ALICE:/var/log/pktgen_tx.log output/pktgen_tx.log
    scp /var/log/pktgen_rx.log output/pktgen_rx.log
    scp /var/log/pdump.log output/pdump.log

    echo -e "\n\n\n===STAGE 4: parse logs and give synopsis"
    tell_synopsis
    # \end collect log and then do some analysis

    # \begin tell your performance
    echo -e "\n\n\n===STAGE 5: tell your performance"
    tell_performance
    # \end tell your performance

    echo -e "\n\n\n===STAGE Y: benchmark end"
}

case $CMD in
    test)
        run_test
        ;;
    *)
        print_usage_then_die
esac

exit 0
