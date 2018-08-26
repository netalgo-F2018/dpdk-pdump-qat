#!/bin/bash

set -ueo pipefail

CALGARY_URL=http://www.data-compression.info/files/corpora/largecalgarycorpus.zip

function gen_calgary
{
    wget -O /tmp/largecalgary.zip $CALGARY_URL && \
        unzip -c /tmp/largecalgary.zip "*" > calgary && \
        rm /tmp/largecalgary.zip
}

function gen_calgary1G
{
    local calgary_sz=$(du calgary | awk '{ print $1 }')
    local nr_repeats=$(($((1*1024*1024)) / calgary_sz))

    for _ in $(seq 1 $nr_repeats); do
        cat calgary >> calgary1G
    done
}

test -e calgary || gen_calgary
test -e calgary1G || gen_calgary1G

exit 0
