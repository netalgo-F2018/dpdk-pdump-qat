#!/bin/bash

set -ueo pipefail

CALGARY_URL=http://www.data-compression.info/files/corpora/largecalgarycorpus.zip

function gen_calgary3M
{
    TMP_CALGARY_ZIP=$(mktemp)
    wget -O $TMP_CALGARY_ZIP $CALGARY_URL && \
        unzip -c $TMP_CALGARY_ZIP "*" > calgary3M && \
        rm -f $TMP_CALGARY_ZIP
}

function gen_calgary1G
{
    local calgary_sz=$(du calgary3M | awk '{ print $1 }')
    local nr_repeats=$(($((1*1024*1024)) / calgary_sz))

    for _ in $(seq 1 $nr_repeats); do
        cat calgary3M >> calgary1G
    done
}

test -e calgary3M || gen_calgary3M
test -e calgary1G || gen_calgary1G

exit 0
