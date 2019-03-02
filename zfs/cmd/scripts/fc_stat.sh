#!/bin/bash

DATA_DIR="/proc/spl/kstat/stmf"
TARGET_FILE="/tmp/target.tmp"
function stat_main()
{
#   echo "name      nread    nwritten reads    writes   wtime    wlentime wupdate  rtime    rlentime rupdate  wcnt     rcnt"
    rm -f ${TARGET_FILE}
    touch ${TARGET_FILE}
    local tgts=`ls $DATA_DIR |grep "stmf_tgt_f"`
    for tgt in $tgts
    do
        local tgt_id=`echo "$tgt" |awk -F'_' '{print $3}'`
        local tgt_name=`grep 'target-name' $DATA_DIR/$tgt |awk '{print $3}'`
        local tgt_data=`sed -n 3p $DATA_DIR/stmf_tgt_io_${tgt_id}`
        echo "${tgt_name} ${tgt_data}">>${TARGET_FILE}
    done
}
stat_main
