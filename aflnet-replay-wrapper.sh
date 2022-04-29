#!/bin/bash

# This is for bftpd only; deletes the ftp directory before every replayed test case.

if [ "$#" -ne 2 ]; then
    echo "You must enter exactly 2 command line arguments"
    exit
fi

pkill bftpd
/home/prober/clean.sh
aflnet-replay-paireval-others $1 $2 FTP 21 &
timeout -k 0 20s /home/ubuntu/experiments/bftpd/bftpd -D -c /home/prober/samples/eval/basic.conf