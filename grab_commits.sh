#!/bin/sh

if [ $# -eq 0 ]; then
    echo usage: grab_commits bro_src_dir
    exit 1
fi

C=$PWD/commits.txt
cd $1 && git rev-list --format=format:%ci master|grep ^comm | cut -d " " -f 2 > $C
