Work in progress benchmark tool.

Usage
=====

    Usage: bench.py [options]

    Options:
      -h, --help            show this help message and exit
      -d DATA, --data=DATA  data file
      -s SRC, --src=SRC     src dir
      -t TMP, --tmp=TMP     tmp dir
      -p PCAPS, --pcap=PCAPS
                            pcaps
      -l SCRIPTS, --load=SCRIPTS
                            scripts


Example usage
=============

    ./bench.py -s /tmp/src/bro/ -t /tmp/bro/ \
        -p traces/net-2009-11-18-10:32.pcap \
        -p traces/net-2009-11-20-10:30.pcap \
        -p traces/net-2009-11-30-16:54.pcap \
        -p traces/net-2009-12-09-11:59.pcap \
        -l bench.bro \
        -d m57_local.csv

Tips
====

* Install ccache
* Put all src and tmp dirs on tmpfs
