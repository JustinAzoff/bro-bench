Work in progress benchmark tool.

Usage
=====

    Options:
      -h, --help            show this help message and exit
      -d DATA, --data=DATA  data file
      -s SRC, --src=SRC     src dir
      -i INST, --inst=INST  install dir
      -t TMP, --tmp=TMP     tmp dir
      -p PCAPS, --pcap=PCAPS
                            pcaps
      -l SCRIPTS, --load=SCRIPTS
                            scripts
      -b BISECT, --bisect=BISECT
                            bisect mode, set to seconds or instructions threshold
      -f, --fastbisect      uses data file for bisecting


Example usage
=============

    ./bench.py -s /tmp/src/bro/ -t /tmp/bro/ \
        -p traces/net-2009-11-18-10:32.pcap \
        -p traces/net-2009-11-20-10:30.pcap \
        -p traces/net-2009-11-30-16:54.pcap \
        -p traces/net-2009-12-09-11:59.pcap \
        -l bench.bro \
        -d m57_local.csv

Bisect mode
===========

Ran with --bisect it can be used with git-bisect run.  The -f option (fast
bisect) will use timing information saved in the data file to avoid testing the
same revisions.


Tips
====

* Install ccache
* Put all src and tmp dirs on tmpfs
