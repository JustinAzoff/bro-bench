#!/bin/sh

if [ $# -eq 0 ]; then
    C=$PWD/commits.txt
    (cd ~/src/bro; git rev-list --format=format:%ci HEAD|fgrep comm | cut -d " " -f 2 > $C)

    ssh -t bromanager sudo ssh broworker cat /usr/local/bench/data.csv | \
    ./commit_sort.py | \
    fgrep -v ,0, > data.csv
fi



gnuplot <<END
set terminal png size 1024,768
set yrange [0:]
set output "bro.png"
set ylabel "instructions"
set datafile separator ","

#set xdata time
#set timefmt "%s"
#set timefmt "%Y-%m-%d %H:%M:%S -0800"
#set format x "%m/%d"

everytenth(col) = (int(column(col))%40 ==0)?substr(stringcolumn(2),6,10):""

set multiplot layout 2, 1 ;

set ylabel "seconds"
set yrange [6:]
plot "data.csv" using 0:4:xtic(everytenth(0)) with linespoints title "Seconds"

set ylabel "instructions"
set yrange [30000000000.0:]
plot "data.csv" using 0:5:xtic(everytenth(0)) with linespoints title "Instructions"

unset multiplot
END
open bro.png
