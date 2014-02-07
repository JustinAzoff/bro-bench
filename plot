#!/bin/sh

F=$1

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
plot "$F" using 0:4:xtic(everytenth(0)) with linespoints title "Seconds"

set ylabel "instructions"
set yrange [40000000000.0:]
plot "$F" using 0:5:xtic(everytenth(0)) with linespoints title "Instructions"

unset multiplot
END
