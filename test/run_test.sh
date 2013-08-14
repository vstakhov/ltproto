#!/bin/sh

LT_TEST="`dirname $0`/ltproto_test"
SIZES="128 256 512 1024 8192 32768 65536 524288"
TEST_FILE="/tmp/ltproto_test.dat"
TEST_OUTPUT="/tmp/ltproto_test"
OUTPUT_EXTENSION="pdf"

if [ F"$1" != F"-g" ] ; then

        unlink $TEST_FILE 2> /dev/null
        unlink $TEST_FILE.binded 2> /dev/null
        unlink $TEST_FILE.dbinded 2> /dev/null

        for _sz in $SIZES ; do
                pkill -9 ltproto
                _data=$($LT_TEST -q -b "$_sz" | tr '\n' '\t')
                echo "$_sz      $_data" >> $TEST_FILE
        done

        for _sz in $SIZES ; do
                pkill -9 ltproto
                _data=$($LT_TEST -c same -q -b "$_sz" | tr '\n' '\t')
                echo "$_sz      $_data" >> $TEST_FILE.binded
        done

#       for _sz in $SIZES ; do
#               pkill -9 ltproto
#               _data=$($LT_TEST -c different -q -b "$_sz" | tr '\n' '\t')
#               echo "$_sz      $_data" >> $TEST_FILE.dbinded
#       done

        for _sz in $SIZES ; do
                pkill -9 ltproto
                _data=$($LT_TEST -v -q -b "$_sz" | tr '\n' '\t')
                echo "$_sz      $_data" >> $TEST_FILE.verified
        done

fi

TICS=$(echo ${SIZES} | tr ' ' ',')
START_X=$(echo ${SIZES} | cut -d ' ' -f1)
END_X=$(echo ${SIZES} | awk '{print $NF}')

gnuplot << EOF
set terminal pdfcairo
set output "$TEST_OUTPUT.$OUTPUT_EXTENSION"
rate(x)=(8589934592. * 8 / x) / (1024 * 1024) * (1000000000.)
set format x "%.0s%c" 
set format y "%.0s%c" 
set autoscale
set xtics (${TICS})
set ytic auto
set title "LTproto test unbinded"
set xlabel "Block size (bytes)"
set ylabel "Throughtput (Mbits/s)"
set xrange [$START_X:$END_X]
set logscale x
plot    "$TEST_FILE" using 1:(rate(\$2)) title 'TCP' w linespoints, \
        "$TEST_FILE" using 1:(rate(\$3)) title 'Unix sockets' w linespoints, \
        "$TEST_FILE" using 1:(rate(\$4)) title 'Pipe' w linespoints, \
        "$TEST_FILE" using 1:(rate(\$5)) title 'Shmem-futex' w linespoints, \
        "$TEST_FILE" using 1:(rate(\$6)) title 'Shmem-sleep' w linespoints
set title "LTproto test binded to a same CPU core"
plot    "$TEST_FILE.binded" using 1:(rate(\$2)) title 'TCP' w linespoints, \
        "$TEST_FILE.binded" using 1:(rate(\$3)) title 'Unix sockets' w linespoints, \
        "$TEST_FILE.binded" using 1:(rate(\$4)) title 'Pipe' w linespoints, \
        "$TEST_FILE.binded" using 1:(rate(\$5)) title 'Shmem-futex' w linespoints, \
        "$TEST_FILE.binded" using 1:(rate(\$6)) title 'Shmem-sleep' w linespoints
set title "LTproto test with checksum verifying"
plot    "$TEST_FILE.verified" using 1:(rate(\$2)) title 'TCP' w linespoints, \
        "$TEST_FILE.verified" using 1:(rate(\$3)) title 'Unix sockets' w linespoints, \
        "$TEST_FILE.verified" using 1:(rate(\$4)) title 'Pipe' w linespoints, \
        "$TEST_FILE.verified" using 1:(rate(\$5)) title 'Shmem-futex' w linespoints, \
        "$TEST_FILE.verified" using 1:(rate(\$6)) title 'Shmem-sleep' w linespoints
EOF

