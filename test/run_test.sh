#!/bin/sh

LT_TEST="`dirname $0`/ltproto_test"
SIZES="8 16 32 64 128 256 512 1024"
TEST_FILE="/tmp/ltproto_test.dat"
TEST_OUTPUT="/tmp/ltproto_test"
OUTPUT_EXTENSION="pdf"

if [ F"$1" != F"-g" ] ; then

	unlink $TEST_FILE 2> /dev/null
	unlink $TEST_FILE.binded 2> /dev/null

	for _sz in $SIZES ; do
		pkill -9 ltproto
		_data=$($LT_TEST -q -b "$_sz"K | tr '\n' '\t')
		echo "$_sz	$_data" >> $TEST_FILE
	done

	for _sz in $SIZES ; do
		pkill -9 ltproto
		_data=$($LT_TEST -c -q -b "$_sz"K | tr '\n' '\t')
		echo "$_sz	$_data" >> $TEST_FILE.binded
	done
fi

gnuplot << EOF
set terminal pdfcairo
set output "$TEST_OUTPUT.$OUTPUT_EXTENSION"
rate(x)=8.*1024./x*1000000000.
set autoscale
set xtics 8 2
set ytic auto
set title "LTproto test unbinded"
set xlabel "Block size (kilobytes)"
set ylabel "Throughtput (Mb/s)"
set xrange [8:1024]
set logscale x
plot	"$TEST_FILE" using 1:(rate(\$2)) title 'TCP' w linespoints, \
	"$TEST_FILE" using 1:(rate(\$3)) title 'Unix sockets' w linespoints, \
	"$TEST_FILE" using 1:(rate(\$4)) title 'UDP-shmem' w linespoints, \
	"$TEST_FILE" using 1:(rate(\$5)) title 'Unix-shmem' w linespoints
set title "LTproto test binded to CPU"
plot	"$TEST_FILE.binded" using 1:(rate(\$2)) title 'TCP' w linespoints, \
	"$TEST_FILE.binded" using 1:(rate(\$3)) title 'Unix sockets' w linespoints, \
	"$TEST_FILE.binded" using 1:(rate(\$4)) title 'UDP-shmem' w linespoints, \
	"$TEST_FILE.binded" using 1:(rate(\$5)) title 'Unix-shmem' w linespoints
EOF

