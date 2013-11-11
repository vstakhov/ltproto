#!/bin/sh

. `dirname $0`/common.sh

get_nproc

TFILE="/tmp/ltproto_lat"

MAX=$((($NPROC) * ($NPROC)))


for _type in $TESTS_ENABLED ; do
	_cnt=0
	rm $TFILE.$_type
	echo "Testing $_type"
	for i in `seq 0 $(($NPROC - 1))` ; do
		for j in `seq 0 $(($NPROC - 1))` ; do
			_cnt=$(($_cnt + 1))
			draw_progress $i $j $_cnt $MAX
			_sec="$_sec `test/ltproto_test -t $_type -l -q -c $i,$j`"
		done
		echo $_sec >> $TFILE.$_type
		_sec=""
	done
	python test/plot_lat.py /tmp/ltproto_lat.$_type $_type
	echo "Done"
done
