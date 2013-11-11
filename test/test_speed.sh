#!/bin/sh

. `dirname $0`/common.sh

get_nproc

TFILE="/tmp/ltproto_speed"
MAX=$((($NPROC) * ($NPROC)))
_cnt=0

for _type in $TESTS_ENABLED ; do
        rm $TFILE.$_type
		echo "Testing $_type"
		_cnt=0
        for i in `seq 0 $(($NPROC - 1))` ; do
                for j in `seq 0 $(($NPROC - 1))` ; do
						_cnt=$(($_cnt + 1))
						draw_progress $i $j $_cnt $MAX
                        _sec="$_sec `test/ltproto_test -t $_type -q -c $i,$j -b 8k -s 1G`"
                done
                echo $_sec >> $TFILE.$_type
                _sec=""
        done
        python test/plot_speed.py /tmp/ltproto_speed.$_type $_type
		echo "Done"
done
