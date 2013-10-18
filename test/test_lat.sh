#!/bin/sh


if [ $# -ge 1 ] ; then
	NPROC=$1
else
	if [ -x "/usr/bin/nproc" ] ; then
		NPROC=$(nproc)
	elif [ -x "/usr/bin/getconf" ] ; then
		NPROC=$(getconf NPROCESSORS_ONLN)
	else
		echo "Cannot detect the number of cores"
		exit 1
	fi
fi

TYPES="null pipe unix shmem shmem_busy shmem_sleep shmem_pipe"
TFILE="/tmp/ltproto_lat"

MAX=$((($NPROC) * ($NPROC)))


for _type in $TYPES ; do
	_cnt=0
	rm $TFILE.$_type
	echo "Testing $_type"
	for i in `seq 0 $(($NPROC - 1))` ; do
		for j in `seq 0 $(($NPROC - 1))` ; do
			_cnt=$(($_cnt + 1))
			echo -n "Completed: $((100 * $_cnt / $MAX))%     \r"
			_sec="$_sec `test/ltproto_test -t $_type -l -q -c $i,$j`"
		done
		echo $_sec >> $TFILE.$_type
		_sec=""
	done
	python test/plot_lat.py /tmp/ltproto_lat.$_type $_type
	echo "Done"
done
