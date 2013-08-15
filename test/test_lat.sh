#!/bin/sh


if [ $# -ge 1 ] ; then
	NPROC=$1
else
	NPROC=$(nproc)
fi

TYPES="null unix shmem shmem_sleep"
TFILE="/tmp/ltproto_lat"

for _type in $TYPES ; do
	rm $TFILE.$_type
	for i in `seq 0 $(($NPROC - 1))` ; do
		for j in `seq 0 $(($NPROC - 1))` ; do
			_sec="$_sec `test/ltproto_test -t $_type -l -q -c $i,$j`"
		done
		echo $_sec >> $TFILE.$_type
		_sec=""
	done
	python test/plot_lat.py /tmp/ltproto_lat.$_type $_type
done
