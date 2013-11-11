#!/bin/sh


# Detect echo command
echo -e test | grep -- '-e' > /dev/null
if [ $? -eq 0 ] ; then
	ECHO="echo -n"
else
	echo -e -n test | grep -- '-n' > /dev/null
	if [ $? -eq 0 ] ; then
		ECHO="echo -e"
	else
		ECHO="echo -e -n"
	fi
fi

TESTS_ENABLED="null pipe unix shmem_sleep shmem_pipe"

get_nproc ( ) 
{
	if [ $# -ge 1 ] ; then
        NPROC=$1
	else
        if [ -x "/usr/bin/nproc" ] ; then
                NPROC=$(nproc)
        elif [ -x "/usr/bin/getconf" ] ; then
                NPROC=$(getconf NPROCESSORS_ONLN)
				if [ $? -ne 0 ] ; then
					NPROC=$(getconf _NPROCESSORS_ONLN)
				fi
        else
                echo "Cannot detect the number of cores"
                exit 1
        fi
	fi
}

draw_progress ( )
{
	local _i=$1
	local _j=$2
	local _count=$3
	local _max=$4

	$ECHO "Cores $_i -> $_j; Completed: $((100 * $_count / $_max))%     \r"
}
