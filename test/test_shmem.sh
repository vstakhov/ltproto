#!/bin/sh

BSIZES="128 256 512 1024 8192 32768 65536 524288"
RING_SLOTS="32 64 128 256 512 1024"
RING_BUFFERS="1024 4096 8192 16384 32768"

for _bsize in $BSIZES ; do
        _rfile="/tmp/lt_shmem-$_bsize.dat"
        if [ F"$1" != F"-g" ] ; then
                rm -f $_rfile
                for _rslots in $RING_SLOTS ; do
                        _seq=""
                        for _rbuf in $RING_BUFFERS ; do
                                _seq="$_seq `LTPROTO_RING_SLOTS=$_rslots LTPROTO_RING_BUF=$_rbuf test/ltproto_test -t shmem_pipe -q -b $_bsize`"
                        done
                        echo $_seq >> $_rfile
                done
        fi
        python test/plot_shmem.py $_rfile "Shmem for $_bsize bytes blocks"
done
