/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "ltproto.h"
#include "ltproto_internal.h"
#include "test_utils.h"
#include <assert.h>

sig_atomic_t got_usr1 = 0;

static void
usr1_handler (int signo)
{
	got_usr1 = 1;
}

static int
wait_for_server (void)
{
	sigset_t sigmask;

	sigemptyset (&sigmask);

	for (;;) {
		if (got_usr1) {
			got_usr1 = 0;
			return 0;
		}
		sigsuspend (&sigmask);
	}

	return -1;
}

static void
perform_module_test_simple (const char *mname)
{
	pid_t spid;
	void *tdata, *mod;
	time_t msec;

	printf ("Test for module: %s\n", mname);
	fflush (stdout);
	mod = ltproto_select_module (mname);
	spid = fork_server (50009, 1024 * 1024, mod);
	assert (spid != -1);
	wait_for_server ();
	start_test_time (&tdata);
	assert (do_client (50009, 8 * 1024 * 1024, 1024, mod) != -1);
	msec = end_test_time (tdata);
	printf ("Send buffer: 8Mb, Recv buffer: 1Mb; Transmitted 8Gb in %.3f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	assert (do_client (50009, 4 * 1024 * 1024, 2048, mod) != -1);
	msec = end_test_time (tdata);
	printf ("Send buffer: 4Mb, Recv buffer: 1Mb; Transmitted 8Gb in %.3f milliseconds\n", round_test_time (msec));

	kill (spid, SIGTERM);
}

static void
test_chunk_size (void **chunks, int chunks_count, int chunk_length)
{
	int i;

	for (i = 0; i < chunks_count; i ++) {
		chunks[i] = ltproto_alloc (chunk_length);
	}
	for (i = 0; i < chunks_count; i ++) {
		ltproto_free (chunk_length, chunks[i]);
	}
}

static void
perform_allocator_test (int num_chunks)
{
	void **chunks;
	void *tdata;
	time_t msec;

	chunks = calloc (num_chunks, sizeof (void *));
	printf ("Test for allocator\n");

	start_test_time (&tdata);
	test_chunk_size (chunks, num_chunks, 8 * 1024);
	msec = end_test_time (tdata);
	printf ("Linear alloc/free for 8K chunks: %.3f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	test_chunk_size (chunks, num_chunks, 32 * 1024);
	msec = end_test_time (tdata);
	printf ("Linear alloc/free for 32K chunks: %.3f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	test_chunk_size (chunks, num_chunks, 64 * 1024);
	msec = end_test_time (tdata);
	printf ("Linear alloc/free for 64K chunks: %.3f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	test_chunk_size (chunks, num_chunks, 512 * 1024);
	msec = end_test_time (tdata);
	printf ("Linear alloc/free for 512K chunks: %.3f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	test_chunk_size (chunks, num_chunks, 2000 * 1024);
	msec = end_test_time (tdata);
	printf ("Linear alloc/free for 2000K chunks: %.3f milliseconds\n", round_test_time (msec));
}

int
main (int argc, char **argv)
{

	sigset_t sigmask;
	struct sigaction sa;

	sigemptyset (&sigmask);
	sigaddset (&sigmask, SIGUSR1);
	memset (&sa, 0, sizeof (sa));
	sa.sa_mask = sigmask;
	sa.sa_handler = usr1_handler;
	sigaction (SIGUSR1, &sa, NULL);

	ltproto_init ();

	/* Start a simple tests */
	perform_allocator_test (1024);
	//perform_module_test_simple ("null");
	perform_module_test_simple ("udp-shmem");

	ltproto_destroy ();

	return 0;
}
