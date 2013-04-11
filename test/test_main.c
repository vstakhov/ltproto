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
	printf ("Send buffer: 8Mb, Recv buffer: 1Mb; Transmitted 8Gb in %.6f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	assert (do_client (50009, 4 * 1024 * 1024, 2048, mod) != -1);
	msec = end_test_time (tdata);
	printf ("Send buffer: 4Mb, Recv buffer: 1Mb; Transmitted 8Gb in %.6f milliseconds\n", round_test_time (msec));

	kill (spid, SIGTERM);
}

typedef void (*alloc_test_func)(void **chunks, int chunks_count, int chunk_length);

static void
test_chunk_linear (void **chunks, int chunks_count, int chunk_length)
{
	int i, j;

	for (i = 0; i < chunks_count; i ++) {
		chunks[i] = ltproto_alloc (chunk_length);
		for (j = 0; j < i; j ++) {
			assert (chunks[i] != chunks[j]);
		}
	}
	for (i = 0; i < chunks_count; i ++) {
		ltproto_free (chunk_length, chunks[i]);
	}
}

static void
test_chunk_circular (void **chunks, int chunks_count, int chunk_length)
{
	int i, j;
	const int ring_length = 16;

	for (i = 0; i < chunks_count / ring_length; i ++) {
		for (j = 0 ; j < ring_length; j ++) {
			chunks[j] = ltproto_alloc (chunk_length);
		}
		for (j = 0 ; j < ring_length; j ++) {
			ltproto_free (chunk_length, chunks[j]);
		}
	}
}

static void
perform_allocator_test (const char *name, int num_chunks, alloc_test_func test_func)
{
	void **chunks;
	void *tdata;
	time_t msec;

	chunks = calloc (num_chunks, sizeof (void *));
	printf ("Test for `%s' allocator\n", name);

	start_test_time (&tdata);
	test_func (chunks, num_chunks, 512);
	msec = end_test_time (tdata);
	printf ("Check for 512 bytes chunks: %.6f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	test_func (chunks, num_chunks, 8 * 1024);
	msec = end_test_time (tdata);
	printf ("Check for 8K chunks: %.6f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	test_func (chunks, num_chunks, 32 * 1024);
	msec = end_test_time (tdata);
	printf ("Check for 32K chunks: %.6f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	test_func (chunks, num_chunks, 64 * 1024);
	msec = end_test_time (tdata);
	printf ("Check for 64K chunks: %.6f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	test_func (chunks, num_chunks, 512 * 1024);
	msec = end_test_time (tdata);
	printf ("Check for 512K chunks: %.6f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	test_func (chunks, num_chunks, 2000 * 1024);
	msec = end_test_time (tdata);
	printf ("Check for 2000K chunks: %.6f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	test_func (chunks, num_chunks, 100);
	msec = end_test_time (tdata);
	printf ("Check for 100 bytes chunks: %.6f milliseconds\n", round_test_time (msec));
}

static void
syscalls_test (void)
{
	void *tdata;
	u_char *map;
	time_t msec;
	key_t key;
	int fd, i, len, pages = 1024, psize = getpagesize (), shmid;
	struct shmid_ds shm_ds;

	len = pages * psize;
	// Check for shm related functions
	start_test_time (&tdata);
	fd = shm_open ("/perf_shm_open", O_RDWR | O_CREAT | O_EXCL, 00600);
	assert (fd != -1);
	msec = end_test_time (tdata);
	printf ("Shm open call: %lu nanoseconds\n", msec);

	start_test_time (&tdata);
	assert (ftruncate (fd, len) != -1);
	msec = end_test_time (tdata);
	printf ("Shm ftruncate to 4Mb: %lu nanoseconds\n", msec);

	start_test_time (&tdata);
	assert ((map = mmap (NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) != MAP_FAILED);
	msec = end_test_time (tdata);
	printf ("Shm mmap 4Mb: %lu nanoseconds\n", msec);

	start_test_time (&tdata);
	assert (mprotect (map, len, PROT_READ) != -1);
	msec = end_test_time (tdata);
	printf ("Shm mprotect 4Mb: %lu nanoseconds\n", msec);

	start_test_time (&tdata);
	for (i = 0; i < len; i += psize) {
		assert (mprotect (map + i, psize, PROT_WRITE) != -1);
	}
	msec = end_test_time (tdata);
	printf ("Shm %d mprotect 4Mb: %lu nanoseconds\n", pages, msec);

	start_test_time (&tdata);
	assert (mprotect (map, len, PROT_READ) != -1);
	msec = end_test_time (tdata);
	printf ("Shm mprotect 4Mb: %lu nanoseconds\n", msec);

	start_test_time (&tdata);
	munmap (map, len);
	msec = end_test_time (tdata);
	printf ("Shm munmap 4Mb: %lu nanoseconds\n", msec);

	close (fd);
	start_test_time (&tdata);
	shm_unlink ("/perf_shm_open");
	msec = end_test_time (tdata);
	printf ("Shm unlink: %lu nanoseconds\n", msec);

	// SysV memory
	key = rand ();
	start_test_time (&tdata);
	assert ((shmid = shmget (key, len, IPC_CREAT | IPC_EXCL | 00640)) != -1);
	msec = end_test_time (tdata);
	printf ("shmget: %lu nanoseconds\n", msec);

	start_test_time (&tdata);
	assert ((map = shmat (shmid, NULL, 0)) != (void *)-1);
	msec = end_test_time (tdata);
	printf ("shmat: %lu nanoseconds\n", msec);

	start_test_time (&tdata);
	assert (shmdt (map) != -1);
	msec = end_test_time (tdata);
	printf ("shmdt: %lu nanoseconds\n", msec);

	start_test_time (&tdata);
	assert (shmctl (shmid, IPC_RMID, &shm_ds) != -1);
	msec = end_test_time (tdata);
	printf ("shmctl: %lu nanoseconds\n", msec);
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

	syscalls_test ();
	/* Start a simple tests */
	assert (ltproto_switch_allocator ("system allocator") != -1);
	perform_allocator_test ("system", 10240, test_chunk_linear);
	assert (ltproto_switch_allocator ("linear allocator") != -1);
	perform_allocator_test ("linear", 10240, test_chunk_circular);
	//perform_module_test_simple ("null");
	perform_module_test_simple ("udp-shmem");

	ltproto_destroy ();

	return 0;
}
