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
#include <sys/wait.h>


static sig_atomic_t got_usr1 = 0;
static int compact = 0;

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
perform_module_test_simple (const char *mname, unsigned long buflen, uint64_t bytes,
		int server_core, int client_core, int numa_node, int strict_check)
{
	pid_t spid, cpid;
	void *tdata, *mod;
	uint64_t msec;
	short port;
	int res;

	if (!compact) {
		printf ("Test for module: %s\n", mname);
	}
	fflush (stdout);
	port = 31119;
	mod = ltproto_select_module (mname);
	spid = fork_server (port, buflen, bytes / (uint64_t)buflen, mod, server_core, numa_node, strict_check, mname);
	assert (spid != -1);
	wait_for_server ();
	cpid = fork ();
	if (cpid == 0) {
		bind_to_core (client_core, numa_node);
		start_test_time (&tdata);
		assert (do_client (port, buflen, bytes / (uint64_t)buflen, mod, mname, strict_check) != -1);
		msec = end_test_time (tdata);
		if (!compact) {
			printf ("Send buffer: %s, ", print_bytes (buflen));
			printf ("Recv buffer: %s; ", print_bytes (buflen));
			printf ("Transmitted %s in ", print_bytes (bytes));
			printf ("%.6f milliseconds, ", round_test_time (msec));
			printf ("%s/sec transfer speed\n", print_bytes (bytes / (msec / 1000000000.)));
		}
		else {
			printf ("%llu\n", (long long unsigned)msec);
		}
		ltproto_destroy ();
		exit (EXIT_SUCCESS);
	}

#if 0
	start_test_time (&tdata);
	assert (do_client (50009, 4 * 1024 * 1024, 2048, mod) != -1);
	msec = end_test_time (tdata);
	printf ("Send buffer: 4Mb, Recv buffer: 4Mb; Transmitted 8Gb in %.6f milliseconds\n", round_test_time (msec));
#endif
	waitpid (cpid, &res, 0);
	waitpid (spid, &res, 0);
}

static int
uint64_cmp (const void *a, const void *b)
{
	const uint64_t *ia = a, *ib = b;

	return (*ia - *ib);
}

static void
perform_module_test_latency (const char *mname,
		int server_core, int client_core, int numa_node)
{
	pid_t spid, cpid;
	void *tdata, *mod;
	uint64_t *msec;
	short port;
	int i, res;
	const int cycles = 64;

	if (!compact) {
		printf ("Test for module: %s\n", mname);
	}
	fflush (stdout);

	msec = mmap (NULL, cycles * sizeof (msec[0]), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	for (i = 0; i < cycles; i ++) {
		port = 31119;
		mod = ltproto_select_module (mname);
		spid = fork_server_latency (port, mod, server_core, numa_node);
		assert (spid != -1);
		wait_for_server ();
		cpid = fork ();
		if (cpid == 0) {
			bind_to_core (client_core, numa_node);
			start_test_time (&tdata);
			assert (do_client_latency (port, mod, mname, &msec[i]) != -1);
			kill (spid, SIGTERM);
			ltproto_destroy ();
			exit (EXIT_SUCCESS);
		}
		else {
			waitpid (spid, &res, 0);
			waitpid (cpid, &res, 0);
		}
	}

	qsort (msec, cycles, sizeof (msec[0]), uint64_cmp);

	if (!compact) {
		printf ("Latency: %s\n", print_nanoseconds (msec[cycles/2]));
	}
	else {
		printf ("%ju\n", (uintmax_t)msec[cycles/2]);
	}

	fflush (stdout);
	munmap (msec, cycles * sizeof (msec[0]));

}

typedef void (*alloc_test_func)(void **chunks, int chunks_count, int chunk_length);

static void
test_chunk_linear (void **chunks, int chunks_count, int chunk_length)
{
	int i, j;
	struct lt_alloc_tag tag;

	for (i = 0; i < chunks_count; i ++) {
		chunks[i] = ltproto_alloc (chunk_length, &tag);
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
	const int ring_length = 8;
	struct lt_alloc_tag tag;

	for (i = 0; i < chunks_count / ring_length; i ++) {
		for (j = 0 ; j < ring_length; j ++) {
			chunks[j] = ltproto_alloc (chunk_length, &tag);
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
	uint64_t msec;

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
	u_char *map, *src, *dst;
	long long unsigned msec;
	key_t key;
	int fd, i, len, pages = 1024, psize = getpagesize (), shmid;
	struct shmid_ds shm_ds;

	len = pages * psize;
	// Check for shm related functions
	start_test_time (&tdata);
	fd = shm_open ("/perf_shm_open", O_RDWR | O_CREAT | O_EXCL, 00600);
	assert (fd != -1);
	msec = end_test_time (tdata);
	printf ("Shm open call: %llu nanoseconds\n", msec);

	start_test_time (&tdata);
	assert (ftruncate (fd, len) != -1);
	msec = end_test_time (tdata);
	printf ("Shm ftruncate to 4Mb: %llu nanoseconds\n", msec);

	start_test_time (&tdata);
	assert ((map = mmap (NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) != MAP_FAILED);
	msec = end_test_time (tdata);
	printf ("Shm mmap 4Mb: %llu nanoseconds\n", msec);

	start_test_time (&tdata);
	assert (mprotect (map, len, PROT_READ) != -1);
	msec = end_test_time (tdata);
	printf ("Shm mprotect 4Mb: %llu nanoseconds\n", msec);

	start_test_time (&tdata);
	for (i = 0; i < len; i += psize) {
		assert (mprotect (map + i, psize, PROT_WRITE) != -1);
	}
	msec = end_test_time (tdata);
	printf ("Shm %d mprotect 4Mb: %llu nanoseconds\n", pages, msec);

	start_test_time (&tdata);
	assert (mprotect (map, len, PROT_READ) != -1);
	msec = end_test_time (tdata);
	printf ("Shm mprotect 4Mb: %llu nanoseconds\n", msec);

	start_test_time (&tdata);
	munmap (map, len);
	msec = end_test_time (tdata);
	printf ("Shm munmap 4Mb: %llu nanoseconds\n", msec);

	close (fd);
	start_test_time (&tdata);
	shm_unlink ("/perf_shm_open");
	msec = end_test_time (tdata);
	printf ("Shm unlink: %llu nanoseconds\n", msec);

	// SysV memory
	key = rand ();
	start_test_time (&tdata);
	assert ((shmid = shmget (key, len, IPC_CREAT | IPC_EXCL | 00640)) != -1);
	msec = end_test_time (tdata);
	printf ("shmget: %llu nanoseconds\n", msec);

	start_test_time (&tdata);
	assert ((map = shmat (shmid, NULL, 0)) != (void *)-1);
	msec = end_test_time (tdata);
	printf ("shmat: %llu nanoseconds\n", msec);

	start_test_time (&tdata);
	assert (shmdt (map) != -1);
	msec = end_test_time (tdata);
	printf ("shmdt: %llu nanoseconds\n", msec);

	start_test_time (&tdata);
	assert (shmctl (shmid, IPC_RMID, &shm_ds) != -1);
	msec = end_test_time (tdata);
	printf ("shmctl: %llu nanoseconds\n", msec);

	src = malloc (1024 * 1024);
	dst = malloc (1024 * 1024);

	start_test_time (&tdata);
	memcpy (src, dst, 1024 * 1024);
	msec = end_test_time (tdata);
	printf ("memcpy 1mb: %llu nanoseconds\n", msec);

	free (src);
	free (dst);

	src = malloc (1024 * 1024);
	dst = malloc (1024 * 1024);
	start_test_time (&tdata);
	for (i = 0; i < 1024; i ++) {
		memcpy (src + i * 1024, dst + i * 1024, 1024);
	}
	msec = end_test_time (tdata);
	printf ("1024 memcpy 1kb: %llu nanoseconds\n", msec);

	free (src);
	free (dst);
}

static void
usage (void)
{
	printf ("Usage: ltproto_test [-b <buffer_size>] [-s <bytes_count>] [-t <tests>] [-c core_client,core_server] [-n numa_node] [-fqhvl]\n");
	exit (EXIT_FAILURE);
}

static int
parse_opt_number (const char *opt, uint64_t *dest)
{
	char *errstr;
	uint64_t var;

	var = strtoul (opt, &errstr, 10);
	if (errstr != NULL && *errstr != '\0')  {
		switch (*errstr) {
		case 'G':
		case 'g':
			var <<= 10;
			// Go down
		case 'M':
		case 'm':
			var <<= 10;
			// Go down
		case 'k':
		case 'K':
			var <<= 10;
			break;
		default:
			return -1;
		}
	}
	*dest = var;

	return 0;
}

static struct {
	const char *test_name;
	const char *description;
	int enabled;
} tests_enabled[] = {
		{
				"null",
				"TCP fallback module",
				1
		},
		{
				"unix",
				"Unix sockets module",
				1
		},
		{
				"pipe",
				"Named pipes module",
				1
		},
		{
				"udp_shmem",
				"UDP + shared memory module",
				0
		},
		{
				"unix_shmem",
				"Unix socket + shared memory module",
				0
		},
		{
				"shmem",
				"Shared memory channel, synced by mutexes",
				1
		},
		{
				"shmem_sleep",
				"Shared memory channel, synced by sleep",
				1
		},
		{
				"shmem_pipe",
				"Shared memory channel, synced by pipes",
				1
		},
		{
				"shmem_busy",
				"Shared memory channel, synced by busy wait",
				1
		}
};

static int
parse_tests_enabled (char *optline)
{
	char *token;
	unsigned int i, found;

	/* Disable all tests initially */
	for (i = 0; i < sizeof (tests_enabled) / sizeof (tests_enabled[0]); i ++) {
		tests_enabled[i].enabled = 0;
	}


	do {
		token = strsep (&optline, ", ;");
		if (token != NULL) {
			if (strcasecmp (token, "all") == 0 || strcasecmp (token, "*") == 0) {
				/* Enable all */
				for (i = 0; i < sizeof (tests_enabled) / sizeof (tests_enabled[0]); i ++) {
					tests_enabled[i].enabled = 1;
				}
			}
			else if (strcasecmp (token, "list") == 0) {
				/* Just list all available tests */
				printf ("Modules available:\n");
				for (i = 0; i < sizeof (tests_enabled) / sizeof (tests_enabled[0]); i ++) {
					printf ("%s: %s\n", tests_enabled[i].test_name, tests_enabled[i].description);
				}
				exit (EXIT_SUCCESS);
			}
			else {
				found = 0;
				for (i = 0; i < sizeof (tests_enabled) / sizeof (tests_enabled[0]); i ++) {
					if (strcasecmp (tests_enabled[i].test_name, token) == 0) {
						tests_enabled[i].enabled = 1;
						found = 1;
						break;
					}
				}
				if (!found) {
					printf ("Test %s is not defined, ignoring\n", token);
				}
			}
		}
	} while (token != NULL);

	return 0;
}

int
main (int argc, char **argv, char **envp)
{
	sigset_t sigmask;
	struct sigaction sa;
	unsigned long buflen = 1024 * 1024;
	uint64_t bytes = 8589934592ULL;
	char c, *end;
	int client_core = -1, server_core = -1, numa_node = -1, full_test = 0,
			strict_check = 0, test_latency = 0;
	unsigned int i;

	lt_init_title (argc, argv, envp);
	sigemptyset (&sigmask);
	sigaddset (&sigmask, SIGUSR1);
	memset (&sa, 0, sizeof (sa));
	sa.sa_mask = sigmask;
	sa.sa_handler = usr1_handler;
	sigaction (SIGUSR1, &sa, NULL);

	while ((c = getopt (argc, argv, "qfc:b:t:s:hvln:")) != -1) {
		switch(c) {
		case 'b':
			if (optarg) {
				if (parse_opt_number (optarg, &buflen) == -1) {
					usage ();
				}
			}
			else {
				usage ();
			}
			break;
		case 's':
			if (optarg) {
				if (parse_opt_number (optarg, &bytes) == -1) {
					usage ();
				}
			}
			else {
				usage ();
			}
			break;
		case 'f':
			full_test = 1;
			break;
		case 'v':
			strict_check = 1;
			break;
		case 'c':
			if (optarg) {
				if (optarg[0] == 's') {
					client_core = 0;
					server_core = 0;
				}
				else if (optarg[0] == 'd') {
					client_core = 1;
					server_core = 0;
				}
				else if (optarg[0] >= '0' && optarg[0] <= '9') {
					client_core = strtoul (optarg, &end, 10);
					if (*end != ',') {
						usage ();
					}
					server_core = strtoul (end + 1, NULL, 10);
				}
				else {
					usage ();
				}
			}
			else {
				usage ();
			}
			break;
		case 'n':
			if (optarg) {
				numa_node = strtoul (optarg, NULL, 10);
			}
			else {
				usage ();
			}
			break;
		case 'q':
			compact = 1;
			break;
		case 't':
			if (optarg) {
				if (parse_tests_enabled (optarg) != 0) {
					usage ();
				}
			}
			else {
				usage ();
			}
			break;
		case 'l':
			test_latency = 1;
			break;
		default:
			usage ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	ltproto_init ();

	if (full_test) {
		syscalls_test ();
		/* Start a simple tests */
		assert (ltproto_switch_allocator ("system allocator") != -1);
		perform_allocator_test ("system", 10240, test_chunk_circular);
		assert (ltproto_switch_allocator ("linear allocator") != -1);
		perform_allocator_test ("linear", 10240, test_chunk_circular);
	}

	for (i = 0; i < sizeof (tests_enabled) / sizeof (tests_enabled[0]); i ++) {
		if (tests_enabled[i].enabled) {
			if (test_latency) {
				perform_module_test_latency (tests_enabled[i].test_name, server_core, client_core, numa_node);
			}
			else {
				perform_module_test_simple (tests_enabled[i].test_name, buflen,
					bytes, server_core, client_core, numa_node, strict_check);
			}
		}
	}

	ltproto_destroy ();

	return 0;
}
