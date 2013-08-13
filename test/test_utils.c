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
#include <math.h>
#include <cpuid.h>

sig_atomic_t got_term = 0;

/**
 * Start time of some test
 * @param time_data opaque data that is used and allocated internally
 */
void
start_test_time (void **time_data)
{
#ifdef HAVE_CLOCK_GETTIME
	struct timespec *tdata;
	const size_t tsize = sizeof (struct timespec);
#else
	struct timeval *tdata;
	const size_t tsize = sizeof (struct timeval);
#endif
	tdata = calloc (1, tsize);
	assert (tdata != NULL);
#ifdef HAVE_CLOCK_GETTIME
# ifdef HAVE_CLOCK_MONOTONIC_RAW
	assert (clock_gettime (CLOCK_MONOTONIC_RAW, tdata) == 0);
# elif defined(HAVE_CLOCK_REALTIME_PRECISE)
	assert (clock_gettime (CLOCK_REALTIME_PRECISE, tdata) == 0);
# else
	assert (clock_gettime (CLOCK_REALTIME, tdata) == 0);
# endif
#else
	assert (gettimeofday (tdata, NULL) == 0);
#endif
	*time_data = tdata;
}

/**
 * Get time from start of a test
 * @param time_data opaque data that is used and deallocated internally
 * @return time in nanoseconds
 */
uint64_t
end_test_time (void *time_data)
{
#ifdef HAVE_CLOCK_GETTIME
	struct timespec *tdata_prev = time_data, tdata_cur;
#else
	struct timeval *tdata_prev = time_data, tdata_cur;
#endif
	uint64_t diff;

	assert (time_data != NULL);

#ifdef HAVE_CLOCK_GETTIME
# ifdef HAVE_CLOCK_MONOTONIC_RAW
	assert (clock_gettime (CLOCK_MONOTONIC_RAW, &tdata_cur) == 0);
# elif defined(HAVE_CLOCK_REALTIME_PRECISE)
	assert (clock_gettime (CLOCK_REALTIME_PRECISE, &tdata_cur) == 0);
# else
	assert (clock_gettime (CLOCK_REALTIME, &tdata_cur) == 0);
# endif
	diff = (tdata_cur.tv_sec - tdata_prev->tv_sec) * 1000000000LL +
				(tdata_cur.tv_nsec - tdata_prev->tv_nsec);
#else
	assert (gettimeofday (&tdata_cur, NULL) == 0);
	diff = (tdata_cur.tv_sec - tdata_prev->tv_sec) * 1000000000LL +
			(tdata_cur.tv_usec - tdata_prev->tv_usec) * 1000LL;
#endif

	free (time_data);

	return diff;
}

/**
 * Convert time to the nearest available double value according to clock resolution
 * @param nanoseconds input nanoseconds
 * @return milliseconds with fractional part
 */
double
round_test_time (uint64_t nanoseconds)
{
	int64_t res;
	double result;
#ifdef HAVE_CLOCK_GETTIME
	struct timespec ts;
#ifdef HAVE_CLOCK_MONOTONIC_RAW
    clock_getres (CLOCK_MONOTONIC_RAW, &ts);
# elif defined(HAVE_CLOCK_REALTIME_PRECISE)
	clock_getres (CLOCK_REALTIME_PRECISE, &ts);
# else
    clock_getres (CLOCK_REALTIME, &ts);
# endif

    res = (int64_t)log10 (1000000000LL / ts.tv_nsec);
    if (res < 0) {
    	res = 0;
    }
    if (res > 6) {
    	res = 6;
    }
#else
    /* For gettimeofday */
    res = 1;
#endif

    result = (uint64_t) (nanoseconds / pow (10, 6 - res));
    result /= pow (10, res);

    return result;
}


static void
server_term_handler (int signo)
{
	got_term = 1;
}

static uint32_t
murmur32_hash (char *in, uint32_t len)
{


	const uint32_t 			 c1 = 0xcc9e2d51;
	const uint32_t 			 c2 = 0x1b873593;

	const int				 nblocks = len / 4;
	const uint32_t 			*blocks = (const uint32_t *)(in);
	const uint8_t 			*tail;
	uint32_t 				 h = 0;
	int 					 i;
	uint32_t 				 k;

	if (in == NULL || len == 0) {
		return 0;
	}

	tail = (const uint8_t *)(in + (nblocks * 4));

	for (i = 0; i < nblocks; i++) {
		k = blocks[i];

		k *= c1;
		k = (k << 15) | (k >> (32 - 15));
		k *= c2;

		h ^= k;
		h = (h << 13) | (h >> (32 - 13));
		h = (h * 5) + 0xe6546b64;
	}

	k = 0;
	switch (len & 3) {
	case 3:
		k ^= tail[2] << 16;
	case 2:
		k ^= tail[1] << 8;
	case 1:
		k ^= tail[0];
		k *= c1;
		k = (k << 13) | (k >> (32 - 15));
		k *= c2;
		h ^= k;
	};

	h ^= len;

	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}

static int
has_sse_42 (void) {
	unsigned int eax, ebx, ecx, edx;

	eax = ebx = ecx = edx = 0;
	__get_cpuid(1, &eax, &ebx, &ecx, &edx);

	if (ecx & bit_SSE4_2) {
		return 1;
	}

	return 0;
}

static uint32_t
fastcrc (char *str, uint32_t len) {
	uint32_t q = len / sizeof(uint32_t),
			r = len % sizeof(uint32_t),
			*p = (uint32_t*)str, crc;

	crc  =0;
	while (q --) {
		__asm__ __volatile__(
				".byte 0xf2, 0xf, 0x38, 0xf1, 0xf1;"
				:"=S"(crc)
				 :"0"(crc), "c"(*p)
		);
		p ++;
	}

	str = (char*)p;
	while (r --) {
		__asm__ __volatile__(
				".byte 0xf2, 0xf, 0x38, 0xf0, 0xf1"
				:"=S"(crc)
				 :"0"(crc), "c"(*str)
		);
		str ++;
	}

	return crc;
}

/**
 * Fork server
 * @param port port to bind
 * @param recv_buffer_size size of receive buffer
 * @return 0 in case of success, -1 in case of error (and doesn't return for server process)
 */
pid_t
fork_server (u_short port, u_int recv_buffer_size, void *mod, int corenum, int strict_check)
{
	pid_t pid;
	struct ltproto_socket *sock, *conn = NULL;
	struct sockaddr_in sin;
	socklen_t slen = sizeof (struct sockaddr_in);
	uint8_t *recv_buf;
	sigset_t sigmask;
	struct sigaction sa;
	uint32_t hash, test;
	int r, remain, done;
	uint32_t (*hf)(char *in, uint32_t len);

	if (has_sse_42 ()) {
		hf = fastcrc;
	}
	else {
		hf = murmur32_hash;
	}

	pid = fork ();

	switch (pid) {
	case 0:
		goto do_client;
	case -1:
		return -1;
	default:
		return pid;
	}

do_client:
	if (corenum != -1) {
		bind_to_core (corenum);
	}
	sigemptyset (&sigmask);
	sigaddset (&sigmask, SIGUSR1);
	memset (&sa, 0, sizeof (sa));
	sa.sa_mask = sigmask;
	sa.sa_handler = server_term_handler;
	sigaction (SIGTERM, &sa, NULL);

	assert (ltproto_socket (mod, &sock) != -1);
	assert (sock != NULL);

	sin.sin_family = AF_INET;
	sin.sin_port = htons (port);
	sin.sin_addr.s_addr = INADDR_ANY;

	assert (posix_memalign ((void **)&recv_buf, 16, recv_buffer_size) == 0);
	assert (recv_buf != NULL);

	assert (ltproto_bind (sock, (struct sockaddr *)&sin, slen) != -1);
	assert (ltproto_listen (sock, -1) != -1);

	/* Tell that we are ready */
	kill (getppid (), SIGUSR1);

	gperf_profiler_init ("server");
	do {
		if (got_term) {
			ltproto_close (conn);
			break;
		}
		conn = ltproto_accept (sock, (struct sockaddr *)&sin, &slen);
		for (;;) {
			remain = recv_buffer_size;
			r = 0;
			done = 0;
			do {
				r = ltproto_read (conn, recv_buf + done, remain);
				if (r > 0) {
					remain -= r;
					done += r;
				}
			} while (remain > 0 && r > 0);
			if (r <= 0) {
				break;
			}
			if (strict_check) {
				memcpy (&hash, recv_buf, sizeof (hash));
				test = hf (recv_buf + sizeof (hash), recv_buffer_size - sizeof (hash));
				assert (hash == test);
			}
		}

		ltproto_close (conn);
	} while (conn != NULL && !got_term);


	ltproto_close (sock);
	gperf_profiler_stop ();
	exit (EXIT_SUCCESS);

	return 0;
}

/**
 * Perform client test
 * @param port port to connect
 * @param send_buffer_size size of send buffer
 * @param repeat_count how many times this buffer should be sent
 * @return
 */
int
do_client (u_short port, u_int send_buffer_size, u_int repeat_count, void *mod, const char *modname, int strict_check)
{
	struct ltproto_socket *sock;
	u_int i;
	struct sockaddr_in sin;
	uint8_t *send_buf;
	int r, remain, done;
	uint32_t hash;
	uint32_t (*hf)(char *in, uint32_t len);

	if (has_sse_42 ()) {
		hf = fastcrc;
	}
	else {
		hf = murmur32_hash;
	}

	sin.sin_family = AF_INET;
	sin.sin_port = htons (port);
	sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

	assert (ltproto_socket (mod, &sock) != -1);
	assert (sock != NULL);

	assert (posix_memalign ((void **)&send_buf, 16, send_buffer_size) == 0);
	assert (send_buf != NULL);

	if (ltproto_connect (sock, (struct sockaddr *)&sin, sizeof (sin)) == -1) {
		perror ("connect failed");
		goto err;
	}
	memset (send_buf, 0x1, send_buffer_size);

	gperf_profiler_init (modname);
	for (i = 0; i < repeat_count; i ++) {
		if (strict_check) {
			memset (send_buf + sizeof (hash), i % 256, send_buffer_size - sizeof (hash));
			hash = hf (send_buf + sizeof (hash), send_buffer_size - sizeof (hash));
			memcpy (send_buf, &hash, sizeof (hash));
		}
		r = 0;
		done = 0;
		remain = send_buffer_size;
		do {
			if ((r = ltproto_write (sock, send_buf + done, remain)) == -1) {
				perror ("write failed");
				goto err;
			}
			remain -= r;
			done += r;
		} while (remain > 0);
	}

	gperf_profiler_stop ();
	ltproto_close (sock);
	return 0;
err:
	ltproto_close (sock);
	return -1;
}

/**
 * Return humanized number of bytes
 * @param bytes bytes to print
 * @return static buffer with desired string
 */
char*
print_bytes (uint64_t bytes)
{
	static char buf[16];
	const char *prefixes = "kMGTPE";
	uint64_t quotient = bytes, cur = bytes;
	int i;

	for (i = 0; i < 6; i ++) {
		cur = quotient >> 10;
		if (cur < 1024) {
			break;
		}
		quotient = cur;
	}
	snprintf (buf, sizeof (buf), "%lu.%lu%cb", (unsigned long)cur,
			(unsigned long)quotient % 1024, prefixes[i]);

	return buf;
}

/**
 * Init google perftools
 * @param descr process description
 */
void
gperf_profiler_init (const char *descr)
{
#if defined(WITH_GPERF_TOOLS)
	char prof_path[PATH_MAX], *tmpdir;

	if (getenv ("CPUPROFILE")) {

		/* disable inherited Profiler enabled in master process */
		ProfilerStop ();
	}
	tmpdir = getenv ("TMPDIR");
	if (tmpdir == NULL) {
		tmpdir = "/tmp";
	}

	snprintf (prof_path, sizeof (prof_path), "%s/ltproto-%s.%d", tmpdir, descr, (int)getpid ());
	if (ProfilerStart (prof_path)) {
		/* start ITIMER_PROF timer */
		ProfilerRegisterThread ();
	}
	else {
		fprintf (stderr, "Cannot start google perftools profiler\n");
	}

#endif
}

/**
 * Stop google perftools and write everything
 */
void
gperf_profiler_stop (void)
{
#if defined(WITH_GPERF_TOOLS)
	ProfilerStop ();
#endif
}


/**
 * Bind this process to a specific core
 * @param corenum number of core
 */
void
bind_to_core (int corenum)
{
#ifdef HAVE_SCHED_SETAFFINITY
	/* Bind to a single core */
	cpu_set_t mask;
	CPU_ZERO (&mask);
	CPU_SET (corenum, &mask);
	sched_setaffinity (0, sizeof(cpu_set_t), &mask);
#elif defined(HAVE_CPUSET_SETAFFINITY)
	cpuset_t mask;
	CPU_ZERO (&mask);
	CPU_SET (corenum, &mask);
	cpuset_setaffinity (CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof (mask), &mask);
#endif
}
