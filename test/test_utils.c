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
	diff = (tdata_cur.tv_sec - tdata_prev->tv_sec) * 1000000000L +
				(tdata_cur.tv_nsec - tdata_prev->tv_nsec);
#else
	assert (gettimeofday (&tdata_cur, NULL) == 0);
	diff = (tdata_cur.tv_sec - tdata_prev->tv_sec) * 1000000000L +
			(tdata_cur.tv_usec - tdata_prev->tv_usec) * 1000;
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

    res = (int64_t)log10 (1000000000L / ts.tv_nsec);
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

/**
 * Fork server
 * @param port port to bind
 * @param recv_buffer_size size of receive buffer
 * @return 0 in case of success, -1 in case of error (and doesn't return for server process)
 */
pid_t
fork_server (u_short port, u_int recv_buffer_size, void *mod)
{
	pid_t pid;
	struct ltproto_socket *sock, *conn;
	struct sockaddr_in sin;
	socklen_t slen = sizeof (struct sockaddr_in);
	u_char *recv_buf;

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
	assert (ltproto_socket (mod, &sock) != -1);
	assert (sock != NULL);

	sin.sin_family = AF_INET;
	sin.sin_port = htons (port);
	sin.sin_addr.s_addr = INADDR_ANY;

	recv_buf = malloc (recv_buffer_size);
	assert (recv_buf != NULL);

	assert (ltproto_bind (sock, (struct sockaddr *)&sin, slen) != -1);
	assert (ltproto_listen (sock, -1) != -1);

	/* Tell that we are ready */
	kill (getppid (), SIGUSR1);

	do {
		conn = ltproto_accept (sock, (struct sockaddr *)&sin, &slen);
		while (ltproto_read (conn, recv_buf, recv_buffer_size) > 0);

		ltproto_close (conn);
	} while (conn != NULL);

	_exit (EXIT_SUCCESS);
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
do_client (u_short port, u_int send_buffer_size, u_int repeat_count, void *mod)
{
	struct ltproto_socket *sock;
	u_int i;
	struct sockaddr_in sin;
	u_char *send_buf;

	sin.sin_family = AF_INET;
	sin.sin_port = htons (port);
	sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

	assert (ltproto_socket (mod, &sock) != -1);
	assert (sock != NULL);

	send_buf = malloc (send_buffer_size);
	memset (send_buf, 0xde, send_buffer_size);
	assert (send_buf != NULL);

	if (ltproto_connect (sock, (struct sockaddr *)&sin, sizeof (sin)) == -1) {
		perror ("connect failed");
		goto err;
	}

	for (i = 0; i < repeat_count; i ++) {
		if (ltproto_write (sock, send_buf, send_buffer_size) == -1) {
			perror ("write failed");
			goto err;
		}
	}

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
