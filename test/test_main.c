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

int
main (int argc, char **argv)
{
	pid_t spid;
	void *tdata;
	time_t msec;
	sigset_t sigmask;
	struct sigaction sa;

	sigemptyset (&sigmask);
	sigaddset (&sigmask, SIGUSR1);
	memset (&sa, 0, sizeof (sa));
	sa.sa_mask = sigmask;
	sa.sa_handler = usr1_handler;
	sigaction (SIGUSR1, &sa, NULL);

	ltproto_init ();

	/* Start a simple test */
	spid = fork_server (50009, 1024 * 1024);
	assert (spid != -1);
	wait_for_server ();
	start_test_time (&tdata);
	assert (do_client (50009, 8 * 1024 * 1024, 1024) != -1);
	msec = end_test_time (tdata);
	printf ("Send buffer: 8Mb, Recv buffer: 1Mb; Transmitted 8Gb in %.3f milliseconds\n", round_test_time (msec));

	start_test_time (&tdata);
	assert (do_client (50009, 4 * 1024 * 1024, 2048) != -1);
	msec = end_test_time (tdata);
	printf ("Send buffer: 4Mb, Recv buffer: 1Mb; Transmitted 8Gb in %.3f milliseconds\n", round_test_time (msec));

	kill (spid, SIGTERM);

	ltproto_destroy ();

	return 0;
}
