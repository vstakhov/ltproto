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

/**
 * @file
 * A simple test for shmem_arbiter
 */
#include "config.h"
#include "ltproto.h"
#include "util.h"
#include "arbiter_proto.h"


static void
usage (void)
{
	printf ("Usage: test_arbiter [-c core] [-h] socket_path\n");
	exit (EXIT_FAILURE);
}

int
main (int argc, char **argv)
{
	char c, buf[64];
	struct sockaddr_un sun;
	int core = -1, sk;

	while ((c = getopt (argc, argv, "c:h")) != -1) {
		switch (c) {
		case 'c':
			if (optarg != NULL) {
				core = strtoul (optarg, NULL, 10);
			}
			else {
				usage ();
			}
			break;
		case 'h':
		default:
			usage ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage ();
	}

	bind_to_core (core, -1);

	sun.sun_family = AF_UNIX;
	snprintf (sun.sun_path, sizeof (sun.sun_path), "%s", argv[0]);
#ifdef BSD
	sun.sun_len = SUN_LEN (&sun);
#endif
	sk = socket (AF_UNIX, SOCK_DGRAM, 0);
	if (sk == -1) {
		perror ("socket failed");
		exit (EXIT_FAILURE);
	}

	if (sendto (sk, buf, sizeof (buf), 0, (struct sockaddr *)&sun, sizeof (sun)) == -1) {
		perror ("send failed");
		exit (EXIT_FAILURE);
	}

	close (sk);

	return EXIT_SUCCESS;
}
