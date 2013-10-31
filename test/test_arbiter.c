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
#include <assert.h>


static void
usage (void)
{
	printf ("Usage: test_arbiter [-c core] [-h] socket_path\n");
	exit (EXIT_FAILURE);
}

int
main (int argc, char **argv)
{
	char c;
	struct sockaddr_un sun;
	struct iovec iov[2];
	struct ltproto_arbiter_msg am;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	int core = -1, sk;
	int shfd;
	size_t reqlen = 4096;
	char cbuf[CMSG_SPACE(sizeof (int))];
	void *map;

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
	sk = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sk == -1) {
		perror ("socket failed");
		exit (EXIT_FAILURE);
	}

	if (connect (sk, &sun, sizeof (sun)) == -1) {
		perror ("connect failed");
		exit (EXIT_FAILURE);
	}
	am.msg = LT_ARBITER_REGISTER;
	am.msg_len = sizeof (size_t);
	memcpy (am.name, "test", 5);
	iov[0].iov_base = &am;
	iov[0].iov_len = sizeof (am);
	iov[1].iov_base = &reqlen;
	iov[1].iov_len = sizeof (reqlen);

	memset (&msg, 0, sizeof (msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	if (sendmsg (sk, &msg, 0) == -1) {
		perror ("send failed");
		exit (EXIT_FAILURE);
	}

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof (cbuf);

	if (recvmsg (sk, &msg, 0) == -1) {
		perror ("recv failed");
		exit (EXIT_FAILURE);
	}

	assert (am.msg == LT_ARBITER_SEND_FD);

	for (cmsg = CMSG_FIRSTHDR (&msg); cmsg != NULL; cmsg = CMSG_NXTHDR (&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			memcpy (&shfd, CMSG_DATA(cmsg), sizeof (int));
			assert (reqlen == 4096);
			assert (shfd != -1);
			break;
		}
	}

	/* Now try to mmap */
	if ((map = mmap (NULL, reqlen, PROT_READ | PROT_WRITE, MAP_SHARED, shfd, 0)) == MAP_FAILED) {
		assert (0);
	}
	memset (map, 0xfe, reqlen);

	am.msg = LT_ARBITER_UNREGISTER;
	memcpy (am.name, "test", 5);

	munmap (map, reqlen);

	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	if (sendmsg (sk, &msg, 0) == -1) {
		perror ("send failed");
		exit (EXIT_FAILURE);
	}

	if (recvmsg (sk, &msg, 0) == -1) {
		perror ("recv failed");
		exit (EXIT_FAILURE);
	}

	assert (am.msg == LT_ARBITER_SUCCESS);
	close (sk);

	return EXIT_SUCCESS;
}
