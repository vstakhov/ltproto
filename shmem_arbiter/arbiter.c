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
#include "util.h"
#include "arbiter_proto.h"
#include <sys/wait.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * @file arbiter.c
 * This is an implementation of a simple shared memory arbiter, that
 * opens shared memory segments and pass descriptors to the calling processes
 */

struct arbiter_maps {
	char *key;
	int fd;
	unsigned ref;
	UT_hash_handle hh;
};

struct arbiter_map *gam = NULL;

static void
usage (void)
{
	printf ("Usage: ltproto_arbiter [-c core1[,core2[,...coreN]]] [-n numa_node] [-h] socket_path\n");
	exit (EXIT_FAILURE);
}

/* XXX: we need shared memory hashes for multiply workers, now we do not support it */
static void
do_worker (int sk, int core, int numa_node)
{
	struct msghdr msg;
	struct iovec iov;
	char buf[512];

	bind_to_core (core, numa_node);
	iov.iov_base = buf;
	iov.iov_len = sizeof (buf);
	memset (&msg, 0, sizeof (msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	for (;;) {
		if (recvmsg (sk, &msg, 0) == -1) {
			break;
		}
		printf ("got message on %d\n", core);
	}

	exit (EXIT_SUCCESS);
}

struct arbiter_core {
	int corenum;
	pid_t pid;
	struct arbiter_core *next;
};

static struct arbiter_core *
parse_cores (const char *line, int *cores_count)
{
	char *end;
	struct arbiter_core *result = NULL, *cur;
	int cur_core;

	for (;;) {
		cur_core = strtoul (line, &end, 10);
		if (end == NULL || *end == '\0' || *end == ',') {
			cur = malloc (sizeof (struct arbiter_core));
			if (cur == NULL) {
				perror ("malloc failed");
				exit (EXIT_FAILURE);
			}
			cur->corenum = cur_core;
			cur->next = result;
			result = cur;
			(*cores_count)++;
			if (end == NULL || *end == '\0') {
				break;
			}
		}
		else {
			perror ("invalid core number");
			exit (EXIT_FAILURE);
		}
		line = end + 1;
	}

	return result;
}

int
main (int argc, char **argv)
{
	char c;
	int numa_node = -1, sk, wres, cores_count = 0;
	pid_t worker;
	struct arbiter_core *cores = NULL, *cur;
	struct sockaddr_un sun;

	while ((c = getopt (argc, argv, "c:n:h")) != -1) {
		switch (c) {
		case 'c':
			if (optarg != NULL) {
				cores = parse_cores (optarg, &cores_count);
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

	sun.sun_family = AF_UNIX;
	snprintf (sun.sun_path, sizeof (sun.sun_path), "%s", argv[0]);
	unlink (sun.sun_path);
#ifdef BSD
	sun.sun_len = SUN_LEN (&sun);
#endif
	sk = socket (AF_UNIX, SOCK_DGRAM, 0);
	if (sk == -1) {
		perror ("socket failed");
		exit (EXIT_FAILURE);
	}
	if (bind (sk, (struct sockaddr *)&sun, sizeof (sun)) == -1) {
		perror ("bind failed");
		exit (EXIT_FAILURE);
	}

	/* Fork workers */
	cur = cores;
	do {
		worker = fork ();
		switch (worker) {
		case 0:
			if (cur == NULL) {
				do_worker (sk, -1, numa_node);
			}
			else {
				do_worker (sk, cur->corenum, numa_node);
			}
			break;
		case -1:
			perror ("fork failed");
			exit (EXIT_FAILURE);
			break;
		}
		if (cur != NULL) {
			cur->pid = worker;
			cur = cur->next;
		}

	} while (cur != NULL);

	cur = cores;
	if (cur == NULL) {
		waitpid (worker, &wres, 0);
	}
	else {
		while (cur != NULL) {
			waitpid (cur->pid, &wres, 0);
			cur = cur->next;
		}
	}

	return EXIT_SUCCESS;
}
