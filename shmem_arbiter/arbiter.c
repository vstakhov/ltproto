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
#include "uthash.h"
#include <sys/wait.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * @file arbiter.c
 * This is an implementation of a simple shared memory arbiter, that
 * opens shared memory segments and pass descriptors to the calling processes
 */

struct arbiter_map {
	char *key;
	char *path;
	int fd;
	unsigned ref;
	size_t len;
	UT_hash_handle hh;
};

struct arbiter_map *gam = NULL;

struct ltproto_arbiter_msg_reply {
	struct ltproto_arbiter_msg msg;
	size_t payload;
};

static void
usage (void)
{
	printf ("Usage: ltproto_arbiter [-c core1[,core2[,...coreN]]] [-n numa_node] [-h] socket_path\n");
	exit (EXIT_FAILURE);
}

static void
arbiter_send_reply (int fd, int code, struct sockaddr *addr, socklen_t slen, struct arbiter_map *map)
{
	struct msghdr msg;
	struct iovec iov;
	struct ltproto_arbiter_msg_reply ram;
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof (int))];


	memset (&msg, 0, sizeof (msg));
	switch (code) {
	case LT_ARBITER_SEND_FD:
		if (map->ref < 2) {
			msg.msg_control = buf;
			msg.msg_controllen = sizeof buf;
			cmsg = CMSG_FIRSTHDR (&msg);
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			cmsg->cmsg_len = CMSG_LEN (sizeof(int));
			memcpy (CMSG_DATA (cmsg), &map->fd, sizeof (int));
			msg.msg_controllen = cmsg->cmsg_len;
			map->ref ++;
			ram.msg.msg = code;
			ram.msg.msg_len = sizeof (size_t);
			ram.payload = map->len;
		}
		else {
			printf ("more than 2 connections to %s\n", map->key);
			code = LT_ARBITER_ERROR;
			ram.msg.msg_len = 0;
		}
		break;
	default:
		ram.msg.msg_len = 0;
		break;
	}


	iov.iov_base = &ram;
	iov.iov_len = sizeof (struct ltproto_arbiter_msg) + ram.msg.msg_len;
	msg.msg_name = addr;
	msg.msg_namelen = slen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg (fd, &msg, 0) == -1) {
		printf ("sendmsg err: %s\n", strerror (errno));
	}
}

static struct arbiter_map *
arbiter_create_map (struct ltproto_arbiter_msg *am)
{
	struct arbiter_map *new = NULL;
	size_t shmem_len, keylen;

	memcpy (&shmem_len, am->payload, sizeof (size_t));
	new = malloc (sizeof (struct arbiter_map));
	if (new == NULL) {
		return NULL;
	}
	keylen = strlen (am->name);
	new->ref = 0;
	new->len = shmem_len;
	new->key = strdup (am->name);
	new->path = malloc (EVP_MAX_MD_SIZE * 2 + 2);
	new->path[0] = '/';
	lt_sha512_buf (am->name, keylen, new->path + 1);

	new->fd = shm_open (new->path, O_RDWR | O_CREAT | O_EXCL, 00600);
	if (new->fd == -1) {
		goto err;
	}
	if (ftruncate (new->fd, shmem_len) == -1) {
		goto err;
	}

	HASH_ADD_KEYPTR (hh, gam, new->key, keylen, new);

	return new;
err:
	if (new != NULL) {
		if (new->key != NULL) {
			free (new->key);
		}
		if (new->path != NULL) {
			shm_unlink (new->path);
			free (new->path);
		}
		if (new->fd != -1) {
			close (new->fd);
		}
		free (new);
	}

	return NULL;
}

static void
arbiter_remove_map (struct arbiter_map *map)
{
	if (--map->ref == 0) {
		if (map->key != NULL) {
			free (map->key);
		}
		if (map->path != NULL) {
			shm_unlink (map->path);
			free (map->path);
		}
		if (map->fd != -1) {
			close (map->fd);
		}
		HASH_DELETE (hh, gam, map);
		free (map);
	}
}

/* XXX: we need shared memory hashes for multiply workers, now we do not support it */
static void
do_worker (int sk, int core, int numa_node)
{
	struct msghdr msg;
	struct iovec iov;
	int r, len;
	char buf[512], *np = NULL;
	struct ltproto_arbiter_msg *am;
	struct arbiter_map *nmap, *found;

	bind_to_core (core, numa_node);
	iov.iov_base = buf;
	iov.iov_len = sizeof (buf);
	memset (&msg, 0, sizeof (msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	for (;;) {
		if ((r = recvmsg (sk, &msg, 0) == -1)) {
			break;
		}

		printf ("got message on %d\n", core);
		if (r < sizeof (struct ltproto_arbiter_msg)) {
			printf ("partial message received, discard\n");
			arbiter_send_reply (sk, LT_ARBITER_ERROR, msg.msg_name, msg.msg_namelen, NULL);
		}
		am = (struct ltproto_arbiter_msg *)buf;
		switch (am->msg) {
		case LT_ARBITER_REGISTER:
			np = memchr (am->name, 0, sizeof (am->name));
			if (np == NULL) {
				printf ("invalid name received, discard\n");
				arbiter_send_reply (sk, LT_ARBITER_ERROR, msg.msg_name, msg.msg_namelen, NULL);
			}
			else {
				len = np - am->name;
				HASH_FIND (hh, gam, am->name, len, found);
				if (found != NULL) {
					printf ("duplicate name %s received, discard\n", am->name);
					arbiter_send_reply (sk, LT_ARBITER_ERROR, msg.msg_name, msg.msg_namelen, NULL);
				}
				else {
					if (r < sizeof (struct ltproto_arbiter_msg) + sizeof (size_t)) {
						printf ("truncated reply for %s received, discard\n", am->name);
						arbiter_send_reply (sk, LT_ARBITER_ERROR, msg.msg_name, msg.msg_namelen, NULL);
					}
					else {
						nmap = arbiter_create_map (am);
						if (nmap != NULL) {
							arbiter_send_reply (sk, LT_ARBITER_SEND_FD, msg.msg_name, msg.msg_namelen, nmap);
						}
						else {
							arbiter_send_reply (sk, LT_ARBITER_ERROR, msg.msg_name, msg.msg_namelen, NULL);
						}
					}
				}
			}
			break;
		case LT_ARBITER_CONNECT:
			np = memchr (am->name, 0, sizeof (am->name));
			if (np == NULL) {
				printf ("invalid name received, discard\n");
				arbiter_send_reply (sk, LT_ARBITER_ERROR, msg.msg_name, msg.msg_namelen, NULL);
			}
			else {
				len = np - am->name;
				HASH_FIND (hh, gam, am->name, len, found);
				if (found == NULL) {
					printf ("name %s is not registered, discard\n", am->name);
					arbiter_send_reply (sk, LT_ARBITER_ERROR, msg.msg_name, msg.msg_namelen, NULL);
				}
				else {
					arbiter_send_reply (sk, LT_ARBITER_SEND_FD, msg.msg_name, msg.msg_namelen, found);
				}
			}
			break;
		case LT_ARBITER_UNREGISTER:
			np = memchr (am->name, 0, sizeof (am->name));
			if (np == NULL) {
				printf ("invalid name received, discard\n");
				arbiter_send_reply (sk, LT_ARBITER_ERROR, msg.msg_name, msg.msg_namelen, NULL);
			}
			else {
				len = np - am->name;
				HASH_FIND (hh, gam, am->name, len, found);
				if (found == NULL) {
					printf ("name %s is not registered, discard\n", am->name);
					arbiter_send_reply (sk, LT_ARBITER_ERROR, msg.msg_name, msg.msg_namelen, NULL);
				}
				else {
					arbiter_remove_map (found);
					arbiter_send_reply (sk, LT_ARBITER_SUCCESS, msg.msg_name, msg.msg_namelen, NULL);
				}
			}
			break;
		default:
			printf ("invalid message %d received, discard\n", am->msg);
			arbiter_send_reply (sk, LT_ARBITER_ERROR, msg.msg_name, msg.msg_namelen, NULL);
			break;
		}
	}

	exit (-errno);
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
