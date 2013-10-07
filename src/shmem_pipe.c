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
#include <assert.h>

/**
 * @file shmem_pipe.c
 * @section DESCRIPTION
 *
 * This module implements the pure shared memory channel using pipes for synchronization.
 * We use an ordinary TCP socket for accept and listen for a connection.
 * Connecting socket is responsible for allocating shmem_pipe ring.
 */

int shmem_pipe_init_func (struct lt_module_ctx **ctx);
struct ltproto_socket* shmem_pipe_socket_func (struct lt_module_ctx *ctx);
int shmem_pipe_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue);
int shmem_pipe_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
int shmem_pipe_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog);
struct ltproto_socket* shmem_pipe_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen);
int shmem_pipe_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
ssize_t shmem_pipe_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len);
ssize_t shmem_pipe_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len);
int shmem_pipe_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv);
int shmem_pipe_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk);
int shmem_pipe_destroy_func (struct lt_module_ctx *ctx);

module_t shmem_pipe_module = {
		.name = "shmem_pipe",
		.priority = 10,
		.module_init_func = shmem_pipe_init_func,
		.module_socket_func = shmem_pipe_socket_func,
		.module_setopts_func = shmem_pipe_setopts_func,
		.module_bind_func = shmem_pipe_bind_func,
		.module_listen_func = shmem_pipe_listen_func,
		.module_accept_func = shmem_pipe_accept_func,
		.module_connect_func = shmem_pipe_connect_func,
		.module_read_func = shmem_pipe_read_func,
		.module_write_func = shmem_pipe_write_func,
		.module_select_func = shmem_pipe_select_func,
		.module_close_func = shmem_pipe_close_func,
		.module_destroy_func = shmem_pipe_destroy_func
};

#define LT_DEFAULT_SLOTS 256
#define LT_DEFAULT_BUF 4096

static int lt_ring_slots = LT_DEFAULT_SLOTS;
static int lt_ring_buf = LT_DEFAULT_BUF;

struct lt_net_ring_slot {
	unsigned int len;
	unsigned int flags;
#define LT_SLOT_FLAG_FREE 0x0
#define LT_SLOT_FLAG_READY 0x1
#define LT_SLOT_FLAG_WAIT_READ 0x2
#define LT_SLOT_FLAG_WAIT_WRITE 0x4
#define LT_SLOT_FLAG_WAIT (LT_SLOT_FLAG_WAIT_READ | LT_SLOT_FLAG_WAIT_WRITE)
};

struct lt_net_ring {
	unsigned int num_slots;
	unsigned int cur;
	unsigned int avail;
	unsigned int ref;

	size_t buf_offset;
	size_t buf_size;

	struct lt_net_ring_slot slot[0];
};

#define LT_RING_BUF(ring, index)                         \
        ((char *)(ring) + (ring)->buf_offset + ((index)*(ring)->buf_size))

#define LT_RING_NEXT(r, i)                               \
        ((i)+1 == (r)->num_slots ? 0 : (i) + 1 )
#define LT_RING_SIZE(slots, bufsize)                     \
        (sizeof (struct lt_net_ring) + sizeof (struct lt_net_ring_slot) * (slots) +  \
        (bufsize) * (slots))

struct ltproto_socket_shmem_pipe {
	int fd;							// Socket descriptor
	int tcp_fd;						// TCP link socket
	struct ltproto_module *mod;		// Module handling this socket
	UT_hash_handle hh;				// Hash entry

	struct lt_net_ring *rx_ring;	// Input
	struct lt_net_ring *tx_ring;	// Output
	unsigned int cur_rx;			// Current RX slot
	unsigned int cur_tx;			// Current TX slot
	struct lt_alloc_tag tag[2];		// Connected tags
	int ring_owner;					// The owner of rings
	int rx_pipe;					// RX ring sync
	int tx_pipe;					// TX ring sync
};

static void
shmem_pipe_init_ring (struct lt_net_ring *ring, int nslots, int bufsize)
{
	memset (ring, 0, LT_RING_SIZE (nslots, bufsize));
	ring->buf_size = bufsize;
	ring->buf_offset = offsetof(struct lt_net_ring, slot) +
				nslots * sizeof (struct lt_net_ring_slot);
	ring->num_slots = nslots;
	ring->ref = 1;
}

int
shmem_pipe_init_func (struct lt_module_ctx **ctx)
{
	char *lt_env;

	*ctx = calloc (1, sizeof (struct lt_module_ctx));
	(*ctx)->len = sizeof (struct lt_module_ctx);
	(*ctx)->sk_cache = lt_objcache_create (sizeof (struct ltproto_socket_shmem_pipe));

	lt_env = getenv ("LTPROTO_RING_SLOTS");
	if (lt_env != NULL) {
		lt_ring_slots = strtoul (lt_env, NULL, 10);
	}

	lt_env = getenv ("LTPROTO_RING_BUF");
	if (lt_env != NULL) {
		lt_ring_buf = strtoul (lt_env, NULL, 10);
	}

	return 0;
}

struct ltproto_socket *
shmem_pipe_socket_func (struct lt_module_ctx *ctx)
{
	struct ltproto_socket_shmem_pipe *sk;

	sk = lt_objcache_alloc (ctx->sk_cache);
	assert (sk != NULL);
	memset (sk, 0, sizeof (*sk));

	return (struct ltproto_socket *)sk;
}

int
shmem_pipe_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue)
{
	return setsockopt (sk->tcp_fd, SOL_SOCKET, optname, &optvalue, sizeof (optvalue));
}

int
shmem_pipe_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	return 0;
}

int
shmem_pipe_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog)
{
	return 0;
}

struct ltproto_socket *
shmem_pipe_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk,
		struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket_shmem_pipe *ssk = (struct ltproto_socket_shmem_pipe *)sk, *nsk;
	int ready = 1;
	char pipe_buf[PATH_MAX];

	nsk = lt_objcache_alloc (ctx->sk_cache);
	assert (nsk != NULL);

	/* Read tag to allocate */
	if (read (ssk->tcp_fd, &nsk->tag[0], sizeof (ssk->tag[0])) == -1) {
		lt_objcache_free (ctx->sk_cache, nsk);
		return NULL;
	}
	if (read (ssk->tcp_fd, &nsk->tag[1], sizeof (ssk->tag[0])) == -1) {
		lt_objcache_free (ctx->sk_cache, nsk);
		ready = 0;
		(void)write (ssk->tcp_fd, &ready, sizeof (int));
		return NULL;
	}
	/* Attach ring */
	nsk->rx_ring = ctx->lib_ctx->allocator->allocator_attachtag_func (ctx->lib_ctx->alloc_ctx,
			&nsk->tag[0]);
	nsk->tx_ring = ctx->lib_ctx->allocator->allocator_attachtag_func (ctx->lib_ctx->alloc_ctx,
				&nsk->tag[1]);

	if (nsk->rx_ring == NULL || nsk->tx_ring == NULL) {
		lt_objcache_free (ctx->sk_cache, nsk);
		return NULL;
	}

	nsk->rx_ring->ref ++;
	nsk->tx_ring->ref ++;

	/* Open pipes */
	snprintf (pipe_buf, sizeof (pipe_buf), "/tmp/lt_pipe_%llu_%llu", (long long unsigned)nsk->tag[0].id,
			(long long unsigned)nsk->tag[0].seq);
	nsk->rx_pipe = open (pipe_buf, O_RDWR);
	if (nsk->rx_pipe == -1) {
		lt_objcache_free (ctx->sk_cache, nsk);
		return NULL;
	}

	snprintf (pipe_buf, sizeof (pipe_buf), "/tmp/lt_pipe_%llu_%llu", (long long unsigned)nsk->tag[1].id,
			(long long unsigned)nsk->tag[1].seq);
	nsk->tx_pipe = open (pipe_buf, O_RDWR);
	if (nsk->tx_pipe == -1) {
		lt_objcache_free (ctx->sk_cache, nsk);
		return NULL;
	}

	if (write (ssk->tcp_fd, &ready, sizeof (int)) == -1) {
		lt_objcache_free (ctx->sk_cache, nsk);
		return NULL;
	}

	return (struct ltproto_socket *)nsk;
}

int
shmem_pipe_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk,
		const struct sockaddr *addr, socklen_t addrlen)
{
	struct ltproto_socket_shmem_pipe *ssk = (struct ltproto_socket_shmem_pipe *)sk;
	int ready = 0;
	char pipe_buf[PATH_MAX];

	/* Inverse the order of tags */
	ssk->rx_ring = ctx->lib_ctx->allocator->allocator_alloc_func (ctx->lib_ctx->alloc_ctx,
			LT_RING_SIZE (lt_ring_slots, lt_ring_buf), &ssk->tag[0]);
	ssk->tx_ring = ctx->lib_ctx->allocator->allocator_alloc_func (ctx->lib_ctx->alloc_ctx,
				LT_RING_SIZE (lt_ring_slots, lt_ring_buf), &ssk->tag[1]);

	if (ssk->rx_ring == NULL || ssk->tx_ring == NULL) {
		return -1;
	}

	shmem_pipe_init_ring (ssk->rx_ring, lt_ring_slots, lt_ring_buf);
	shmem_pipe_init_ring (ssk->tx_ring, lt_ring_slots, lt_ring_buf);

	/* Open pipes */
	snprintf (pipe_buf, sizeof (pipe_buf), "/tmp/lt_pipe_%llu_%llu", (long long unsigned)ssk->tag[0].id,
			(long long unsigned)ssk->tag[0].seq);
	mkfifo (pipe_buf, 0600);
	ssk->rx_pipe = open (pipe_buf, O_RDWR);
	if (ssk->rx_pipe == -1) {
		lt_objcache_free (ctx->sk_cache, ssk);
		return -1;
	}

	snprintf (pipe_buf, sizeof (pipe_buf), "/tmp/lt_pipe_%llu_%llu", (long long unsigned)ssk->tag[1].id,
			(long long unsigned)ssk->tag[1].seq);
	mkfifo (pipe_buf, 0600);
	ssk->tx_pipe = open (pipe_buf, O_RDWR);
	if (ssk->tx_pipe == -1) {
		lt_objcache_free (ctx->sk_cache, ssk);
		return -1;
	}

	/* Inverse the order of tags */
	if (write (ssk->tcp_fd, &ssk->tag[1], sizeof (ssk->tag[0])) == -1) {
		return -1;
	}
	if (write (ssk->tcp_fd, &ssk->tag[0], sizeof (ssk->tag[0])) == -1) {
		return -1;
	}
	ssk->ring_owner = 1;

	if (read (ssk->tcp_fd, &ready, sizeof (int)) == -1 || ready != 1) {
		return -1;
	}

	return 0;
}

static int
shmem_signal_pipe (volatile unsigned int *ptr, int signal_value, int set_value, int pipe_fd)
{
	int oldval;

	oldval = lt_int_atomic_xchg (ptr, set_value);

	if (oldval & signal_value) {
		//fprintf (stderr, "%d: signal: old: %d, desired: %d, signal: %d\n", getpid (), oldval, signal_value, set_value);
		if (write (pipe_fd, &oldval, sizeof (int)) == -1) {
			return -1;
		}
	}

	return 0;
}

static int
shmem_wait_pipe (volatile unsigned int *ptr, int desired_value, int wait_value, int forbidden_value, int pipe_fd)
{
	int val, rd;

	for (;;) {
		val = lt_int_atomic_get (ptr);

		if (val == desired_value || (val == forbidden_value)) {
			break;
		}
		if (lt_int_atomic_cmpxchg (ptr, val, wait_value) == val) {
			//fprintf (stderr, "%d: wait: old: %d, desired: %d, wait: %d\n", getpid (), val, desired_value, wait_value);
			if (read (pipe_fd, &rd, sizeof (int)) == -1) {
				return -1;
			}
			//fprintf (stderr, "%d: wakeup\n", getpid ());
			return shmem_wait_pipe (ptr, desired_value, wait_value, forbidden_value, pipe_fd);
		}
	}

	return 0;
}

ssize_t
shmem_pipe_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t orig_len)
{
	struct ltproto_socket_shmem_pipe *ssk = (struct ltproto_socket_shmem_pipe *)sk;
	struct lt_net_ring_slot *slot;
	unsigned char *cur;
	unsigned int len = orig_len;

	if (ssk->rx_ring == NULL) {
		/* Force TCP connection */
		return -1;
	}

	cur = buf;

	for (;;) {
		//fprintf (stderr, "read: %d\n", ssk->cur_rx);
		slot = &ssk->rx_ring->slot[ssk->cur_rx];
		if (shmem_wait_pipe (&slot->flags, LT_SLOT_FLAG_READY, LT_SLOT_FLAG_WAIT_READ,
				LT_SLOT_FLAG_WAIT_WRITE, ssk->rx_pipe) == -1) {
			return -1;
		}
		if (slot->len < len) {
			memcpy (cur, LT_RING_BUF (ssk->rx_ring, ssk->cur_rx), slot->len);
			cur += slot->len;
			len -= slot->len;
			ssk->cur_rx = LT_RING_NEXT (ssk->rx_ring, ssk->cur_rx);
			shmem_signal_pipe (&slot->flags, LT_SLOT_FLAG_WAIT, LT_SLOT_FLAG_FREE, ssk->tx_pipe);
		}
		else {
			memcpy (cur, LT_RING_BUF (ssk->rx_ring, ssk->cur_rx), len);
			if (len == slot->len) {
				/* Aligned case */
				ssk->cur_rx = LT_RING_NEXT (ssk->rx_ring, ssk->cur_rx);
				shmem_signal_pipe (&slot->flags, LT_SLOT_FLAG_WAIT, LT_SLOT_FLAG_FREE, ssk->tx_pipe);
			}
			else {
				memcpy (LT_RING_BUF (ssk->rx_ring, ssk->cur_rx),
						LT_RING_BUF (ssk->rx_ring, ssk->cur_rx) + slot->len,
						ssk->rx_ring->buf_size - slot->len);
			}
			return orig_len;
		}
	}

	/* Not reached */
	return -1;
}

ssize_t
shmem_pipe_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t orig_len)
{
	struct ltproto_socket_shmem_pipe *ssk = (struct ltproto_socket_shmem_pipe *)sk;
	struct lt_net_ring_slot *slot;
	const unsigned char *cur;
	unsigned int len = orig_len;

	if (ssk->tx_ring == NULL) {
		/* Force TCP connection */
		return -1;
	}

	cur = buf;

	for (;;) {
		slot = &ssk->tx_ring->slot[ssk->cur_tx];
		//fprintf (stderr, "write: %d\n", ssk->cur_tx);
		if (shmem_wait_pipe (&slot->flags, LT_SLOT_FLAG_FREE,
				LT_SLOT_FLAG_WAIT_WRITE, LT_SLOT_FLAG_WAIT_READ, ssk->rx_pipe) == -1) {
			return -1;
		}
		if (ssk->tx_ring->buf_size < len) {
			memcpy (LT_RING_BUF (ssk->tx_ring, ssk->cur_tx), cur, ssk->tx_ring->buf_size);
			slot->len = ssk->tx_ring->buf_size;
			cur += slot->len;
			len -= slot->len;
			ssk->cur_tx = LT_RING_NEXT (ssk->tx_ring, ssk->cur_tx);
			shmem_signal_pipe (&slot->flags, LT_SLOT_FLAG_WAIT, LT_SLOT_FLAG_READY, ssk->tx_pipe);
		}
		else {
			memcpy (LT_RING_BUF (ssk->tx_ring, ssk->cur_tx), cur, len);
			ssk->cur_tx = LT_RING_NEXT (ssk->tx_ring, ssk->cur_tx);
			slot->len = len;
			shmem_signal_pipe (&slot->flags, LT_SLOT_FLAG_WAIT, LT_SLOT_FLAG_READY, ssk->tx_pipe);
			return orig_len;
		}
	}
	return -1;
}

int
shmem_pipe_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv)
{
	struct pollfd pfd;
	int msec = -1;

	pfd.events = what;
	pfd.fd = sk->fd;

	if (tv != NULL) {
		msec = tv_to_msec (tv);
	}

	return poll (&pfd, 1, msec);
}

int
shmem_pipe_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	struct ltproto_socket_shmem_pipe *ssk = (struct ltproto_socket_shmem_pipe *)sk;
	char pipe_buf[PATH_MAX];

	if (ssk->rx_ring != NULL && ssk->tx_ring != NULL) {
		ssk->tx_ring->ref --;
		ssk->rx_ring->ref --;
	}

	if (ssk->ring_owner) {
		snprintf (pipe_buf, sizeof (pipe_buf), "/tmp/lt_pipe_%llu_%llu", (long long unsigned)ssk->tag[0].id,
				(long long unsigned)ssk->tag[0].seq);
		unlink (pipe_buf);

		snprintf (pipe_buf, sizeof (pipe_buf), "/tmp/lt_pipe_%llu_%llu", (long long unsigned)ssk->tag[1].id,
				(long long unsigned)ssk->tag[1].seq);
		unlink (pipe_buf);
	}

	close (ssk->rx_pipe);
	close (ssk->tx_pipe);

	lt_objcache_free (ctx->sk_cache, ssk);

	return 0;
}

int
shmem_pipe_destroy_func (struct lt_module_ctx *ctx)
{
	lt_objcache_destroy (ctx->sk_cache);
	free (ctx);
	return 0;
}
