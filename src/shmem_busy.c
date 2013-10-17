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
 * @file shmem_busy.c
 * @section DESCRIPTION
 *
 * This module implements the pure shared memory channel using futexes or sleep
 * for synchronization.
 * We use an ordinary TCP socket for accept and listen for a connection.
 * Connecting socket is responsible for allocating shmem_busy ring.
 */

int shmem_busy_init_func (struct lt_module_ctx **ctx);
struct ltproto_socket* shmem_busy_socket_func (struct lt_module_ctx *ctx);
int shmem_busy_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue);
int shmem_busy_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
int shmem_busy_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog);
struct ltproto_socket* shmem_busy_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen);
int shmem_busy_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
ssize_t shmem_busy_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len);
ssize_t shmem_busy_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len);
int shmem_busy_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk);
int shmem_busy_destroy_func (struct lt_module_ctx *ctx);

module_t shmem_busy_module = {
		.name = "shmem_busy",
		.priority = 10,
		.pollable = false,
		.module_init_func = shmem_busy_init_func,
		.module_socket_func = shmem_busy_socket_func,
		.module_setopts_func = shmem_busy_setopts_func,
		.module_bind_func = shmem_busy_bind_func,
		.module_listen_func = shmem_busy_listen_func,
		.module_accept_func = shmem_busy_accept_func,
		.module_connect_func = shmem_busy_connect_func,
		.module_read_func = shmem_busy_read_func,
		.module_write_func = shmem_busy_write_func,
		.module_close_func = shmem_busy_close_func,
		.module_destroy_func = shmem_busy_destroy_func
};

#define LT_DEFAULT_SLOTS 256
#define LT_DEFAULT_BUF 4096

static int lt_ring_slots = LT_DEFAULT_SLOTS;
static int lt_ring_buf = LT_DEFAULT_BUF;

struct lt_net_ring_slot {
	unsigned int len;
};

struct lt_net_ring {
	unsigned int num_slots;
	unsigned int ref;

	size_t buf_offset;
	size_t buf_size;

	/* Read pos */
	volatile uint32_t head;
	volatile char __pad1[CACHELINE - sizeof(uint32_t)];

	/* Write pos */
	volatile uint32_t tail;
	volatile char __pad2[CACHELINE - sizeof(uint32_t)];

	struct lt_net_ring_slot slot[0];
};

#define LT_RING_BUF(ring, index)                         \
        ((char *)(ring) + (ring)->buf_offset + ((index)*(ring)->buf_size))

#define NEXT(x, r)     ((x + 1) & ((r)->num_slots - 1))
#define EMPTY(x)    ((x)->head == (x)->tail)
#define FULL(x)     ((x)->head == NEXT((x)->tail, (x)))
#define LT_RING_SIZE(slots, bufsize)                     \
        (sizeof (struct lt_net_ring) + sizeof (struct lt_net_ring_slot) * (slots) +  \
        (bufsize) * (slots))

struct ltproto_socket_shmem_busy {
	int fd;							// Socket descriptor
	int tcp_fd;						// TCP link socket
	struct ltproto_module *mod;		// Module handling this socket
	UT_hash_handle hh;				// Hash entry

	struct lt_net_ring *rx_ring;	// Input
	struct lt_net_ring *tx_ring;	// Output
	struct lt_alloc_tag tag[2];		// Connected tags
	int ring_owner;					// The owner of rings
};

static void
shmem_busy_init_ring (struct lt_net_ring *ring, int nslots, int bufsize)
{
	memset (ring, 0, LT_RING_SIZE (nslots, bufsize));
	ring->buf_size = bufsize;
	ring->buf_offset = offsetof(struct lt_net_ring, slot) +
				nslots * sizeof (struct lt_net_ring_slot);
	ring->num_slots = nslots;
	ring->ref = 1;
}

int
shmem_busy_init_func (struct lt_module_ctx **ctx)
{
	char *lt_env;

	*ctx = calloc (1, sizeof (struct lt_module_ctx));
	(*ctx)->len = sizeof (struct lt_module_ctx);
	(*ctx)->sk_cache = lt_objcache_create (sizeof (struct ltproto_socket_shmem_busy));

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
shmem_busy_socket_func (struct lt_module_ctx *ctx)
{
	struct ltproto_socket_shmem_busy *sk;

	sk = lt_objcache_alloc (ctx->sk_cache);
	assert (sk != NULL);
	memset (sk, 0, sizeof (*sk));

	return (struct ltproto_socket *)sk;
}

int
shmem_busy_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue)
{
	return setsockopt (sk->tcp_fd, SOL_SOCKET, optname, &optvalue, sizeof (optvalue));
}

int
shmem_busy_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	return 0;
}

int
shmem_busy_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog)
{
	return 0;
}

struct ltproto_socket *
shmem_busy_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk,
		struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket_shmem_busy *ssk = (struct ltproto_socket_shmem_busy *)sk, *nsk;
	int ready = 1;

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

	if (write (ssk->tcp_fd, &ready, sizeof (int)) == -1) {
		lt_objcache_free (ctx->sk_cache, nsk);
		return NULL;
	}

	return (struct ltproto_socket *)nsk;
}

int
shmem_busy_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk,
		const struct sockaddr *addr, socklen_t addrlen)
{
	struct ltproto_socket_shmem_busy *ssk = (struct ltproto_socket_shmem_busy *)sk;
	int ready = 0;

	/* Inverse the order of tags */
	ssk->rx_ring = ctx->lib_ctx->allocator->allocator_alloc_func (ctx->lib_ctx->alloc_ctx,
			LT_RING_SIZE (lt_ring_slots, lt_ring_buf), &ssk->tag[0]);
	ssk->tx_ring = ctx->lib_ctx->allocator->allocator_alloc_func (ctx->lib_ctx->alloc_ctx,
				LT_RING_SIZE (lt_ring_slots, lt_ring_buf), &ssk->tag[1]);

	if (ssk->rx_ring == NULL || ssk->tx_ring == NULL) {
		return -1;
	}

	shmem_busy_init_ring (ssk->rx_ring, lt_ring_slots, lt_ring_buf);
	shmem_busy_init_ring (ssk->tx_ring, lt_ring_slots, lt_ring_buf);

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

ssize_t
shmem_busy_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t orig_len)
{
	struct ltproto_socket_shmem_busy *ssk = (struct ltproto_socket_shmem_busy *)sk;
	struct lt_net_ring_slot *slot;
	unsigned char *cur;
	unsigned int len = orig_len;

	if (ssk->rx_ring == NULL) {
		/* Force TCP connection */
		return -1;
	}

	cur = buf;

	for (;;) {
		if (ssk->rx_ring->ref == 1) {
			return 0;
		}
		//fprintf (stderr, "read: %d\n", ssk->cur_rx);
		/* Busy loop here */
		while (EMPTY (ssk->rx_ring)) {
			continue;
		}

		slot = &ssk->rx_ring->slot[ssk->rx_ring->tail];
		if (slot->len < len) {
			memcpy (cur, LT_RING_BUF (ssk->rx_ring, ssk->rx_ring->tail), slot->len);
			cur += slot->len;
			len -= slot->len;
			ssk->rx_ring->tail = NEXT (ssk->rx_ring->tail, ssk->rx_ring);
		}
		else {
			memcpy (cur, LT_RING_BUF (ssk->rx_ring, ssk->rx_ring->tail), len);
			if (len == slot->len) {
				/* Aligned case */
				ssk->rx_ring->tail = NEXT (ssk->rx_ring->tail, ssk->rx_ring);
			}
			else {
				memcpy (LT_RING_BUF (ssk->rx_ring, ssk->rx_ring->tail),
						LT_RING_BUF (ssk->rx_ring, ssk->rx_ring->tail) + slot->len,
						ssk->rx_ring->buf_size - slot->len);
			}
			return orig_len;
		}
	}

	/* Not reached */
	return -1;
}

ssize_t
shmem_busy_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t orig_len)
{
	struct ltproto_socket_shmem_busy *ssk = (struct ltproto_socket_shmem_busy *)sk;
	struct lt_net_ring_slot *slot;
	const unsigned char *cur;
	unsigned int len = orig_len;

	if (ssk->tx_ring == NULL) {
		/* Force TCP connection */
		return -1;
	}

	cur = buf;

	for (;;) {
		//fprintf (stderr, "write: %d\n", ssk->cur_tx);
		while (FULL (ssk->tx_ring)) {
			continue;
		}
		slot = &ssk->tx_ring->slot[ssk->tx_ring->head];
		if (ssk->tx_ring->buf_size < len) {
			memcpy (LT_RING_BUF (ssk->tx_ring, ssk->tx_ring->head), cur, ssk->tx_ring->buf_size);
			slot->len = ssk->tx_ring->buf_size;
			cur += slot->len;
			len -= slot->len;
			ssk->tx_ring->head = NEXT (ssk->tx_ring->head, ssk->tx_ring);
		}
		else {
			memcpy (LT_RING_BUF (ssk->tx_ring, ssk->tx_ring->head), cur, len);
			slot->len = len;
			ssk->tx_ring->head = NEXT (ssk->tx_ring->head, ssk->tx_ring);
			return orig_len;
		}
	}
	return -1;
}

int
shmem_busy_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	struct ltproto_socket_shmem_busy *ssk = (struct ltproto_socket_shmem_busy *)sk;

	if (ssk->rx_ring != NULL && ssk->tx_ring != NULL) {
		ssk->tx_ring->ref --;
		ssk->rx_ring->ref --;
	}

	lt_objcache_free (ctx->sk_cache, ssk);

	return 0;
}

int
shmem_busy_destroy_func (struct lt_module_ctx *ctx)
{
	lt_objcache_destroy (ctx->sk_cache);
	free (ctx);
	return 0;
}
