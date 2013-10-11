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
 * @file shmem.c
 * @section DESCRIPTION
 *
 * This module implements the pure shared memory channel using futexes or sleep
 * for synchronization.
 * We use an ordinary TCP socket for accept and listen for a connection.
 * Connecting socket is responsible for allocating shmem ring.
 */

int shmem_init_func (struct lt_module_ctx **ctx);
struct ltproto_socket* shmem_socket_func (struct lt_module_ctx *ctx);
int shmem_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue);
int shmem_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
int shmem_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog);
struct ltproto_socket* shmem_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen);
int shmem_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
ssize_t shmem_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len);
ssize_t shmem_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len);
int shmem_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk);
int shmem_destroy_func (struct lt_module_ctx *ctx);

module_t shmem_module = {
		.name = "shmem",
		.priority = 10,
		.pollable = false,
		.module_init_func = shmem_init_func,
		.module_socket_func = shmem_socket_func,
		.module_setopts_func = shmem_setopts_func,
		.module_bind_func = shmem_bind_func,
		.module_listen_func = shmem_listen_func,
		.module_accept_func = shmem_accept_func,
		.module_connect_func = shmem_connect_func,
		.module_read_func = shmem_read_func,
		.module_write_func = shmem_write_func,
		.module_close_func = shmem_close_func,
		.module_destroy_func = shmem_destroy_func
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
#define LT_SLOT_FLAG_CLOSED 0x8
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

struct ltproto_socket_shmem {
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
};

static void
shmem_init_ring (struct lt_net_ring *ring, int nslots, int bufsize)
{
	memset (ring, 0, LT_RING_SIZE (nslots, bufsize));
	ring->buf_size = bufsize;
	ring->buf_offset = offsetof(struct lt_net_ring, slot) +
				nslots * sizeof (struct lt_net_ring_slot);
	ring->num_slots = nslots;
	ring->ref = 1;
}

int
shmem_init_func (struct lt_module_ctx **ctx)
{
	char *lt_env;

	*ctx = calloc (1, sizeof (struct lt_module_ctx));
	(*ctx)->len = sizeof (struct lt_module_ctx);
	(*ctx)->sk_cache = lt_objcache_create (sizeof (struct ltproto_socket_shmem));

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
shmem_socket_func (struct lt_module_ctx *ctx)
{
	struct ltproto_socket_shmem *sk;

	sk = lt_objcache_alloc (ctx->sk_cache);
	assert (sk != NULL);
	memset (sk, 0, sizeof (*sk));

	return (struct ltproto_socket *)sk;
}

int
shmem_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue)
{
	return setsockopt (sk->tcp_fd, SOL_SOCKET, optname, &optvalue, sizeof (optvalue));
}

int
shmem_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	return 0;
}

int
shmem_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog)
{
	return 0;
}

struct ltproto_socket *
shmem_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket_shmem *ssk = (struct ltproto_socket_shmem *)sk, *nsk;
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
		return NULL;
	}
	/* Attach ring */
	nsk->rx_ring = ctx->lib_ctx->allocator->allocator_attachtag_func (ctx->lib_ctx->alloc_ctx,
			&nsk->tag[0]);
	nsk->tx_ring = ctx->lib_ctx->allocator->allocator_attachtag_func (ctx->lib_ctx->alloc_ctx,
				&nsk->tag[1]);

	if (nsk->rx_ring == NULL || nsk->tx_ring == NULL) {
		lt_objcache_free (ctx->sk_cache, nsk);
		ready = 0;
		(void)write (ssk->tcp_fd, &ready, sizeof (int));
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
shmem_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	struct ltproto_socket_shmem *ssk = (struct ltproto_socket_shmem *)sk;
	int ready = 0;

	ssk->rx_ring = ctx->lib_ctx->allocator->allocator_alloc_func (ctx->lib_ctx->alloc_ctx,
			LT_RING_SIZE (lt_ring_slots, lt_ring_buf), &ssk->tag[0]);
	ssk->tx_ring = ctx->lib_ctx->allocator->allocator_alloc_func (ctx->lib_ctx->alloc_ctx,
				LT_RING_SIZE (lt_ring_slots, lt_ring_buf), &ssk->tag[1]);
	if (ssk->rx_ring == NULL || ssk->tx_ring == NULL) {
		return -1;
	}

	shmem_init_ring (ssk->rx_ring, lt_ring_slots, lt_ring_buf);
	shmem_init_ring (ssk->tx_ring, lt_ring_slots, lt_ring_buf);

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
shmem_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t orig_len)
{
	struct ltproto_socket_shmem *ssk = (struct ltproto_socket_shmem *)sk;
	struct lt_net_ring_slot *slot;
	unsigned char *cur;
	unsigned int len = orig_len;

	if (ssk->rx_ring == NULL) {
		/* Force TCP connection */
		return -1;
	}

	cur = buf;

	for (;;) {
		slot = &ssk->rx_ring->slot[ssk->cur_rx];
		//fprintf (stderr, "read ring: %d\n", ssk->cur_rx);
		if (ssk->rx_ring->ref == 1) {
			return 0;
		}
		if (slot->flags & LT_SLOT_FLAG_CLOSED) {
			return 0;
		}
		if (wait_for_memory_state (&slot->flags, LT_SLOT_FLAG_READY,
				LT_SLOT_FLAG_WAIT_READ, LT_SLOT_FLAG_WAIT_WRITE) == -1) {
			return -1;
		}
		if (slot->flags & LT_SLOT_FLAG_CLOSED) {
			return 0;
		}
		if (slot->len < len) {
			memcpy (cur, LT_RING_BUF (ssk->rx_ring, ssk->cur_rx), slot->len);
			cur += slot->len;
			len -= slot->len;
			ssk->cur_rx = LT_RING_NEXT (ssk->rx_ring, ssk->cur_rx);
			//slot->flags = LT_SLOT_FLAG_FREE;
			//shmem_queue_slot (slot, ssk);
			signal_memory (&slot->flags, LT_SLOT_FLAG_WAIT, LT_SLOT_FLAG_FREE);
		}
		else {
			memcpy (cur, LT_RING_BUF (ssk->rx_ring, ssk->cur_rx), len);
			if (len == slot->len) {
				/* Aligned case */
				ssk->cur_rx = LT_RING_NEXT (ssk->rx_ring, ssk->cur_rx);
				//slot->flags = LT_SLOT_FLAG_FREE;
				//shmem_queue_slot (slot, ssk);
				signal_memory (&slot->flags, LT_SLOT_FLAG_WAIT, LT_SLOT_FLAG_FREE);
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
shmem_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t orig_len)
{
	struct ltproto_socket_shmem *ssk = (struct ltproto_socket_shmem *)sk;
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
		//fprintf (stderr, "write ring: %d\n", ssk->cur_tx);
		if (slot->flags & LT_SLOT_FLAG_CLOSED) {
			return 0;
		}
		if (wait_for_memory_state (&slot->flags, LT_SLOT_FLAG_FREE,
				LT_SLOT_FLAG_WAIT_WRITE, LT_SLOT_FLAG_WAIT_READ) == -1) {
			return -1;
		}
		if (slot->flags & LT_SLOT_FLAG_CLOSED) {
			return 0;
		}
		if (ssk->tx_ring->buf_size < len) {
			memcpy (LT_RING_BUF (ssk->tx_ring, ssk->cur_tx), cur, ssk->tx_ring->buf_size);
			slot->len = ssk->tx_ring->buf_size;
			cur += slot->len;
			len -= slot->len;
			ssk->cur_tx = LT_RING_NEXT (ssk->tx_ring, ssk->cur_tx);
			//slot->flags = LT_SLOT_FLAG_READY;
			//shmem_queue_slot (slot, ssk);
			signal_memory (&slot->flags, LT_SLOT_FLAG_WAIT, LT_SLOT_FLAG_READY);
		}
		else {
			memcpy (LT_RING_BUF (ssk->tx_ring, ssk->cur_tx), cur, len);
			ssk->cur_tx = LT_RING_NEXT (ssk->tx_ring, ssk->cur_tx);
			slot->len = len;
			//slot->flags = LT_SLOT_FLAG_READY;
			//shmem_queue_slot (slot, ssk);
			signal_memory (&slot->flags, LT_SLOT_FLAG_WAIT, LT_SLOT_FLAG_READY);
			return orig_len;
		}
	}
	return -1;
}

int
shmem_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	struct ltproto_socket_shmem *ssk = (struct ltproto_socket_shmem *)sk;
	struct lt_net_ring_slot *slot;
	unsigned int i;

	//fprintf (stderr, "closing\n");
	if (ssk->rx_ring != NULL && ssk->tx_ring != NULL) {
		for (i = 0; i < ssk->rx_ring->num_slots; i ++) {
			slot = &ssk->rx_ring->slot[i];
			signal_memory (&slot->flags, LT_SLOT_FLAG_WAIT, LT_SLOT_FLAG_CLOSED);
		}
		for (i = 0; i < ssk->tx_ring->num_slots; i ++) {
			slot = &ssk->tx_ring->slot[i];
			signal_memory (&slot->flags, LT_SLOT_FLAG_WAIT, LT_SLOT_FLAG_CLOSED);
		}

		ssk->tx_ring->ref --;
		ssk->rx_ring->ref --;
	}

	lt_objcache_free (ctx->sk_cache, ssk);

	return 0;
}

int
shmem_destroy_func (struct lt_module_ctx *ctx)
{
	lt_objcache_destroy (ctx->sk_cache);
	free (ctx);
	return 0;
}
