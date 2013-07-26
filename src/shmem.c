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
int shmem_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv);
int shmem_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk);
int shmem_destroy_func (struct lt_module_ctx *ctx);

module_t shmem_module = {
		.name = "shmem",
		.priority = 10,
		.module_init_func = shmem_init_func,
		.module_socket_func = shmem_socket_func,
		.module_setopts_func = shmem_setopts_func,
		.module_bind_func = shmem_bind_func,
		.module_listen_func = shmem_listen_func,
		.module_accept_func = shmem_accept_func,
		.module_connect_func = shmem_connect_func,
		.module_read_func = shmem_read_func,
		.module_write_func = shmem_write_func,
		.module_select_func = shmem_select_func,
		.module_close_func = shmem_close_func,
		.module_destroy_func = shmem_destroy_func
};

#define LT_DEFAULT_SLOTS 10
#define LT_DEFAULT_BUF 32768

struct lt_net_ring_slot {
	unsigned int len;
	unsigned int flags;
#define LT_SLOT_FLAG_READY 0x1
};

struct lt_net_ring {
	unsigned int num_slots;
	unsigned int cur;
	unsigned int avail;

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
	struct lt_alloc_tag tag[2];		// Connected tags
};


int
shmem_init_func (struct lt_module_ctx **ctx)
{
	*ctx = calloc (1, sizeof (struct lt_module_ctx));
	(*ctx)->len = sizeof (struct lt_module_ctx);
	(*ctx)->sk_cache = lt_objcache_create (sizeof (struct ltproto_socket_shmem));

	return 0;
}

struct ltproto_socket *
shmem_socket_func (struct lt_module_ctx *ctx)
{
	struct ltproto_socket_shmem *sk;

	sk = lt_objcache_alloc (ctx->sk_cache);
	assert (sk != NULL);

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

	nsk = lt_objcache_alloc (ctx->sk_cache);
	assert (nsk != NULL);

	/* Read tag to allocate */
	if (read (ssk->tcp_fd, &nsk->tag, sizeof (ssk->tag[0]) * 2) == -1) {
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
		return NULL;
	}

	return (struct ltproto_socket *)nsk;
}

int
shmem_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	struct ltproto_socket_shmem *ssk = (struct ltproto_socket_shmem *)sk;

	/* Inverse the order of tags */
	ssk->rx_ring = ctx->lib_ctx->allocator->allocator_alloc_func (ctx->lib_ctx->alloc_ctx,
			LT_RING_SIZE (LT_DEFAULT_SLOTS, LT_DEFAULT_BUF), &ssk->tag[1]);
	ssk->tx_ring = ctx->lib_ctx->allocator->allocator_alloc_func (ctx->lib_ctx->alloc_ctx,
				LT_RING_SIZE (LT_DEFAULT_SLOTS, LT_DEFAULT_BUF), &ssk->tag[0]);

	if (ssk->rx_ring == NULL || ssk->tx_ring == NULL) {
		return -1;
	}

	/* Send tag */
	if (write (ssk->tcp_fd, &ssk->tag, sizeof (ssk->tag[0]) * 2) == -1) {
		ctx->lib_ctx->allocator->allocator_free_func (ctx->lib_ctx->alloc_ctx,
				&ssk->tag, sizeof (ssk->tag));
		return -1;
	}

	return 0;
}

ssize_t
shmem_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len)
{
	/* Force TCP connection */
	return -1;
}

ssize_t
shmem_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len)
{
	/* Force TCP connection */
	return -1;
}

int
shmem_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv)
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
shmem_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	lt_objcache_free (ctx->sk_cache, sk);

	return 0;
}

int
shmem_destroy_func (struct lt_module_ctx *ctx)
{
	lt_objcache_destroy (ctx->sk_cache);
	free (ctx);
	return 0;
}
