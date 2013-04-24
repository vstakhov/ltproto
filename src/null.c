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
 * @file null.c
 * @section DESCRIPTION
 *
 * Test module for ltopt that just uses ordinary BSD sockets
 */

int null_init_func (struct lt_module_ctx **ctx);
struct ltproto_socket* null_socket_func (struct lt_module_ctx *ctx);
int null_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue);
int null_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
int null_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog);
struct ltproto_socket* null_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen);
int null_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
ssize_t null_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len);
ssize_t null_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len);
int null_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv);
int null_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk);
int null_destroy_func (struct lt_module_ctx *ctx);

module_t null_module = {
	.name = "null",
	.priority = 0,
	.module_init_func = null_init_func,
	.module_socket_func = null_socket_func,
	.module_setopts_func = null_setopts_func,
	.module_bind_func = null_bind_func,
	.module_listen_func = null_listen_func,
	.module_accept_func = null_accept_func,
	.module_connect_func = null_connect_func,
	.module_read_func = null_read_func,
	.module_write_func = null_write_func,
	.module_select_func = null_select_func,
	.module_close_func = null_close_func,
	.module_destroy_func = null_destroy_func
};

int
null_init_func (struct lt_module_ctx **ctx)
{
	*ctx = calloc (1, sizeof (struct lt_module_ctx));
	(*ctx)->len = sizeof (struct lt_module_ctx);
	(*ctx)->sk_cache = lt_objcache_create (sizeof (struct ltproto_socket));

	return 0;
}

struct ltproto_socket *
null_socket_func (struct lt_module_ctx *ctx)
{
	struct ltproto_socket *sk;

	sk = lt_objcache_alloc (ctx->sk_cache);
	assert (sk != NULL);
	sk->fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk->fd == -1) {
		lt_objcache_free (ctx->sk_cache, sk);
		return NULL;
	}

	return sk;
}

int
null_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue)
{
	return setsockopt (sk->fd, SOL_SOCKET, optname, &optvalue, sizeof (optvalue));
}

int
null_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{

	return 0;
}

int
null_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog)
{
	return 0;
}

struct ltproto_socket *
null_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket *nsk;
	int afd;

	afd = dup (sk->fd);
	if (afd == -1) {
		return NULL;
	}

	nsk = lt_objcache_alloc (ctx->sk_cache);
	assert (nsk != NULL);
	nsk->fd = afd;

	return nsk;
}

int
null_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	return 0;
}

ssize_t
null_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len)
{
	/* Force TCP connection */
	return -1;
}

ssize_t
null_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len)
{
	/* Force TCP connection */
	return -1;
}

int
null_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv)
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
null_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	int serrno, ret;

	ret = close (sk->fd);
	serrno = errno;
	lt_objcache_free (ctx->sk_cache, sk);
	errno = serrno;

	return ret;
}

int
null_destroy_func (struct lt_module_ctx *ctx)
{
	lt_objcache_destroy (ctx->sk_cache);
	free (ctx);
	return 0;
}
