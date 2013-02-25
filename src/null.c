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

	return 0;
}

struct ltproto_socket *
null_socket_func (struct lt_module_ctx *ctx)
{
	struct ltproto_socket *sk;

	sk = calloc (1, sizeof (struct ltproto_socket));
	assert (sk != NULL);
	sk->fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk->fd == -1) {
		free (sk);
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
	int reuseaddr = 1;

	setsockopt (sk->fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof (int));
	return bind (sk->fd, addr, addrlen);
}

int
null_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog)
{
	return listen (sk->fd, backlog);
}

struct ltproto_socket *
null_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket *nsk;
	int afd;

	afd = accept (sk->fd, addr, addrlen);
	if (afd == -1) {
		return NULL;
	}

	nsk = calloc (1, sizeof (struct ltproto_socket));
	assert (nsk != NULL);
	nsk->fd = afd;

	return nsk;
}

int
null_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	return connect (sk->fd, addr, addrlen);
}

ssize_t
null_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len)
{
	return read (sk->fd, buf, len);
}

ssize_t
null_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len)
{
	return write (sk->fd, buf, len);
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
	return close (sk->fd);
}

int
null_destroy_func (struct lt_module_ctx *ctx)
{
	free (ctx);
	return 0;
}
