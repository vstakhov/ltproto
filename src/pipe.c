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
 * @file pipe.c
 * @section DESCRIPTION
 *
 * Module that uses named pipe for data transfer
 */

int pipe_init_func (struct lt_module_ctx **ctx);
struct ltproto_socket* pipe_socket_func (struct lt_module_ctx *ctx);
int pipe_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue);
int pipe_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
int pipe_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog);
struct ltproto_socket* pipe_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen);
int pipe_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
ssize_t pipe_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len);
ssize_t pipe_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len);
int pipe_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv);
int pipe_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk);
int pipe_destroy_func (struct lt_module_ctx *ctx);

module_t pipe_module = {
	.name = "pipe",
	.priority = 0,
	.module_init_func = pipe_init_func,
	.module_socket_func = pipe_socket_func,
	.module_setopts_func = pipe_setopts_func,
	.module_bind_func = pipe_bind_func,
	.module_listen_func = pipe_listen_func,
	.module_accept_func = pipe_accept_func,
	.module_connect_func = pipe_connect_func,
	.module_read_func = pipe_read_func,
	.module_write_func = pipe_write_func,
	.module_select_func = pipe_select_func,
	.module_close_func = pipe_close_func,
	.module_destroy_func = pipe_destroy_func
};

int
pipe_init_func (struct lt_module_ctx **ctx)
{
	*ctx = calloc (1, sizeof (struct lt_module_ctx));
	(*ctx)->len = sizeof (struct lt_module_ctx);
	(*ctx)->sk_cache = lt_objcache_create (sizeof (struct ltproto_socket));

	return 0;
}

struct ltproto_socket *
pipe_socket_func (struct lt_module_ctx *ctx)
{
	struct ltproto_socket *sk;

	sk = lt_objcache_alloc (ctx->sk_cache);
	assert (sk != NULL);

	return sk;
}

int
pipe_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue)
{
	return -1;
}

int
pipe_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	return 0;
}

int
pipe_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog)
{
	return 0;
}

struct ltproto_socket *
pipe_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket *nsk;
	char fifoname[PATH_MAX];
	int afd, len;

	if (read (sk->tcp_fd, &len, sizeof (len)) == -1) {
		return NULL;
	}
	if (read (sk->tcp_fd, fifoname, MIN (len, sizeof (fifoname) - 1)) == -1) {
		return NULL;
	}

	afd = open (fifoname, O_RDWR);
	if (afd == -1) {
		return NULL;
	}

	nsk = lt_objcache_alloc (ctx->sk_cache);
	assert (nsk != NULL);
	nsk->fd = afd;

	return nsk;
}

int
pipe_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	char tmpname[PATH_MAX] = "/tmp/ltproto_pipe_XXXXXX";
	int len;

	mkdtemp (tmpname);
	len = strlen (tmpname);
	snprintf (tmpname + len, sizeof (tmpname) - len, "/fifo");
	assert (mkfifo (tmpname, 0600) == 0);
	sk->fd = open (tmpname, O_RDWR);
	if (sk->fd == -1) {
		return -1;
	}

	/* Send pipe name over tcp socket */
	len = strlen (tmpname);
	if (write (sk->tcp_fd, &len, sizeof (len)) == -1) {
		close (sk->fd);
		return -1;
	}
	if (write (sk->tcp_fd, tmpname, len) == -1) {
		close (sk->fd);
		return -1;
	}

	return sk->fd;
}

ssize_t
pipe_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len)
{
	return read (sk->fd, buf, len);
}

ssize_t
pipe_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len)
{
	return write (sk->fd, buf, len);
}

int
pipe_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv)
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
pipe_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	int serrno, ret;
	struct sockaddr_un sun;

	ret = close (sk->fd);
	serrno = errno;
	lt_objcache_free (ctx->sk_cache, sk);
	errno = serrno;

	return ret;
}

int
pipe_destroy_func (struct lt_module_ctx *ctx)
{
	lt_objcache_destroy (ctx->sk_cache);
	free (ctx);
	return 0;
}

