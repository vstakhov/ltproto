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
int pipe_get_wait_fd (struct lt_module_ctx *ctx, struct ltproto_socket *sk);
int pipe_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk);
int pipe_destroy_func (struct lt_module_ctx *ctx);

module_t pipe_module = {
	.name = "pipe",
	.priority = 0,
	.pollable = true,
	.module_init_func = pipe_init_func,
	.module_socket_func = pipe_socket_func,
	.module_setopts_func = pipe_setopts_func,
	.module_bind_func = pipe_bind_func,
	.module_listen_func = pipe_listen_func,
	.module_accept_func = pipe_accept_func,
	.module_connect_func = pipe_connect_func,
	.module_read_func = pipe_read_func,
	.module_write_func = pipe_write_func,
	.module_get_wait_fd = pipe_get_wait_fd,
	.module_close_func = pipe_close_func,
	.module_destroy_func = pipe_destroy_func
};

struct ltproto_socket_pipe {
	int fd;							// Socket descriptor
	int tcp_fd;						// TCP link socket
	struct ltproto_module *mod;		// Module handling this socket
	UT_hash_handle hh;				// Hash entry
	char *pname;					// The name of pipe
};

int
pipe_init_func (struct lt_module_ctx **ctx)
{
	*ctx = calloc (1, sizeof (struct lt_module_ctx));
	(*ctx)->len = sizeof (struct lt_module_ctx);
	(*ctx)->sk_cache = lt_objcache_create (sizeof (struct ltproto_socket_pipe));

	return 0;
}

struct ltproto_socket *
pipe_socket_func (struct lt_module_ctx *ctx)
{
	struct ltproto_socket_pipe *sk;

	sk = lt_objcache_alloc (ctx->sk_cache);
	sk->pname = NULL;
	assert (sk != NULL);

	return (struct ltproto_socket *)sk;
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
	struct ltproto_socket_pipe *nsk;
	char fifoname[PATH_MAX];
	int afd, len, r, ready;

	while (read (sk->tcp_fd, &len, sizeof (len)) == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			return NULL;
		}
	}
	while ((r = lt_read (sk->tcp_fd, fifoname, MIN (len, sizeof (fifoname) - 1))) == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			return NULL;
		}
	}

	fifoname[r] = '\0';

	afd = open (fifoname, O_RDWR);
	if (afd == -1) {
		ready = 0;
		write (sk->tcp_fd, &ready, sizeof (int));
		return NULL;
	}

	nsk = lt_objcache_alloc (ctx->sk_cache);
	assert (nsk != NULL);
	nsk->fd = afd;
	nsk->pname = NULL;

	ready = 1;
	if (write (sk->tcp_fd, &ready, sizeof (int)) == -1) {
		lt_objcache_free (ctx->sk_cache, nsk);
		return NULL;
	}

	return (struct ltproto_socket *)nsk;
}

static void
pipe_remove_pipe (struct ltproto_socket_pipe *sk)
{
	char *slash;
	if (sk->pname != NULL) {
		slash = strrchr (sk->pname, '/');
		(void)unlink (sk->pname);
		if (slash != NULL) {
			*slash = '\0';
			(void)rmdir (sk->pname);
		}
		free (sk->pname);
	}
}

int
pipe_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	char tmpname[PATH_MAX] = "/tmp/ltproto_pipe_XXXXXX";
	int len, ready;
	struct ltproto_socket_pipe *ssk = sk;

	mkdtemp (tmpname);
	len = strlen (tmpname);
	snprintf (tmpname + len, sizeof (tmpname) - len, "/fifo");
	assert (mkfifo (tmpname, 0600) == 0);
	ssk->fd = open (tmpname, O_RDWR);
	if (ssk->fd == -1) {
		return -1;
	}

	/* Send pipe name over tcp socket */
	ssk->pname = strdup (tmpname);
	len = strlen (tmpname);
	if (write (ssk->tcp_fd, &len, sizeof (len)) == -1) {
		close (ssk->fd);
		pipe_remove_pipe (ssk);
		return -1;
	}
	if (write (ssk->tcp_fd, tmpname, len) == -1) {
		close (ssk->fd);
		pipe_remove_pipe (ssk);
		return -1;
	}

	if (read (ssk->tcp_fd, &ready, sizeof (int)) == -1 || ready != 1) {
		close (ssk->fd);
		pipe_remove_pipe (ssk);
		return -1;
	}

	return ssk->fd;
}

ssize_t
pipe_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len)
{
	return lt_read (sk->fd, buf, len);
}

ssize_t
pipe_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len)
{
	ssize_t r;
	struct pollfd pfd;

	pfd.events = POLL_OUT;
	pfd.fd = sk->fd;

	while ((r = lt_write (sk->fd, buf, len)) == -1) {
		if (errno != EAGAIN && errno != EPIPE && errno != EINTR) {
			return -1;
		}
		if (poll (&pfd, 1, -1) == -1) {
			return -1;
		}
	}

	return r;
}

int
pipe_get_wait_fd (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	return sk->fd;
}

int
pipe_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	int serrno, ret;
	struct ltproto_socket_pipe *ssk = sk;

	ret = close (ssk->fd);
	pipe_remove_pipe (ssk);
	serrno = errno;
	lt_objcache_free (ctx->sk_cache, ssk);
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

