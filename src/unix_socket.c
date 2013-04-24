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
 * @file unix.c
 * @section DESCRIPTION
 *
 * Module that uses unix sockets for data transfer
 */

int unix_init_func (struct lt_module_ctx **ctx);
struct ltproto_socket* unix_socket_func (struct lt_module_ctx *ctx);
int unix_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue);
int unix_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
int unix_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog);
struct ltproto_socket* unix_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen);
int unix_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
ssize_t unix_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len);
ssize_t unix_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len);
int unix_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv);
int unix_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk);
int unix_destroy_func (struct lt_module_ctx *ctx);

module_t unix_module = {
	.name = "unix",
	.priority = 0,
	.module_init_func = unix_init_func,
	.module_socket_func = unix_socket_func,
	.module_setopts_func = unix_setopts_func,
	.module_bind_func = unix_bind_func,
	.module_listen_func = unix_listen_func,
	.module_accept_func = unix_accept_func,
	.module_connect_func = unix_connect_func,
	.module_read_func = unix_read_func,
	.module_write_func = unix_write_func,
	.module_select_func = unix_select_func,
	.module_close_func = unix_close_func,
	.module_destroy_func = unix_destroy_func
};

int
unix_init_func (struct lt_module_ctx **ctx)
{
	*ctx = calloc (1, sizeof (struct lt_module_ctx));
	(*ctx)->len = sizeof (struct lt_module_ctx);
	(*ctx)->sk_cache = lt_objcache_create (sizeof (struct ltproto_socket));

	return 0;
}

struct ltproto_socket *
unix_socket_func (struct lt_module_ctx *ctx)
{
	struct ltproto_socket *sk;

	sk = lt_objcache_alloc (ctx->sk_cache);
	assert (sk != NULL);
	sk->fd = socket (PF_UNIX, SOCK_STREAM, 0);
	if (sk->fd == -1) {
		lt_objcache_free (ctx->sk_cache, sk);
		return NULL;
	}

	return sk;
}

int
unix_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue)
{
	return setsockopt (sk->fd, SOL_SOCKET, optname, &optvalue, sizeof (optvalue));
}

int
unix_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_in sin;
	struct sockaddr_un sun;
	const char *tmpdir = "/tmp";

	if (addrlen != sizeof (sin)) {
		errno = ENOTSUP;
		return -1;
	}

	memcpy (&sin, addr, sizeof (sin));

	sun.sun_family = AF_UNIX;
	snprintf (sun.sun_path, sizeof (sun.sun_path), "%s/ltproto_%d", tmpdir, ntohs (sin.sin_port));
	unlink (sun.sun_path);
#ifdef BSD
	sun.sun_len = SUN_LEN (&sun);
#endif

	return bind (sk->fd, (struct sockaddr *)&sun, SUN_LEN (&sun));
}

int
unix_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog)
{
	return listen (sk->fd, backlog);
}

struct ltproto_socket *
unix_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket *nsk;
	int afd;
	struct sockaddr_un sun;
	socklen_t sun_len;

	sun_len = sizeof (sun);

	afd = accept (sk->fd, (struct sockaddr *)&sun, &sun_len);
	if (afd == -1) {
		return NULL;
	}

	nsk = lt_objcache_alloc (ctx->sk_cache);
	assert (nsk != NULL);
	nsk->fd = afd;

	*addrlen = sun_len;
	return nsk;
}

int
unix_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_un sun;
	struct sockaddr_in sin;
	const char *tmpdir = "/tmp";

	if (addrlen != sizeof (sin)) {
		errno = ENOTSUP;
		return -1;
	}

	memcpy (&sin, addr, sizeof (sin));

	sun.sun_family = AF_UNIX;
	snprintf (sun.sun_path, sizeof (sun.sun_path), "%s/ltproto_%d", tmpdir, ntohs (sin.sin_port));
#ifdef BSD
	sun.sun_len = SUN_LEN (&sun);
#endif

	return connect (sk->fd, (struct sockaddr *)&sun, SUN_LEN (&sun));
}

ssize_t
unix_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len)
{
	return read (sk->fd, buf, len);
}

ssize_t
unix_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len)
{
	return write (sk->fd, buf, len);
}

int
unix_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv)
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
unix_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	int serrno, ret;
	struct sockaddr_un sun;
	socklen_t slen = sizeof (sun);

	if (getsockname (sk->fd, (struct sockaddr *)&sun, &slen) != -1) {
		unlink (sun.sun_path);
	}

	ret = close (sk->fd);
	serrno = errno;
	lt_objcache_free (ctx->sk_cache, sk);
	errno = serrno;

	return ret;
}

int
unix_destroy_func (struct lt_module_ctx *ctx)
{
	lt_objcache_destroy (ctx->sk_cache);
	free (ctx);
	return 0;
}
