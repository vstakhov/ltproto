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
 * @file udp_shmem.c
 * @section DESCRIPTION
 *
 * A module that uses shared memory for data transfer and udp for signalling
 */

struct ltproto_udp_command {
	enum {
		SHMEM_UDP_CMD_CONNECT = 0,		// Connect to listening socket
		SHMEM_UDP_CMD_CONNECT_ACK,	// Acknowledgement of a connection
		SHMEM_UDP_CMD_SEND,			// Send data command
		SHMEM_UDP_CMD_ACK,			// Acknowledgement of sending
		SHMEM_UDP_CMD_FIN			// Finalise connection
	} cmd;
	union {
		uint32_t cookie;			// Initialization cookie
		struct {
			uint32_t seqno;			// Sequence number
			uint32_t seglen;		// Segment length
		} data;
	} payload;
};

struct ltproto_socket_udp {
	int fd;							// Socket descriptor
	struct ltproto_module *mod;		// Module handling this socket
	UT_hash_handle hh;				// Hash entry
	u_char mod_data[1];				// Module's private data
	struct {
		u_char *data;				// Shmem pipe
		u_char *pos;
		u_char *last;
		size_t len;
	} pipe;
	enum {
		SHMEM_UDP_STATE_INIT = 0,
		SHMEM_UDP_STATE_LISTEN,
		SHMEM_UDP_STATE_CONNECTED
	} state;
	uint32_t cookie_local;
	uint32_t cookie_remote;
};

int udp_shmem_init_func (struct lt_module_ctx **ctx);
struct ltproto_socket* udp_shmem_socket_func (struct lt_module_ctx *ctx);
int udp_shmem_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue);
int udp_shmem_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
int udp_shmem_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog);
struct ltproto_socket* udp_shmem_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen);
int udp_shmem_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
ssize_t udp_shmem_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len);
ssize_t udp_shmem_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len);
int udp_shmem_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv);
int udp_shmem_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk);
int udp_shmem_destroy_func (struct lt_module_ctx *ctx);

module_t udp_shmem_module = {
	.name = "udp_shmem",
	.priority = 2,
	.module_init_func = udp_shmem_init_func,
	.module_socket_func = udp_shmem_socket_func,
	.module_setopts_func = udp_shmem_setopts_func,
	.module_bind_func = udp_shmem_bind_func,
	.module_listen_func = udp_shmem_listen_func,
	.module_accept_func = udp_shmem_accept_func,
	.module_connect_func = udp_shmem_connect_func,
	.module_read_func = udp_shmem_read_func,
	.module_write_func = udp_shmem_write_func,
	.module_select_func = udp_shmem_select_func,
	.module_close_func = udp_shmem_close_func,
	.module_destroy_func = udp_shmem_destroy_func
};

int
udp_shmem_init_func (struct lt_module_ctx **ctx)
{
	*ctx = calloc (1, sizeof (struct lt_module_ctx));
	(*ctx)->len = sizeof (struct lt_module_ctx);

	return 0;
}

struct ltproto_socket *
udp_shmem_socket_func (struct lt_module_ctx *ctx)
{
	struct ltproto_socket_udp *sk;

	sk = calloc (1, sizeof (struct ltproto_socket_udp));
	assert (sk != NULL);
	sk->fd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk->fd == -1) {
		free (sk);
		return NULL;
	}

	return sk;
}

int
udp_shmem_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue)
{
	return setsockopt (sk->fd, SOL_SOCKET, optname, &optvalue, sizeof (optvalue));
}

int
udp_shmem_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	int reuseaddr = 1;
	struct ltproto_socket_udp *usk = sk;

	setsockopt (usk->fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof (int));
	return bind (usk->fd, addr, addrlen);
}

int
udp_shmem_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog)
{
	struct ltproto_socket_udp *usk = sk;

	usk->state = SHMEM_UDP_STATE_LISTEN;

	return 0;
}

struct ltproto_socket *
udp_shmem_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket_udp *usk = sk, *nsk;
	int afd;

	if (usk->state != SHMEM_UDP_STATE_LISTEN) {
		errno = EINVAL;
		return -1;
	}

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
udp_shmem_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	struct ltproto_socket_udp *usk = sk;
	return connect (sk->fd, addr, addrlen);
}

ssize_t
udp_shmem_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len)
{
	struct ltproto_socket_udp *usk = sk;
	return read (sk->fd, buf, len);
}

ssize_t
udp_shmem_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len)
{
	struct ltproto_socket_udp *usk = sk;
	return write (sk->fd, buf, len);
}

int
udp_shmem_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv)
{
	struct pollfd pfd;
	int msec = -1;
	struct ltproto_socket_udp *usk = sk;

	pfd.events = what;
	pfd.fd = sk->fd;

	if (tv != NULL) {
		msec = tv_to_msec (tv);
	}

	return poll (&pfd, 1, msec);
}

int
udp_shmem_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	struct ltproto_socket_udp *usk = sk;
	return close (sk->fd);
}

int
udp_shmem_destroy_func (struct lt_module_ctx *ctx)
{
	free (ctx);
	return 0;
}
