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
 * @file unix_shmem.c
 * @section DESCRIPTION
 *
 * A module that uses shared memory for data transfer and unix socket for signalling.
 */

#define DEFAULT_UNIX_SHMEM_SEGMENT (1024 * 1024)

/**
 * Important notice: since we are implementing local transport it is assumed, that
 * we have the same byteorder for all peers affected.
 * If this approach is not true, this code should be adopted to use network
 * byte order.
 */
struct ltproto_unix_command {
	enum {
		SHMEM_UNIX_CMD_SEND = 0x1,				// Send data command
		SHMEM_UNIX_CMD_ACK = 0x1 << 1,			// Acknowledgement of sending
		SHMEM_UNIX_CMD_FIN = 0x1 << 2			// Finalise connection
	} cmd;
	struct lt_alloc_tag tag;	// Data tag
	uint32_t len;				// Data length
};

struct unacked_chunk_entry {
	void *addr;
	size_t len;
	struct unacked_chunk_entry *next;
};

struct ltproto_socket_unix {
	int fd;							// Socket descriptor
	int tcp_fd;						// TCP link socket
	struct ltproto_module *mod;		// Module handling this socket
	UT_hash_handle hh;				// Hash entry
	struct unacked_chunk_entry *unacked_chunks;	 // Chunks that are unacked
	unsigned long unacked_bytes;			// Number of bytes that are unacked
};

struct lt_unix_module_ctx {
	size_t len;						// Length of the context
	struct ltproto_ctx *lib_ctx;	// Parent ctx
	struct lt_objcache *sk_cache;	// Object cache for sockets
	struct lt_objcache *cmd_cache;			// Object cache for unix commands
	struct lt_objcache *chunks_cache; // Object cache for unacked chunks
	unsigned long max_segment;		// Maximum amount of unacked data
};

int unix_shmem_init_func (struct lt_module_ctx **ctx);
struct ltproto_socket* unix_shmem_socket_func (struct lt_module_ctx *ctx);
int unix_shmem_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue);
int unix_shmem_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
int unix_shmem_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog);
struct ltproto_socket* unix_shmem_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen);
int unix_shmem_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
ssize_t unix_shmem_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len);
ssize_t unix_shmem_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len);
int unix_shmem_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv);
int unix_shmem_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk);
int unix_shmem_destroy_func (struct lt_module_ctx *ctx);

module_t unix_shmem_module = {
	.name = "unix_shmem",
	.priority = 2,
	.module_init_func = unix_shmem_init_func,
	.module_socket_func = unix_shmem_socket_func,
	.module_setopts_func = unix_shmem_setopts_func,
	.module_bind_func = unix_shmem_bind_func,
	.module_listen_func = unix_shmem_listen_func,
	.module_accept_func = unix_shmem_accept_func,
	.module_connect_func = unix_shmem_connect_func,
	.module_read_func = unix_shmem_read_func,
	.module_write_func = unix_shmem_write_func,
	.module_select_func = unix_shmem_select_func,
	.module_close_func = unix_shmem_close_func,
	.module_destroy_func = unix_shmem_destroy_func
};


/**
 * Receive command from network
 * @param usk socket structure
 * @param saved_errno errno to be saved
 * @return allocated command or NULL if error occurred
 */
static inline struct ltproto_unix_command*
unix_shmem_recv_command (struct ltproto_socket_unix *usk, int *saved_errno)
{
	struct ltproto_unix_command *cmd;
	struct lt_unix_module_ctx *ctx = (struct lt_unix_module_ctx *)usk->mod->ctx;
	int r;

	cmd = lt_objcache_alloc0 (ctx->cmd_cache);
	while ((r = read (usk->fd, cmd, sizeof (struct ltproto_unix_command)))
			!= sizeof (struct ltproto_unix_command)) {
		if (r == -1 && (errno == EINTR)) {
			continue;
		}
		else if (r >= 0) {
			*saved_errno = EINVAL;
		}
		else {
			*saved_errno = errno;
		}/* Do not accept commands that cannot be enqueued */
		return NULL;
	}

	/* Actually we alloc memory for the whole entry here */
	*saved_errno = 0;

	return cmd;
}

int
unix_shmem_init_func (struct lt_module_ctx **ctx)
{
	struct lt_unix_module_ctx *real_ctx;
	char *segment_size;

	real_ctx = calloc (1, sizeof (struct lt_unix_module_ctx));
	real_ctx->len = sizeof (struct lt_unix_module_ctx);
	real_ctx->sk_cache = lt_objcache_create (sizeof (struct ltproto_socket_unix));
	real_ctx->cmd_cache = lt_objcache_create (sizeof (struct ltproto_unix_command));
	real_ctx->chunks_cache = lt_objcache_create (sizeof (struct unacked_chunk_entry));
	*ctx = (struct lt_module_ctx *)real_ctx;

	segment_size = getenv ("LTPROTO_SEGMENT_SIZE");
	if (segment_size != NULL) {
		real_ctx->max_segment = strtoul (segment_size, NULL, 10);
	}
	else {
		real_ctx->max_segment = DEFAULT_UNIX_SHMEM_SEGMENT;
	}

	return 0;
}

struct ltproto_socket *
unix_shmem_socket_func (struct lt_module_ctx *ctx)
{
	struct ltproto_socket_unix *sk;
	struct lt_unix_module_ctx *real_ctx = (struct lt_unix_module_ctx *)ctx;
	int reuseaddr = 1;

	sk = lt_objcache_alloc0 (real_ctx->sk_cache);
	assert (sk != NULL);
#ifdef HAVE_UNIX_SEQPACKET
	sk->fd = socket (AF_UNIX, SOCK_SEQPACKET, 0);
#else
	sk->fd = socket (AF_UNIX, SOCK_STREAM, 0);
#endif
	if (sk->fd == -1) {
		lt_objcache_free (real_ctx->sk_cache, sk);
		return NULL;
	}
	setsockopt (sk->fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof (reuseaddr));

	return (struct ltproto_socket *)sk;
}

int
unix_shmem_setopts_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue)
{
	return setsockopt (sk->fd, SOL_SOCKET, optname, &optvalue, sizeof (optvalue));
}

int
unix_shmem_bind_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	struct ltproto_socket_unix *usk = (struct ltproto_socket_unix *)sk;
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

	return bind (usk->fd, (struct sockaddr *)&sun, SUN_LEN (&sun));
}

int
unix_shmem_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog)
{
	struct ltproto_socket_unix *usk = (struct ltproto_socket_unix *)sk;

	return listen (usk->fd, backlog);
}

struct ltproto_socket *
unix_shmem_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket_unix *usk = (struct ltproto_socket_unix *)sk, *nsk = NULL;
	int afd;
	struct sockaddr_un sun;
	socklen_t sun_len;

	sun_len = sizeof (sun);

	afd = accept (usk->fd, (struct sockaddr *)&sun, &sun_len);
	if (afd == -1) {
		return NULL;
	}

	nsk = lt_objcache_alloc (ctx->sk_cache);
	assert (nsk != NULL);
	nsk->fd = afd;

	*addrlen = sun_len;

	return (struct ltproto_socket *)nsk;
}

int
unix_shmem_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk,
		const struct sockaddr *addr, socklen_t addrlen)
{
	struct ltproto_socket_unix *usk = (struct ltproto_socket_unix *)sk;
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

	return connect (usk->fd, (struct sockaddr *)&sun, SUN_LEN (&sun));
}

ssize_t
unix_shmem_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len)
{
	struct ltproto_socket_unix *usk = (struct ltproto_socket_unix *)sk;
	struct ltproto_unix_command *cmd, lcmd;
	struct lt_unix_module_ctx *real_ctx = (struct lt_unix_module_ctx *)ctx;
	int serrno;
	void *mem;

	cmd = unix_shmem_recv_command (usk, &serrno);

	if (cmd != NULL) {
		if (cmd->cmd == SHMEM_UNIX_CMD_FIN) {
			/* Connection has been closed */
			lt_objcache_free (real_ctx->cmd_cache, cmd);
			return 0;
		}
		else if (cmd->cmd == SHMEM_UNIX_CMD_SEND) {
			/* We have send request pending */
			mem = real_ctx->lib_ctx->allocator->allocator_attachtag_func (real_ctx->lib_ctx->alloc_ctx,
					&cmd->tag);
			if (mem == NULL) {
				/* Cannot attach memory for some reason */
				serrno = EINVAL;
				lt_objcache_free (real_ctx->cmd_cache, cmd);
			}
			else {
				/* XXX: just copy buffer assuming local and remote sizes are equal */
				memcpy (buf, mem, len);
				usk->unacked_bytes += len;
				if (usk->unacked_bytes >= real_ctx->max_segment) {
					lcmd.cmd = SHMEM_UNIX_CMD_ACK;
					if (write (usk->fd, &lcmd, sizeof (lcmd)) == -1) {
						lt_objcache_free (real_ctx->cmd_cache, cmd);
						return -1;
					}
					usk->unacked_bytes = 0;
				}

				lt_objcache_free (real_ctx->cmd_cache, cmd);
				return len;
			}
		}
	}

	errno = serrno;
	return -1;
}

ssize_t
unix_shmem_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len)
{
	struct ltproto_socket_unix *usk = (struct ltproto_socket_unix *)sk;
	struct ltproto_unix_command lcmd, *cmd;
	struct unacked_chunk_entry *unacked_chunk, *tmp;
	struct lt_unix_module_ctx *real_ctx = (struct lt_unix_module_ctx *)ctx;
	u_char *shared_data;
	int serrno;

	lcmd.cmd = SHMEM_UNIX_CMD_SEND;
	shared_data = real_ctx->lib_ctx->allocator->allocator_alloc_func (real_ctx->lib_ctx->alloc_ctx,
			len, &lcmd.tag);
	if (shared_data == NULL) {
		errno = EAGAIN;
		return -1;
	}
	memcpy (shared_data, buf, len);
	lcmd.len = len;

	if (write (usk->fd, &lcmd, sizeof (lcmd)) == -1) {
		return -1;
	}
	usk->unacked_bytes += len;
	if (usk->unacked_bytes >= real_ctx->max_segment) {
		cmd = unix_shmem_recv_command (usk, &serrno);
		if (cmd != NULL) {
			/* XXX: Check cookie */
			usk->unacked_bytes = 0;

			/* Free all chunks pending */
			unacked_chunk = usk->unacked_chunks;
			while (unacked_chunk != NULL) {
				real_ctx->lib_ctx->allocator->allocator_free_func (real_ctx->lib_ctx->alloc_ctx,
									unacked_chunk->addr, unacked_chunk->len);
				tmp = unacked_chunk;
				unacked_chunk = unacked_chunk->next;
				lt_objcache_free (real_ctx->chunks_cache, tmp);
			}
			usk->unacked_chunks = NULL;
			real_ctx->lib_ctx->allocator->allocator_free_func (real_ctx->lib_ctx->alloc_ctx,
					shared_data, len);
			lt_objcache_free (real_ctx->cmd_cache, cmd);
			return len;
		}
	}
	else {
		unacked_chunk = lt_objcache_alloc (real_ctx->chunks_cache);
		unacked_chunk->addr = shared_data;
		unacked_chunk->len = len;
		unacked_chunk->next = usk->unacked_chunks;
		usk->unacked_chunks = unacked_chunk;
		return len;
	}
	return -1;
}

int
unix_shmem_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv)
{
	struct pollfd pfd;
	int msec = -1;
	struct ltproto_socket_unix *usk = (struct ltproto_socket_unix *)sk;

	pfd.events = what;
	pfd.fd = usk->fd;

	if (tv != NULL) {
		msec = tv_to_msec (tv);
	}

	return poll (&pfd, 1, msec);
}

int
unix_shmem_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	struct ltproto_socket_unix *usk = (struct ltproto_socket_unix *)sk;
	struct ltproto_unix_command lcmd;
	struct unacked_chunk_entry *unacked_chunk, *tmp;
	struct lt_unix_module_ctx *real_ctx = (struct lt_unix_module_ctx *)ctx;
	int serrno = 0, ret;
	struct sockaddr_un sun;
	socklen_t slen = sizeof (sun);

	if (getpeername (usk->fd, (struct sockaddr *)&sun, &slen) != -1) {
		/* Send fin command */
		lcmd.cmd = SHMEM_UNIX_CMD_FIN;
		if (write (usk->fd, &lcmd, sizeof (lcmd)) == -1) {
			serrno = errno;
		}
	}
	else {
		/* Free all chunks pending */
		unacked_chunk = usk->unacked_chunks;
		while (unacked_chunk != NULL) {
			real_ctx->lib_ctx->allocator->allocator_free_func (real_ctx->lib_ctx->alloc_ctx,
					unacked_chunk->addr, unacked_chunk->len);
			tmp = unacked_chunk;
			unacked_chunk = unacked_chunk->next;
			lt_objcache_free (real_ctx->chunks_cache, tmp);
		}
	}

	slen = sizeof (sun);
	if (getsockname (sk->fd, (struct sockaddr *)&sun, &slen) != -1) {
		unlink (sun.sun_path);
	}
	ret = close (usk->fd);
	lt_objcache_free (real_ctx->sk_cache, usk);
	errno = serrno;

	return ret;
}

int
unix_shmem_destroy_func (struct lt_module_ctx *ctx)
{
	struct lt_unix_module_ctx *real_ctx = (struct lt_unix_module_ctx *)ctx;

	lt_objcache_destroy (real_ctx->cmd_cache);
	lt_objcache_destroy (real_ctx->sk_cache);
	lt_objcache_destroy (real_ctx->chunks_cache);
	free (real_ctx);
	return 0;
}

