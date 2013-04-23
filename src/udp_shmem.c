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
 * A module that uses shared memory for data transfer and udp for signalling.
 *
 * UDP shmem module uses a single socket to listen and accept events, however
 * it is dup(2)ed for accepted connection.
 * Here is the logic of connections handling:
 *
 * - Each of read functions, such as accept, read triggers network reading, but we
 * know that UDP transport is not ordered and we can receive non-expected event
 * (like data segment when we are awaiting for connection request). To avoid such
 * situation it is required to keep incoming queue for each socket. Then after
 * receiving a non-expected command it is possible to search for appropriate socket and
 * enqueue request.
 *
 * - To allow this logic each connection has specific cookie that is generated from a
 * pair of random 32 bits number by intersection formulae.
 *
 * - After accepting the peer sends CONNECTION_ACK command to inform peer about connection
 * cookie.
 *
 * - If a listening socket is closed, accepted connection will work fine but further connection
 * attempts will be ignored.
 *
 * XXX: this module uses dup, hence, it is not possible to mix blocking and
 * non-blocking IO for listening socket and accepted sockets.
 */

#define DEFAULT_UDP_SHMEM_SEGMENT (1024 * 1024)

/**
 * Important notice: since we are implementing local transport it is assumed, that
 * we have the same byteorder for all peers affected.
 * If this approach is not true, this code should be adopted to use network
 * byte order.
 */
struct ltproto_udp_command {
	enum {
		SHMEM_UDP_CMD_CONNECT = 0x1,			// Connect to listening socket
		SHMEM_UDP_CMD_CONNECT_ACK = 0x1 << 1,	// Acknowledgement of a connection
		SHMEM_UDP_CMD_SEND = 0x1 << 2,			// Send data command
		SHMEM_UDP_CMD_ACK = 0x1 << 3,			// Acknowledgement of sending
		SHMEM_UDP_CMD_FIN = 0x1 << 4			// Finalise connection
	} cmd;
	union {
		uint32_t cookie;				// Initialization cookie
		struct {
			uint32_t conn_cookie;		// Connection cookie
			struct lt_alloc_tag tag;	// Data tag
			uint32_t len;				// Data length
		} data;
	} payload;
};

struct ltproto_udp_command_entry {
	struct ltproto_udp_command cmd;
	struct sockaddr_in sin;
	TAILQ_ENTRY (ltproto_udp_command_entry) link;
};

struct unacked_chunk_entry {
	void *addr;
	size_t len;
	struct unacked_chunk_entry *next;
};

struct ltproto_socket_udp {
	int fd;							// Socket descriptor
	int tcp_fd;						// TCP link socket
	struct ltproto_module *mod;		// Module handling this socket
	UT_hash_handle hh;				// Hash entry
	enum {
		SHMEM_UDP_STATE_INIT = 0,
		SHMEM_UDP_STATE_LISTEN,
		SHMEM_UDP_STATE_CONNECTED,
		SHMEM_UDP_STATE_ACCEPTED
	} state;						// State of a socket
	u_short substate;				// Substate of individual socket to simplify state handling
	union {
		struct {
			struct {
				u_char *data;				// Shmem pipe
				u_char *pos;
				u_char *last;
				size_t len;
			} pipe;

			struct ltproto_socket_udp *parent;		// Parent socket
			struct sockaddr_in peer_addr;			// Connected peer
			struct unacked_chunk_entry *unacked_chunks;	 // Chunks that are unacked
			unsigned long unacked_bytes;			// Number of bytes that are unacked
		} data_sock;
		struct {
			struct ltproto_socket_udp *accepted_sk; // Hash of accepted sockets
#ifndef THREAD_UNSAFE
			pthread_mutex_t accept_lock;
#endif
		} listen_sock;
	} common;
	uint32_t cookie_local;							// Local cookie
	uint32_t conn_cookie;							// Connection cookie
	TAILQ_HEAD (,ltproto_udp_command_entry) in_q;	// Incoming commands
	TAILQ_HEAD (,ltproto_udp_command_entry) out_q;	// Outgoing commands
#ifndef THREAD_UNSAFE
	pthread_mutex_t inq_lock;
	pthread_mutex_t outq_lock;
#endif
};

struct lt_udp_module_ctx {
	size_t len;						// Length of the context
	struct ltproto_ctx *lib_ctx;	// Parent ctx
	struct lt_objcache *sk_cache;	// Object cache for sockets
	struct lt_objcache *cmd_cache;			// Object cache for udp commands
	struct lt_objcache *chunks_cache; // Object cache for unacked chunks
	unsigned long max_segment;		// Maximum amount of unacked data
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

/**
 * Enqueue command to a proper socket (listening or data socket)
 * @param usk socket structure
 * @param cmd command entry structure (casted to command)
 * @return 0 if command has been enqueued or -1 in case of error
 */
static int
udp_shmem_enqueue_command (struct ltproto_socket_udp *usk, struct ltproto_udp_command *cmd)
{
	struct ltproto_udp_command_entry *cmd_entry = (struct ltproto_udp_command_entry *)cmd;
	struct ltproto_socket_udp *sk_found;

	if (usk->state == SHMEM_UDP_STATE_LISTEN) {
		switch (cmd->cmd) {
		case SHMEM_UDP_CMD_CONNECT:
			/* Enqueue to this socket */
			TAILQ_INSERT_TAIL (&usk->in_q, cmd_entry, link);
			break;
		case SHMEM_UDP_CMD_CONNECT_ACK:
		case SHMEM_UDP_CMD_SEND:
		case SHMEM_UDP_CMD_ACK:
		case SHMEM_UDP_CMD_FIN:
			/* Try to find appropriate socket */
#ifndef THREAD_SAFE
			pthread_mutex_lock (&usk->common.listen_sock.accept_lock);
#endif
			HASH_FIND_INT (usk->common.listen_sock.accepted_sk, &cmd->payload.data.conn_cookie, sk_found);
#ifndef THREAD_SAFE
			pthread_mutex_unlock (&usk->common.listen_sock.accept_lock);
#endif
			if (sk_found == NULL) {
				return -1;
			}
			TAILQ_INSERT_TAIL (&sk_found->in_q, cmd_entry, link);
			break;
		}
	}
	else if (usk->state == SHMEM_UDP_STATE_CONNECTED ||
			usk->state == SHMEM_UDP_STATE_ACCEPTED) {
		switch (cmd->cmd) {
		case SHMEM_UDP_CMD_CONNECT:
			/* Enqueue to parent socket */
			if (usk->common.data_sock.parent) {
				TAILQ_INSERT_TAIL (&usk->common.data_sock.parent->in_q, cmd_entry, link);
			}
			else {
				/* Listening socket was closed */
				return -1;
			}
			break;
		case SHMEM_UDP_CMD_SEND:
		case SHMEM_UDP_CMD_ACK:
		case SHMEM_UDP_CMD_FIN:
		case SHMEM_UDP_CMD_CONNECT_ACK:
			TAILQ_INSERT_TAIL (&usk->in_q, cmd_entry, link);
			break;
		}
	}
	else {
		return -1;
	}

	return 0;
}

/**
 * Receive command from network
 * @param usk socket structure
 * @param saved_errno errno to be saved
 * @return allocated command or NULL if error occurred
 */
static inline struct ltproto_udp_command*
udp_shmem_recv_command (struct ltproto_socket_udp *usk, int *saved_errno)
{
	struct ltproto_udp_command cmd;
	struct ltproto_udp_command_entry *pcmd;
	struct lt_udp_module_ctx *ctx = (struct lt_udp_module_ctx *)usk->mod->ctx;
	int r;
	struct sockaddr_in sin;
	socklen_t slen = sizeof (struct sockaddr_in);

	while ((r = recvfrom (usk->fd, &cmd, sizeof (cmd), 0, (struct sockaddr *)&sin, &slen)) != sizeof (cmd)) {
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
	pcmd = lt_objcache_alloc0 (ctx->cmd_cache);
	assert (pcmd != NULL);
	memcpy (&pcmd->cmd, &cmd, sizeof (cmd));
	memcpy (&pcmd->sin, &sin, slen);

	return (struct ltproto_udp_command*)pcmd;
}

/**
 * Process socket and enqueue requests, returning the first command of specified type
 * @param usk socket structure
 * @param cmd command to get
 * @param saved_errno errno to save
 * @return command entry or NULL saving error to errno
 */
static struct ltproto_udp_command_entry*
udp_shmem_expect_command (struct ltproto_socket_udp *usk, u_int cmd, int *saved_errno)
{
	struct ltproto_udp_command_entry *cur;
	struct ltproto_udp_command *res;
	struct lt_udp_module_ctx *ctx = (struct lt_udp_module_ctx *)usk->mod->ctx;

	/* Check queue first */
#ifndef THREAD_UNSAFE
	pthread_mutex_lock (&usk->inq_lock);
#endif
	TAILQ_FOREACH (cur, &usk->in_q, link) {
		if (cur->cmd.cmd & cmd) {
#ifndef THREAD_UNSAFE
			pthread_mutex_unlock (&usk->inq_lock);
#endif
			return cur;
		}
	}

	for (;;) {
		/* We got nothing, so try to accept data */
		res = udp_shmem_recv_command (usk, saved_errno);
		if (res == NULL) {
#ifndef THREAD_UNSAFE
			pthread_mutex_unlock (&usk->inq_lock);
#endif
			return NULL;
		}

		if (udp_shmem_enqueue_command (usk, res) == -1) {
			if (res->cmd == cmd) {
				*saved_errno = EINVAL;
				lt_objcache_free (ctx->sk_cache, res);
#ifndef THREAD_UNSAFE
				pthread_mutex_unlock (&usk->inq_lock);
#endif
				return NULL;
			}
		}

		if (res->cmd & cmd) {
#ifndef THREAD_UNSAFE
			pthread_mutex_unlock (&usk->inq_lock);
#endif
			return (struct ltproto_udp_command_entry *)res;
		}
	}

	/* Not reached */
	return NULL;
}

int
udp_shmem_init_func (struct lt_module_ctx **ctx)
{
	struct lt_udp_module_ctx *real_ctx;
	char *segment_size;

	real_ctx = calloc (1, sizeof (struct lt_udp_module_ctx));
	real_ctx->len = sizeof (struct lt_udp_module_ctx);
	real_ctx->sk_cache = lt_objcache_create (sizeof (struct ltproto_socket_udp));
	real_ctx->cmd_cache = lt_objcache_create (sizeof (struct ltproto_udp_command_entry));
	real_ctx->chunks_cache = lt_objcache_create (sizeof (struct unacked_chunk_entry));
	*ctx = (struct lt_module_ctx *)real_ctx;

	segment_size = getenv ("LTPROTO_SEGMENT_SIZE");
	if (segment_size != NULL) {
		real_ctx->max_segment = strtoul (segment_size, NULL, 10);
	}
	else {
		real_ctx->max_segment = DEFAULT_UDP_SHMEM_SEGMENT;
	}

	return 0;
}

struct ltproto_socket *
udp_shmem_socket_func (struct lt_module_ctx *ctx)
{
	struct ltproto_socket_udp *sk;
	struct lt_udp_module_ctx *real_ctx = (struct lt_udp_module_ctx *)ctx;

	sk = lt_objcache_alloc0 (real_ctx->sk_cache);
	assert (sk != NULL);
	sk->fd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk->fd == -1) {
		lt_objcache_free (real_ctx->sk_cache, sk);
		return NULL;
	}
	sk->cookie_local = rand ();
	TAILQ_INIT (&sk->in_q);
	TAILQ_INIT (&sk->out_q);
#ifndef THREAD_SAFE
	pthread_mutex_init (&sk->inq_lock, NULL);
	pthread_mutex_init (&sk->outq_lock, NULL);
#endif

	return (struct ltproto_socket *)sk;
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
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk;

	setsockopt (usk->fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof (int));
	return bind (usk->fd, addr, addrlen);
}

int
udp_shmem_listen_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog)
{
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk;

	if (usk->state != SHMEM_UDP_STATE_INIT) {
		/* Do not allow connected or already listened sockets */
		errno = EINVAL;
		return -1;
	}
	usk->state = SHMEM_UDP_STATE_LISTEN;
#ifndef THREAD_SAFE
	pthread_mutex_init (&usk->common.listen_sock.accept_lock, NULL);
#endif

	return 0;
}

struct ltproto_socket *
udp_shmem_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk, *nsk = NULL;
	struct lt_udp_module_ctx *real_ctx = (struct lt_udp_module_ctx *)ctx;
	struct ltproto_udp_command_entry *cmd;
	struct ltproto_udp_command lcmd;
	int serrno;

	if (usk->state != SHMEM_UDP_STATE_LISTEN) {
		errno = EINVAL;
		return NULL;
	}

	/* Now we process command till got CONNECT command */
	cmd = udp_shmem_expect_command (usk, SHMEM_UDP_CMD_CONNECT, &serrno);
	if (cmd != NULL) {
		/* We have initial syn packet, so we can setup socket */
#ifndef THREAD_UNSAFE
		pthread_mutex_lock (&usk->inq_lock);
#endif
		TAILQ_REMOVE (&usk->in_q, cmd, link);
#ifndef THREAD_UNSAFE
		pthread_mutex_unlock (&usk->inq_lock);
#endif
		nsk = lt_objcache_alloc0 (real_ctx->sk_cache);
		if (nsk == NULL) {
			return NULL;
		}
		nsk->fd = dup (usk->fd);
		if (nsk->fd == -1) {
			lt_objcache_free (real_ctx->sk_cache, nsk);
			return NULL;
		}
		nsk->common.data_sock.parent = usk;
		nsk->cookie_local = get_random_int (ctx->lib_ctx->prng);

		/* Make connection cookie */
		nsk->conn_cookie = (((long)(nsk->cookie_local + cmd->cmd.payload.cookie) *
				(nsk->cookie_local + cmd->cmd.payload.cookie + 1)) << 2) + cmd->cmd.payload.cookie;
		memset (&lcmd, 0, sizeof (lcmd));
		lcmd.cmd = SHMEM_UDP_CMD_CONNECT_ACK;
		lcmd.payload.cookie = nsk->cookie_local;
		memcpy (&nsk->common.data_sock.peer_addr, &cmd->sin, sizeof(cmd->sin));
		memcpy (addr, &cmd->sin, MIN (sizeof (cmd->sin), *addrlen));
		*addrlen = sizeof (cmd->sin);

		if (sendto (nsk->fd, &lcmd, sizeof (lcmd), 0, (struct sockaddr *)&cmd->sin, sizeof (cmd->sin)) == -1) {
			serrno = errno;
			close (nsk->fd);
			lt_objcache_free (real_ctx->sk_cache, nsk);
			errno = serrno;
			return NULL;
		}

		nsk->state = SHMEM_UDP_STATE_ACCEPTED;

		TAILQ_INIT (&nsk->in_q);
		TAILQ_INIT (&nsk->out_q);

		lt_objcache_free (real_ctx->cmd_cache, cmd);
#ifndef THREAD_SAFE
		pthread_mutex_init (&nsk->inq_lock, NULL);
		pthread_mutex_init (&nsk->outq_lock, NULL);
#endif
#ifndef THREAD_SAFE
		pthread_mutex_lock (&usk->common.listen_sock.accept_lock);
#endif
		HASH_ADD_INT (usk->common.listen_sock.accepted_sk, conn_cookie, nsk);
#ifndef THREAD_SAFE
		pthread_mutex_unlock (&usk->common.listen_sock.accept_lock);
#endif
	}
	else {
		errno = serrno;
	}

	return (struct ltproto_socket *)nsk;
}

int
udp_shmem_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk,
		const struct sockaddr *addr, socklen_t addrlen)
{
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk;
	struct ltproto_udp_command lcmd;
	struct ltproto_udp_command_entry *cmd;
	struct lt_udp_module_ctx *real_ctx = (struct lt_udp_module_ctx *)ctx;
	int serrno;

	if (usk->state != SHMEM_UDP_STATE_INIT) {
		/* Do not allow connected or already listened sockets */
		errno = EINVAL;
		return -1;
	}
	memset (&lcmd, 0, sizeof (lcmd));
	lcmd.cmd = SHMEM_UDP_CMD_CONNECT;
	lcmd.payload.cookie = usk->cookie_local;

	if (sendto (usk->fd, &lcmd, sizeof (lcmd), 0, addr, addrlen) == -1) {
		return -1;
	}
	/* Wait for ACK */
	usk->state = SHMEM_UDP_STATE_CONNECTED;
	cmd = udp_shmem_expect_command (usk, SHMEM_UDP_CMD_CONNECT_ACK | SHMEM_UDP_CMD_FIN, &serrno);
	if (cmd != NULL) {
		/* We have initial syn packet, so we can setup socket */
#ifndef THREAD_UNSAFE
		pthread_mutex_lock (&usk->inq_lock);
#endif
		TAILQ_REMOVE (&usk->in_q, cmd, link);
#ifndef THREAD_UNSAFE
		pthread_mutex_unlock (&usk->inq_lock);
#endif
		if (cmd->cmd.cmd == SHMEM_UDP_CMD_CONNECT_ACK) {
			/* Make connection cookie */
			usk->conn_cookie = (((long)(usk->cookie_local + cmd->cmd.payload.cookie) *
					(usk->cookie_local + cmd->cmd.payload.cookie + 1)) << 2) + cmd->cmd.payload.cookie;
			memcpy (&usk->common.data_sock.peer_addr, addr, sizeof(struct sockaddr_in));
		}
		else {
			/* Connection has been reset */
			errno = ECONNABORTED;
			usk->state = SHMEM_UDP_STATE_INIT;
			lt_objcache_free (real_ctx->cmd_cache, cmd);
			return -1;
		}
		lt_objcache_free (real_ctx->cmd_cache, cmd);
	}
	else {
		usk->state = SHMEM_UDP_STATE_INIT;
		errno = serrno;
		return -1;
	}

	return 0;
}

ssize_t
udp_shmem_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len)
{
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk;
	struct ltproto_udp_command_entry *cmd;
	struct ltproto_udp_command lcmd;
	struct lt_udp_module_ctx *real_ctx = (struct lt_udp_module_ctx *)ctx;
	int serrno;
	void *mem;

	if (usk->state != SHMEM_UDP_STATE_CONNECTED &&
			usk->state != SHMEM_UDP_STATE_ACCEPTED) {
		/* Do not allow not connected sockets */
		errno = EINVAL;
		return -1;
	}

recv_more:
	cmd = udp_shmem_expect_command (usk, SHMEM_UDP_CMD_SEND | SHMEM_UDP_CMD_FIN, &serrno);
	if (cmd != NULL) {
#ifndef THREAD_UNSAFE
		pthread_mutex_lock (&usk->inq_lock);
#endif
		TAILQ_REMOVE (&usk->in_q, cmd, link);
#ifndef THREAD_UNSAFE
		pthread_mutex_unlock (&usk->inq_lock);
#endif
		/* XXX: Check cookie */

		if (cmd->cmd.cmd == SHMEM_UDP_CMD_FIN) {
			/* Connection has been closed */
			lt_objcache_free (real_ctx->cmd_cache, cmd);
			return 0;
		}
		else {
			/* We have send request pending */
			mem = real_ctx->lib_ctx->allocator->allocator_attachtag_func (real_ctx->lib_ctx->alloc_ctx,
					&cmd->cmd.payload.data.tag);
			if (mem == NULL) {
				/* Cannot attach memory for some reason */
				serrno = EINVAL;
				lt_objcache_free (real_ctx->cmd_cache, cmd);
			}
			else {
				/* XXX: just copy buffer assuming local and remote sizes are equal */
				memcpy (buf, mem, len);
				usk->common.data_sock.unacked_bytes += len;
				if (usk->common.data_sock.unacked_bytes >= real_ctx->max_segment) {
					lcmd.cmd = SHMEM_UDP_CMD_ACK;
					lcmd.payload.cookie = usk->conn_cookie;
					if (sendto (usk->fd, &lcmd, sizeof (lcmd), 0,
							(struct sockaddr *)&usk->common.data_sock.peer_addr,
							sizeof (struct sockaddr_in)) == -1) {
						lt_objcache_free (real_ctx->cmd_cache, cmd);
						return -1;
					}
					usk->common.data_sock.unacked_bytes = 0;
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
udp_shmem_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len)
{
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk;
	struct ltproto_udp_command lcmd;
	struct ltproto_udp_command_entry *cmd;
	struct unacked_chunk_entry *unacked_chunk, *tmp;
	struct lt_udp_module_ctx *real_ctx = (struct lt_udp_module_ctx *)ctx;
	u_char *shared_data;
	int serrno;

	if (usk->state != SHMEM_UDP_STATE_CONNECTED &&
			usk->state != SHMEM_UDP_STATE_ACCEPTED) {
		/* Do not allow not connected sockets */
		errno = EINVAL;
		return -1;
	}
	lcmd.cmd = SHMEM_UDP_CMD_SEND;
	lcmd.payload.cookie = usk->conn_cookie;
	shared_data = real_ctx->lib_ctx->allocator->allocator_alloc_func (real_ctx->lib_ctx->alloc_ctx,
			len, &lcmd.payload.data.tag);
	if (shared_data == NULL) {
		errno = EAGAIN;
		return -1;
	}
	memcpy (shared_data, buf, len);
	lcmd.payload.data.len = len;

	if (sendto (usk->fd, &lcmd, sizeof (lcmd), 0,
			(struct sockaddr *)&usk->common.data_sock.peer_addr,
			sizeof (struct sockaddr_in)) == -1) {
		return -1;
	}
	usk->common.data_sock.unacked_bytes += len;
	if (usk->common.data_sock.unacked_bytes >= real_ctx->max_segment) {
		cmd = udp_shmem_expect_command (usk, SHMEM_UDP_CMD_ACK, &serrno);
		if (cmd != NULL) {
#ifndef THREAD_UNSAFE
			pthread_mutex_lock (&usk->inq_lock);
#endif
			TAILQ_REMOVE (&usk->in_q, cmd, link);
#ifndef THREAD_UNSAFE
			pthread_mutex_unlock (&usk->inq_lock);
#endif
			/* XXX: Check cookie */
			usk->common.data_sock.unacked_bytes = 0;

			/* Free all chunks pending */
			unacked_chunk = usk->common.data_sock.unacked_chunks;
			while (unacked_chunk != NULL) {
				real_ctx->lib_ctx->allocator->allocator_free_func (real_ctx->lib_ctx->alloc_ctx,
									unacked_chunk->addr, unacked_chunk->len);
				tmp = unacked_chunk;
				unacked_chunk = unacked_chunk->next;
				lt_objcache_free (real_ctx->chunks_cache, tmp);
			}
			usk->common.data_sock.unacked_chunks = NULL;
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
		unacked_chunk->next = usk->common.data_sock.unacked_chunks;
		usk->common.data_sock.unacked_chunks = unacked_chunk;
		return len;
	}
	return -1;
}

int
udp_shmem_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv)
{
	struct pollfd pfd;
	int msec = -1;
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk;

	pfd.events = what;
	pfd.fd = usk->fd;

	if (tv != NULL) {
		msec = tv_to_msec (tv);
	}

	return poll (&pfd, 1, msec);
}

int
udp_shmem_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk, *csk;
	struct ltproto_udp_command lcmd;
	struct unacked_chunk_entry *unacked_chunk, *tmp;
	struct lt_udp_module_ctx *real_ctx = (struct lt_udp_module_ctx *)ctx;
	int serrno = 0, ret;

	if (usk->state == SHMEM_UDP_STATE_LISTEN) {
#ifndef THREAD_SAFE
		pthread_mutex_lock (&usk->common.listen_sock.accept_lock);
#endif
		/* Reset parent on all accepted sockets */
		for(csk = usk->common.listen_sock.accepted_sk; csk != NULL; csk = csk->hh.next) {
			csk->common.data_sock.parent = NULL;
		}
#ifndef THREAD_SAFE
		pthread_mutex_unlock (&usk->common.listen_sock.accept_lock);
#endif
	}
	else if (usk->state == SHMEM_UDP_STATE_ACCEPTED) {
		/* Remove from listen hash */
		if (usk->common.data_sock.parent != NULL) {
			csk = usk->common.data_sock.parent;
#ifndef THREAD_SAFE
			pthread_mutex_lock (&csk->common.listen_sock.accept_lock);
#endif
			HASH_DEL(csk->common.listen_sock.accepted_sk, usk);
#ifndef THREAD_SAFE
			pthread_mutex_unlock (&csk->common.listen_sock.accept_lock);
#endif
		}
	}
	else if (usk->state == SHMEM_UDP_STATE_CONNECTED) {
		/* Send fin command */
		lcmd.cmd = SHMEM_UDP_CMD_FIN;
		lcmd.payload.cookie = usk->conn_cookie;
		if (sendto (usk->fd, &lcmd, sizeof (lcmd), 0,
				(struct sockaddr *)&usk->common.data_sock.peer_addr,
				sizeof (struct sockaddr_in)) == -1) {
			serrno = errno;
		}
	}

	if (usk->state == SHMEM_UDP_STATE_CONNECTED || usk->state == SHMEM_UDP_STATE_ACCEPTED) {
		/* Free all chunks pending */
		unacked_chunk = usk->common.data_sock.unacked_chunks;
		while (unacked_chunk != NULL) {
			real_ctx->lib_ctx->allocator->allocator_free_func (real_ctx->lib_ctx->alloc_ctx,
					unacked_chunk->addr, unacked_chunk->len);
			tmp = unacked_chunk;
			unacked_chunk = unacked_chunk->next;
			lt_objcache_free (real_ctx->chunks_cache, tmp);
		}
	}

	ret = close (sk->fd);
	lt_objcache_free (real_ctx->sk_cache, sk);
	errno = serrno;

	return ret;
}

int
udp_shmem_destroy_func (struct lt_module_ctx *ctx)
{
	struct lt_udp_module_ctx *real_ctx = (struct lt_udp_module_ctx *)ctx;

	lt_objcache_destroy (real_ctx->cmd_cache);
	lt_objcache_destroy (real_ctx->sk_cache);
	lt_objcache_destroy (real_ctx->chunks_cache);
	free (real_ctx);
	return 0;
}
