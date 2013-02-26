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
			uint32_t conn_cookie;	// Connection cookie
			uint32_t seqno;			// Sequence number
			uint32_t seglen;		// Segment length
		} data;
	} payload;
};

struct ltproto_udp_command_entry {
	struct ltproto_udp_command cmd;
	struct sockaddr_in sin;
	TAILQ_ENTRY (ltproto_udp_command_entry) link;
};

struct ltproto_socket_udp {
	int fd;							// Socket descriptor
	struct ltproto_module *mod;		// Module handling this socket
	UT_hash_handle hh;				// Hash entry
	u_char mod_data[1];				// Module's private data
	enum {
		SHMEM_UDP_STATE_INIT = 0,
		SHMEM_UDP_STATE_LISTEN,
		SHMEM_UDP_STATE_CONNECTED
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
		} data_sock;
		struct {
			struct ltproto_socket_udp *accepted_sk; // Hash of accepted sockets
#ifndef THREAD_UNSAFE
			pthread_mutex_t acept_lock;
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
		case SHMEM_UDP_CMD_CONNECT_ACK:
			/* Enqueue to this socket */
			TAILQ_INSERT_TAIL (&usk->in_q, cmd_entry, link);
			break;
		case SHMEM_UDP_CMD_SEND:
		case SHMEM_UDP_CMD_ACK:
		case SHMEM_UDP_CMD_FIN:
			/* Try to find appropriate socket */
#ifndef THREAD_SAFE
			pthread_mutex_lock (&usk->common.listen_sock.acept_lock);
#endif
			HASH_FIND_INT (usk->common.listen_sock.accepted_sk, &cmd->payload.data.conn_cookie, sk_found);
#ifndef THREAD_SAFE
			pthread_mutex_unlock (&usk->common.listen_sock.acept_lock);
#endif
			if (sk_found == NULL) {
				return -1;
			}
			TAILQ_INSERT_TAIL (&sk_found->in_q, cmd_entry, link);
			break;
		}
	}
	else if (usk->state == SHMEM_UDP_STATE_CONNECTED) {
		switch (cmd->cmd) {
		case SHMEM_UDP_CMD_CONNECT:
		case SHMEM_UDP_CMD_CONNECT_ACK:
			/* Enqueue to parent socket */
			TAILQ_INSERT_TAIL (&usk->common.data_sock.parent->in_q, cmd_entry, link);
			break;
		case SHMEM_UDP_CMD_SEND:
		case SHMEM_UDP_CMD_ACK:
		case SHMEM_UDP_CMD_FIN:
			/* Try to find appropriate socket */
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
	struct ltproto_udp_command cmd, *pcmd;
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
		}
		return NULL;
	}

	/* Actually we alloc memory for the whole entry here */
	pcmd = malloc (sizeof (struct ltproto_udp_command_entry));
	assert (pcmd != NULL);
	memcpy (pcmd, &cmd, sizeof (cmd));
	memcpy (pcmd + sizeof (cmd), &sin, slen);

	return pcmd;
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

	/* Check queue first */
#ifndef THREAD_UNSAFE
	pthread_mutex_lock (&usk->inq_lock);
#endif
	TAILQ_FOREACH (cur, &usk->in_q, link) {
		if (cur->cmd.cmd == cmd) {
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
			return NULL;
		}

		if (udp_shmem_enqueue_command (usk, res) == -1) {
			/* Do not accept commands that cannot be enqueued */
			*saved_errno = EINVAL;
			free (res);
			return NULL;
		}

		if (res->cmd == cmd) {
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

	usk->state = SHMEM_UDP_STATE_LISTEN;
#ifndef THREAD_SAFE
	pthread_mutex_init (&usk->common.listen_sock.acept_lock, NULL);
#endif

	return 0;
}

struct ltproto_socket *
udp_shmem_accept_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk, *nsk = NULL;
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
		nsk = calloc (1, sizeof (struct ltproto_socket_udp));
		if (nsk == NULL) {
			return NULL;
		}
		nsk->fd = dup (usk->fd);
		if (nsk->fd == -1) {
			free (nsk);
			return NULL;
		}
		nsk->common.data_sock.parent = usk;
		nsk->cookie_local = rand ();

		/* Make connection cookie */
		nsk->conn_cookie = (((long)(nsk->cookie_local + cmd->cmd.payload.cookie) *
				(nsk->cookie_local + cmd->cmd.payload.cookie + 1)) << 2) + cmd->cmd.payload.cookie;
		lcmd.cmd = SHMEM_UDP_CMD_CONNECT_ACK;
		lcmd.payload.cookie = nsk->cookie_local;
		if (sendto (nsk->fd, &lcmd, sizeof (lcmd), 0, (struct sockaddr *)&cmd->sin, sizeof (cmd->sin)) == -1) {
			close (nsk->fd);
			free (nsk);
			return NULL;
		}

		TAILQ_INIT (&nsk->in_q);
		TAILQ_INIT (&nsk->out_q);
#ifndef THREAD_SAFE
		pthread_mutex_init (&nsk->inq_lock, NULL);
		pthread_mutex_init (&nsk->outq_lock, NULL);
#endif
#ifndef THREAD_SAFE
		pthread_mutex_lock (&usk->common.listen_sock.acept_lock);
#endif
		HASH_ADD_INT (usk->common.listen_sock.accepted_sk, conn_cookie, nsk);
#ifndef THREAD_SAFE
		pthread_mutex_unlock (&usk->common.listen_sock.acept_lock);
#endif
	}
	else {
		errno = serrno;
	}

	return (struct ltproto_socket *)nsk;
}

int
udp_shmem_connect_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk;
	return connect (sk->fd, addr, addrlen);
}

ssize_t
udp_shmem_read_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len)
{
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk;
	return len;
}

ssize_t
udp_shmem_write_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len)
{
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk;
	return len;
}

int
udp_shmem_select_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk, short what, const struct timeval *tv)
{
	struct pollfd pfd;
	int msec = -1;
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk;

	pfd.events = what;
	pfd.fd = sk->fd;

	if (tv != NULL) {
		msec = tv_to_msec (tv);
	}

	return 1;
}

int
udp_shmem_close_func (struct lt_module_ctx *ctx, struct ltproto_socket *sk)
{
	struct ltproto_socket_udp *usk = (struct ltproto_socket_udp *)sk;
	return close (sk->fd);
}

int
udp_shmem_destroy_func (struct lt_module_ctx *ctx)
{
	free (ctx);
	return 0;
}
