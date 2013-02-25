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

static struct ltproto_ctx *lib_ctx = NULL;

/**
 * Find a socket in socket array or hash
 * @param ctx library context
 * @param fd socket descriptor
 * @return sk structure or NULL if this fd was not found
 */
static struct ltproto_socket*
find_sk (struct ltproto_ctx *ctx, int fd)
{
	struct ltproto_socket *sk;

	if (fd < SK_ARRAY_BUCKETS) {
		return lt_ptr_atomic_get (&ctx->sockets_ar[fd]);
	}
	else {
		SOCK_TABLE_RDLOCK (ctx);
		HASH_FIND_INT (ctx->sockets_hash, &fd, sk);
		SOCK_TABLE_UNLOCK (ctx);
	}

	return sk;
}

/**
 * Init ltproto library
 */
void
ltproto_init (void)
{
	int i, max_priority = INT_MIN;
	struct ltproto_module *mod;

	lib_ctx = calloc (1, sizeof (struct ltproto_ctx));
	assert (lib_ctx != NULL);

	lib_ctx->sockets_ar = calloc (SK_ARRAY_BUCKETS, sizeof (struct ltproto_socket *));
	assert (lib_ctx->sockets_ar != NULL);

#ifndef THREAD_UNSAFE
	pthread_rwlock_init (&lib_ctx->sock_lock, NULL);
	pthread_rwlock_init (&lib_ctx->mod_lock, NULL);
#endif
	/* Init modules */
	for (i = 0;; i++) {
		if (modules[i] != NULL) {
			mod = calloc (1, sizeof (struct ltproto_module));
			assert (mod != NULL);
			modules[i]->module_init_func (&mod->ctx);
			mod->mod = modules[i];
			mod->name = modules[i]->name;
			MOD_TABLE_WRLOCK (lib_ctx);
			HASH_ADD_KEYPTR (hh, lib_ctx->modules, mod->name, strlen (mod->name), mod);
			MOD_TABLE_UNLOCK (lib_ctx);
			if (modules[i]->priority > max_priority) {
				lib_ctx->default_mod = mod;
				max_priority = modules[i]->priority;
			}
		}
		else {
			break;
		}
	}

	/* Do we have any modules defined ? */
	assert (lib_ctx->default_mod != NULL);
}

/**
 * Select desired module by name
 * @param module name of the module
 * @return pointer to module or -1 in case of error
 */
void*
ltproto_select_module (const char *module)
{
	struct ltproto_module *mod;

	assert (module != NULL);
	assert (lib_ctx != NULL);

	MOD_TABLE_RDLOCK (lib_ctx);
	HASH_FIND_STR (lib_ctx->modules, module, mod);
	MOD_TABLE_UNLOCK (lib_ctx);

	return mod;
}

/**
 * Create new ltproto socket
 * @param module pointer to module that should be used for this socket, if NULL the default module is selected
 * @return socket descriptor or -1 in case of error, see errno variable for details
 */
int
ltproto_socket (void *module)
{
	int nsock;
	struct ltproto_module *mod;
	struct ltproto_socket *sk;

	assert (lib_ctx != NULL);
	if (module != NULL) {
		mod = (struct ltproto_module *)module;
	}
	else {
		mod = lib_ctx->default_mod;
	}
	assert (mod != NULL);
	nsock = mod->mod->module_socket_func (mod->ctx);
	if (nsock != -1) {
		if (find_sk (lib_ctx, nsock) != NULL) {
			/* Duplicate socket, internal error */
			errno = EINVAL;
			return -1;
		}
		sk = calloc (1, sizeof (struct ltproto_socket));
		assert (sk != NULL);
		sk->fd = nsock;
		sk->mod = mod;
		if (nsock < SK_ARRAY_BUCKETS) {
			lt_ptr_atomic_set (&lib_ctx->sockets_ar[nsock], sk);
		}
		else {
			SOCK_TABLE_WRLOCK (lib_ctx);
			HASH_ADD_INT (lib_ctx->sockets_hash, fd, sk);
			SOCK_TABLE_UNLOCK (lib_ctx);
		}
	}

	return nsock;
}

/**
 * Set up an option for a socket. Currently only O_NONBLOCK is supported.
 * @param sock socket descriptor
 * @param optname an integer associated with option (O_NONBLOCK, for example)
 * @param optvalue a value of option
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int
ltproto_setsockopt (int sock, int optname, int optvalue)
{
	struct ltproto_socket *sk;

	assert (lib_ctx != NULL);
	sk = find_sk (lib_ctx, sock);

	if (sk != NULL) {
		return sk->mod->mod->module_setopts_func (sk->mod->ctx, sock, optname, optvalue);
	}

	errno = -EBADF;
	return -1;
}

/**
 * Bind socket to a specific address
 * @param sock socket descriptor
 * @param addr sockaddr structure (currently only sockaddr_in is supported)
 * @param addrlen length of addr structure (should be sizeof(struct sockaddr_in))
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int
ltproto_bind (int sock, const struct sockaddr *addr, socklen_t addrlen)
{
	struct ltproto_socket *sk;

	assert (lib_ctx != NULL);
	sk = find_sk (lib_ctx, sock);

	if (sk != NULL) {
		return sk->mod->mod->module_bind_func (sk->mod->ctx, sock, addr, addrlen);
	}

	errno = -EBADF;
	return -1;
}

/**
 * Set listen mode for a specific socket
 * @param sock socket descriptor
 * @param backlog listen backlog queue size
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int
ltproto_listen (int sock, int backlog)
{
	struct ltproto_socket *sk;

	assert (lib_ctx != NULL);
	sk = find_sk (lib_ctx, sock);

	if (sk != NULL) {
		return sk->mod->mod->module_listen_func (sk->mod->ctx, sock, backlog);
	}

	errno = -EBADF;
	return -1;
}

/**
 * Accept new connection from a listening socket
 * @param sock socket descriptor
 * @param addr sockaddr structure (currently only sockaddr_in is supported) that will be filled
 * @param addrlen length of addr structure (should be sizeof(struct sockaddr_in))
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int
ltproto_accept (int sock, struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket *sk;

	assert (lib_ctx != NULL);
	sk = find_sk (lib_ctx, sock);

	if (sk != NULL) {
		return sk->mod->mod->module_accept_func (sk->mod->ctx, sock, addr, addrlen);
	}

	errno = -EBADF;
	return -1;
}

/**
 * Connect a socket to a peer
 * @param socks socket descriptor
 * @param addr sockaddr structure (currently only sockaddr_in is supported) of a peer
 * @param addrlen length of addr structure (should be sizeof(struct sockaddr_in))
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int
ltproto_connect (int sock, const struct sockaddr *addr, socklen_t addrlen)
{
	struct ltproto_socket *sk;

	assert (lib_ctx != NULL);
	sk = find_sk (lib_ctx, sock);

	if (sk != NULL) {
		return sk->mod->mod->module_bind_func (sk->mod->ctx, sock, addr, addrlen);
	}

	errno = -EBADF;
	return -1;
}

/**
 * Read data from a socket
 * @param sock socket descriptor
 * @param buf buffer pointer
 * @param len length to read
 * @return number of bytes read or -1 in case of error
 */
int
ltproto_read (int sock, void *buf, size_t len)
{
	struct ltproto_socket *sk;

	assert (lib_ctx != NULL);
	sk = find_sk (lib_ctx, sock);

	if (sk != NULL) {
		return sk->mod->mod->module_read_func (sk->mod->ctx, sock, buf, len);
	}

	errno = -EBADF;
	return -1;
}

/**
 * Write data to a socket
 * @param sock socket descriptor
 * @param buf buffer pointer
 * @param len length to write
 * @return number of bytes written or -1 in case of error
 */
int
ltproto_write (int sock, const void *buf, size_t len)
{
	struct ltproto_socket *sk;

	assert (lib_ctx != NULL);
	sk = find_sk (lib_ctx, sock);

	if (sk != NULL) {
		return sk->mod->mod->module_write_func (sk->mod->ctx, sock, buf, len);
	}

	errno = -EBADF;
	return -1;
}

/**
 * Close a socket
 * @param sock socket descriptor
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int
ltproto_close (int sock)
{
	struct ltproto_socket *sk;
	int ret;

	assert (lib_ctx != NULL);
	sk = find_sk (lib_ctx, sock);

	if (sk != NULL) {
		ret = sk->mod->mod->module_close_func (sk->mod->ctx, sock);
		if (ret != -1) {
			if (sock < SK_ARRAY_BUCKETS) {
				lt_ptr_atomic_set (&lib_ctx->sockets_ar[sock], NULL);
			}
			else {
				SOCK_TABLE_WRLOCK (lib_ctx);
				HASH_DEL (lib_ctx->sockets_hash, sk);
				SOCK_TABLE_UNLOCK (lib_ctx);
			}
			free (sk);
		}
		return ret;
	}

	errno = -EBADF;
	return -1;
}

/**
 * Wait for an event on a non-blocking socket
 * @param sock socket descriptor
 * @param what POLLIN for read event and POLLOUT for write one (can be mixed via logical OR)
 * @param tv timeout for waiting
 * @return 0 in case of timeout, 1 in case of event happened, -1 in case of error
 */
int
ltproto_select (int sock, short what, const struct timeval *tv)
{
	struct ltproto_socket *sk;

	assert (lib_ctx != NULL);
	sk = find_sk (lib_ctx, sock);

	if (sk != NULL) {
		return sk->mod->mod->module_select_func (sk->mod->ctx, sock, what, tv);
	}

	errno = -EBADF;
	return -1;
}

/**
 * Deinitialize of ltproto library
 */
void
ltproto_destroy (void)
{
	struct ltproto_module *mod, *mod_tmp;
	struct ltproto_socket *sk, *sk_tmp;
	int i;

	/* Close all sockets */
	for (i = 0; i < SK_ARRAY_BUCKETS; i ++) {
		if (lib_ctx->sockets_ar[i] != NULL) {
			sk = lib_ctx->sockets_ar[i];
			sk->mod->mod->module_close_func (sk->mod->ctx, sk->fd);
			free (sk);
		}
	}
	HASH_ITER (hh, lib_ctx->sockets_hash, sk, sk_tmp) {
		sk->mod->mod->module_close_func (sk->mod->ctx, sk->fd);
		HASH_DEL (lib_ctx->sockets_hash, sk);
		free (sk);
	}

	/* Clear all modules */
	HASH_ITER (hh, lib_ctx->modules, mod, mod_tmp) {
		mod->mod->module_destroy_func (mod->ctx);
		HASH_DEL (lib_ctx->modules, mod);
		free (mod);
	}

	free (lib_ctx);
}
