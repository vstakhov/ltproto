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
 * Init ltproto library
 */
void
ltproto_init (void)
{
	int i, max_priority = INT_MIN;
	struct ltproto_module *mod;
	allocator_t *alloc = NULL;

	lib_ctx = calloc (1, sizeof (struct ltproto_ctx));
	assert (lib_ctx != NULL);

	lib_ctx->prng = init_prng ();

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
			mod->ctx->lib_ctx = lib_ctx;
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

	max_priority = INT_MIN;
	for (i = 0;; i++) {
		if (allocators[i] != NULL) {
			if (allocators[i]->priority > max_priority) {
				alloc = allocators[i];
				max_priority = allocators[i]->priority;
			}
		}
		else {
			break;
		}
	}

	assert (alloc != NULL);
	lib_ctx->allocator = alloc;
	assert (lib_ctx->allocator->allocator_init_func (&lib_ctx->alloc_ctx, get_random_seq (lib_ctx->prng)) != -1);

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
ltproto_socket (void *module, struct ltproto_socket **psk)
{
	struct ltproto_module *mod;
	struct ltproto_socket *sk;
	int nodelay = 1, reuseaddr = 1;

	assert (lib_ctx != NULL);
	assert (psk != NULL);
	if (module != NULL) {
		mod = (struct ltproto_module *)module;
	}
	else {
		mod = lib_ctx->default_mod;
	}
	assert (mod != NULL);
	sk = mod->mod->module_socket_func (mod->ctx);
	if (sk == NULL) {
		return -1;
	}

	sk->mod = mod;
	sk->tcp_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk->tcp_fd == -1) {
		mod->mod->module_close_func (mod->ctx, sk);
		return -1;
	}

	setsockopt (sk->tcp_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof (reuseaddr));
	setsockopt (sk->tcp_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof (nodelay));

	*psk = sk;
	return 0;
}

/**
 * Set up an option for a socket. Currently only O_NONBLOCK is supported.
 * @param sock socket descriptor
 * @param optname an integer associated with option (O_NONBLOCK, for example)
 * @param optvalue a value of option
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int
ltproto_setsockopt (struct ltproto_socket *sk, int optname, int optvalue)
{
	if (sk != NULL) {
		return sk->mod->mod->module_setopts_func (sk->mod->ctx, sk, optname, optvalue);
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
ltproto_bind (struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	if (sk != NULL) {
		if (bind (sk->tcp_fd, addr, addrlen) == -1) {
			return -1;
		}
		return sk->mod->mod->module_bind_func (sk->mod->ctx, sk, addr, addrlen);
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
ltproto_listen (struct ltproto_socket *sk, int backlog)
{
	if (sk != NULL) {
		if (listen (sk->tcp_fd, backlog) == -1) {
			return -1;
		}
		return sk->mod->mod->module_listen_func (sk->mod->ctx, sk, backlog);
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
struct ltproto_socket *
ltproto_accept (struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen)
{
	struct ltproto_socket *ask;
	struct sockaddr_storage st;
	socklen_t st_len = sizeof (st);
	int tcp_fd;

	assert (lib_ctx != NULL);

	if (sk != NULL) {
		tcp_fd = accept (sk->tcp_fd, (struct sockaddr *)&st, &st_len);
		if (tcp_fd == -1) {
			return NULL;
		}
		ask = sk->mod->mod->module_accept_func (sk->mod->ctx, sk, addr, addrlen);
		if (ask != NULL) {
			ask->tcp_fd = tcp_fd;
			ask->mod = sk->mod;
			return ask;
		}
		else {
			close (tcp_fd);
			errno = EINVAL;
			return NULL;
		}
	}

	errno = -EBADF;
	return NULL;
}

/**
 * Connect a socket to a peer
 * @param socks socket descriptor
 * @param addr sockaddr structure (currently only sockaddr_in is supported) of a peer
 * @param addrlen length of addr structure (should be sizeof(struct sockaddr_in))
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int
ltproto_connect (struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	if (sk != NULL) {
		if (connect (sk->tcp_fd, addr, addrlen) == -1) {
			return -1;
		}
		return sk->mod->mod->module_connect_func (sk->mod->ctx, sk, addr, addrlen);
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
ltproto_read (struct ltproto_socket *sk, void *buf, size_t len)
{
	int r;

	if (sk != NULL) {
		if ((r = sk->mod->mod->module_read_func (sk->mod->ctx, sk, buf, len)) == -1) {
			return read (sk->tcp_fd, buf, len);
		}
		return r;
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
ltproto_write (struct ltproto_socket *sk, const void *buf, size_t len)
{
	int r;

	if (sk != NULL) {
		if ((r = sk->mod->mod->module_write_func (sk->mod->ctx, sk, buf, len)) == -1) {
			return write (sk->tcp_fd, buf, len);
		}
		return r;
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
ltproto_close (struct ltproto_socket *sk)
{
	if (sk != NULL) {
		close (sk->tcp_fd);
		return sk->mod->mod->module_close_func (sk->mod->ctx, sk);
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
ltproto_select (struct ltproto_socket *sk, short what, const struct timeval *tv)
{
	int r;
	struct pollfd pfd;

	if (sk != NULL) {
		if ((r = sk->mod->mod->module_select_func (sk->mod->ctx, sk, what, tv)) <= 0) {
			pfd.events = what;
			pfd.fd = sk->tcp_fd;
			pfd.revents = 0;
			return poll (&pfd, 1, tv_to_msec(tv));
		}
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

	/* Clear all modules */
	HASH_ITER (hh, lib_ctx->modules, mod, mod_tmp) {
		mod->mod->module_destroy_func (mod->ctx);
		HASH_DEL (lib_ctx->modules, mod);
		free (mod);
	}

	if (lib_ctx->prng) {
		free (lib_ctx->prng);
	}
	lib_ctx->allocator->allocator_destroy_func (lib_ctx->alloc_ctx);
	free (lib_ctx);
}

/**
 * Allocate chunk from ltproto allocator
 * @param size size of chunk
 */
void*
ltproto_alloc (size_t size, struct lt_alloc_tag *tag)
{
	assert (size != 0);

	return lib_ctx->allocator->allocator_alloc_func (lib_ctx->alloc_ctx, size, tag);
}

/**
 * Free chunk allocated by ltproto
 * @param size size of chunk
 * @param ptr pointer to chunk
 */
void
ltproto_free (size_t size, void *ptr)
{
	assert (ptr != 0);
	lib_ctx->allocator->allocator_free_func (lib_ctx->alloc_ctx, ptr, size);
}

/**
 * Try to switch allocator to another one
 * @param name name of allocator to switch to
 * @return -1 in case of error or 0 otherwise
 */
int
ltproto_switch_allocator (const char *name)
{
	allocator_t *alloc = NULL;
	int i;

	for (i = 0;; i++) {
		if (allocators[i] != NULL) {
			if (strcmp (allocators[i]->name, name) == 0) {
				alloc = allocators[i];
				break;
			}
		}
		else {
			break;
		}
	}

	if (alloc == NULL) {
		errno = ENOENT;
		return -1;
	}

	/* Destroy old allocator */
	lib_ctx->allocator->allocator_destroy_func (lib_ctx->alloc_ctx);
	lib_ctx->alloc_ctx = NULL;

	lib_ctx->allocator = alloc;
	assert (lib_ctx->allocator->allocator_init_func (&lib_ctx->alloc_ctx, get_random_seq (lib_ctx->prng)) != -1);

	return 0;
}
