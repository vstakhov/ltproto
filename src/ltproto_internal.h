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

#ifndef LTPROTO_INTERNAL_H_
#define LTPROTO_INTERNAL_H_

#include "config.h"
#include "uthash.h"
#include "util.h"
#include "objcache.h"

/**
 * @file ltproto_internal.h
 * @section DESCRIPTION
 *
 * Internal structures and functions used by ltproto library
 */

/*
 * Locking macroes
 */

#ifndef THREAD_UNSAFE
 #define SOCK_TABLE_RDLOCK(ctx) do { pthread_rwlock_rdlock (&(ctx)->sock_lock); } while(0)
 #define SOCK_TABLE_WRLOCK(ctx) do { pthread_rwlock_wrlock (&(ctx)->sock_lock); } while(0)
 #define SOCK_TABLE_UNLOCK(ctx) do { pthread_rwlock_unlock (&(ctx)->sock_lock); } while(0)
 #define MOD_TABLE_RDLOCK(ctx) do { pthread_rwlock_rdlock (&(ctx)->mod_lock); } while(0)
 #define MOD_TABLE_WRLOCK(ctx) do { pthread_rwlock_wrlock (&(ctx)->mod_lock); } while(0)
 #define MOD_TABLE_UNLOCK(ctx) do { pthread_rwlock_unlock (&(ctx)->mod_lock); } while(0)
#else
 #define SOCK_TABLE_RDLOCK(ctx) do { } while(0)
 #define SOCK_TABLE_WRLOCK(ctx) do { } while(0)
 #define SOCK_TABLE_UNLOCK(ctx) do { } while(0)
 #define MOD_TABLE_RDLOCK(ctx) do { } while(0)
 #define MOD_TABLE_WRLOCK(ctx) do { } while(0)
 #define MOD_TABLE_UNLOCK(ctx) do { } while(0)
#endif

#define SK_ARRAY_BUCKETS 1024


/**
 * Forwarded declarations
 */
struct ltproto_ctx;
struct lt_module_ctx;
struct ltproto_socket;

struct lt_allocator_ctx;
struct lt_alloc_tag;

/**
 * Common ltproto module
 */
typedef struct module_s {
    char *name;
    int priority;
    bool pollable;
    int (*module_init_func)(struct lt_module_ctx **ctx);
    struct ltproto_socket * (*module_socket_func)(struct lt_module_ctx *ctx);
    int (*module_setopts_func)(struct lt_module_ctx *ctx, struct ltproto_socket *sk, int optname, int optvalue);
    int (*module_bind_func)(struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
    int (*module_listen_func)(struct lt_module_ctx *ctx, struct ltproto_socket *sk, int backlog);
    struct ltproto_socket * (*module_accept_func)(struct lt_module_ctx *ctx, struct ltproto_socket *sk, struct sockaddr *addr, socklen_t *addrlen);
    int (*module_connect_func)(struct lt_module_ctx *ctx, struct ltproto_socket *sk, const struct sockaddr *addr, socklen_t addrlen);
    ssize_t (*module_read_func)(struct lt_module_ctx *ctx, struct ltproto_socket *sk, void *buf, size_t len);
    ssize_t (*module_write_func)(struct lt_module_ctx *ctx, struct ltproto_socket *sk, const void *buf, size_t len);
    /** TODO: add iovector functions as well */
    int (*module_get_wait_fd)(struct lt_module_ctx *ctx, struct ltproto_socket *sk);
    int (*module_close_func)(struct lt_module_ctx *ctx, struct ltproto_socket *sk);
    int (*module_destroy_func)(struct lt_module_ctx *ctx);
} module_t;

/**
 * Common ltproto allocator
 */
typedef struct allocator_s {
	char *name;
	int priority;
	int (*allocator_init_func)(struct lt_allocator_ctx **ctx, uint64_t init_seq);
	void * (*allocator_alloc_func)(struct lt_allocator_ctx *ctx, size_t size, struct lt_alloc_tag *tag);
	void * (*allocator_attachtag_func)(struct lt_allocator_ctx *ctx, struct lt_alloc_tag *tag);
	void (*allocator_free_func)(struct lt_allocator_ctx *ctx, void *addr, size_t size);
	void (*allocator_destroy_func)(struct lt_allocator_ctx *ctx);
	void (*allocator_set_numa_node)(struct lt_allocator_ctx *ctx, int node);
} allocator_t;

/**
 * Abstract allocator ctx
 */
struct lt_allocator_ctx {
	size_t len;
	size_t bytes_allocated;
	uint64_t seq;
	int numa_node;
	struct ltproto_ctx *lib_ctx;	// Parent ctx
};

/**
 * Unique identifier of memory region
 */
struct lt_alloc_tag {
	uint64_t seq;				// Constantly growing sequence
	uint64_t id;				// Unique ID
};

/**
 * Asbtract module ctx
 */
struct lt_module_ctx {
	size_t len;						// Length of the context
	struct ltproto_ctx *lib_ctx;	// Parent ctx
	struct lt_objcache *sk_cache;	// Object cache for sockets
};

/**
 * Hash entry for modules table
 */
struct ltproto_module {
	char *name;
	module_t *mod;
	struct lt_module_ctx *ctx;
	UT_hash_handle hh;
};

/**
 * Hash entry for sockets table
 */
struct ltproto_socket {
	int fd;							// Socket descriptor
	int tcp_fd;						// TCP link socket
	struct ltproto_module *mod;		// Module handling this socket
	UT_hash_handle hh;				// Hash entry
	u_char mod_data[1];				// Module's private data
};

/**
 * Ltproto main context
 */
struct ltproto_ctx {
	void *prng;							// Prng specific data
	struct ltproto_module *modules;		// Available modules
	struct ltproto_module *default_mod;	// Default module used for ltproto sockets
	allocator_t *allocator;
	struct lt_allocator_ctx *alloc_ctx;	// Allocator context
#ifndef THREAD_UNSAFE
	pthread_rwlock_t sock_lock;			// Lock for sockets table
	pthread_rwlock_t mod_lock;			// Lock for modules table
#endif
};

#endif /* LTPROTO_INTERNAL_H_ */
