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

#if     __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 8)
#  define _GNUC_EXTENSION __extension__
#else
#  define _GNUC_EXTENSION
#endif

#define lt_ptr_atomic_get(ptr) 								\
  (_GNUC_EXTENSION ({										\
    __sync_synchronize ();									\
    (void *) *(ptr);										\
  }))
#define lt_ptr_atomic_set(ptr, nptr)						\
  (_GNUC_EXTENSION ({										\
    (void) (0 ? (void *) *(ptr) : 0);						\
    *(ptr) = (__typeof__ (*(ptr))) (uintptr_t) (nptr);		\
    __sync_synchronize ();									\
  }))


/**
 * Asbtract module ctx
 */
struct lt_module_ctx {
	size_t len;					// Length of the context
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
	struct ltproto_module *mod;		// Module handling this socket
	UT_hash_handle hh;				// Hash entry
};

/**
 * Ltproto main context
 */
struct ltproto_ctx {
	struct ltproto_module *modules;		// Available modules
	struct ltproto_socket *sockets_hash; // Sockets table
	struct ltproto_socket **sockets_ar;	// Array of sockets
	struct ltproto_module *default_mod;	// Default module used for ltproto sockets
#ifndef THREAD_UNSAFE
	pthread_rwlock_t sock_lock;			// Lock for sockets table
	pthread_rwlock_t mod_lock;			// Lock for modules table
#endif
};

#define msec_to_tv(msec, tv) do { (tv)->tv_sec = (msec) / 1000; (tv)->tv_usec = ((msec) - (tv)->tv_sec * 1000) * 1000; } while(0)
#define tv_to_msec(tv) (tv)->tv_sec * 1000 + (tv)->tv_usec / 1000

#endif /* LTPROTO_INTERNAL_H_ */
