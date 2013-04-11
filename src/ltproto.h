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

#ifndef LTPROTO_H_
#define LTPROTO_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/**
 * @file ltproto.h
 * @author Vsevolod Stakhov <vsevolod@highsecure.ru>
 * @section DESCRIPTION
 *
 * Ltproto is a modular system of local transport protocols implemented completely in
 * userspace. Ltproto must be initialized before using by calling ltproto_init function.
 * The specific algorithm of local transport can be specified by calling ltproto_select_module,
 * the best algorithm is used by default.
 *
 * Ltproto supports BSD socket like interface for operations, however, it supports only
 * SOCK_STREAM sockets at the moment.
 */

struct ltproto_socket;
/**
 * Init ltproto library
 */
void ltproto_init (void);

/**
 * Select desired module by name
 * @param module name of the module
 * @return pointer to module or -1 in case of error
 */
void* ltproto_select_module (const char *module);

/**
 * Create new ltproto socket
 * @param module pointer to module that should be used for this socket, if NULL the default module is selected
 * @return socket descriptor or -1 in case of error, see errno variable for details
 */
int ltproto_socket (void *module, struct ltproto_socket **sk);

/**
 * Set up an option for a socket. Currently only O_NONBLOCK is supported.
 * @param sock socket descriptor
 * @param optname an integer associated with option (O_NONBLOCK, for example)
 * @param optvalue a value of option
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int ltproto_setsockopt (struct ltproto_socket *sock, int optname, int optvalue);

/**
 * Bind socket to a specific address
 * @param sock socket descriptor
 * @param addr sockaddr structure (currently only sockaddr_in is supported)
 * @param addrlen length of addr structure (should be sizeof(struct sockaddr_in))
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int ltproto_bind (struct ltproto_socket *sock, const struct sockaddr *addr, socklen_t addrlen);

/**
 * Set listen mode for a specific socket
 * @param sock socket descriptor
 * @param backlog listen backlog queue size
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int ltproto_listen (struct ltproto_socket *sock, int backlog);

/**
 * Accept new connection from a listening socket
 * @param sock socket descriptor
 * @param addr sockaddr structure (currently only sockaddr_in is supported) that will be filled
 * @param addrlen length of addr structure (should be sizeof(struct sockaddr_in))
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
struct ltproto_socket* ltproto_accept (struct ltproto_socket *sock,
		struct sockaddr *addr, socklen_t *addrlen);

/**
 * Connect a socket to a peer
 * @param socks socket descriptor
 * @param addr sockaddr structure (currently only sockaddr_in is supported) of a peer
 * @param addrlen length of addr structure (should be sizeof(struct sockaddr_in))
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int ltproto_connect (struct ltproto_socket *sock, const struct sockaddr *addr, socklen_t addrlen);

/**
 * Read data from a socket
 * @param sock socket descriptor
 * @param buf buffer pointer
 * @param len length to read
 * @return number of bytes read or -1 in case of error
 */
int ltproto_read (struct ltproto_socket *sock, void *buf, size_t len);

/**
 * Get buffer without copying
 * @param sock socket descriptor
 * @param len read up to len bytes
 * @return pointer to a buffer
 */
void* ltproto_read_zero (struct ltproto_socket *sock, size_t len);

/**
 * Release read buffer for desired address
 * @param sock socket descriptor
 * @param address address to be released
 * @return 0 or -1 in case of error
 */
int ltproto_read_release (struct ltproto_socket *sock, void *address);

/**
 * Write data to a socket
 * @param sock socket descriptor
 * @param buf buffer pointer
 * @param len length to write
 * @return number of bytes written or -1 in case of error
 */
int ltproto_write (struct ltproto_socket *sock, const void *buf, size_t len);

/**
 * Get write buffer for zero-copy writing
 * @param sock socket descriptor
 * @param len length of write buffer required
 */
void* ltproto_get_write_buf (struct ltproto_socket *sock, size_t len);

/**
 * Write buffer in zero-copy mode
 * @param sock socket descriptor
 * @param buf buffer that should be transferred
 * @param len length of buffer
 * @return len or -1 in case of error
 */
int ltproto_write_zero (struct ltproto_socket *sock, void *buf, size_t len);


/**
 * Close a socket
 * @param sock socket descriptor
 * @return 0 if succeeded, -1 in case of error, see errno variable for details
 */
int ltproto_close (struct ltproto_socket *sock);

/**
 * Wait for an event on a non-blocking socket
 * @param sock socket descriptor
 * @param what POLLIN for read event and POLLOUT for write one (can be mixed via logical OR)
 * @param tv timeout for waiting
 * @return 0 in case of timeout, 1 in case of event happened, -1 in case of error
 */
int ltproto_select (struct ltproto_socket *sock, short what, const struct timeval *tv);

/**
 * Deinitialize of ltproto library
 */
void ltproto_destroy (void);

/**
 * Utility functions
 */
/**
 * Allocate chunk from ltproto allocator
 * @param size size of chunk
 */
void* ltproto_alloc (size_t size);

/**
 * Free chunk allocated by ltproto
 * @param size size of chunk
 * @param ptr pointer to chunk
 */
void ltproto_free (size_t size, void *ptr);

/**
 * Try to switch allocator to another one
 * @param name name of allocator to switch to
 * @return -1 in case of error or 0 otherwise
 */
int ltproto_switch_allocator (const char *name);

#endif /* LTPROTO_H_ */
