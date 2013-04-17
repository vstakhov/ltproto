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

#ifndef OBJCACHE_H_
#define OBJCACHE_H_

#include "config.h"

/**
 * @file objcache.h
 * Object cache is an efficient storage for small reusable objects.
 */
struct lt_objcache;

/**
 * Create new object cache
 * @param elt_size size of elements in this cache
 * @return new object cache
 */
struct lt_objcache* lt_objcache_create (size_t elt_size);
/**
 * Allocate element of elt_size form cache
 * @param cache cache object
 */
void* lt_objcache_alloc (struct lt_objcache *cache);
/**
 * Free element from cache
 * @param cache cache object
 * @param addr address to free
 */
void lt_objcache_free (struct lt_objcache *cache, void *addr);
/**
 * Destroy object cache and all associated objects
 * @param cache
 */
void lt_objcache_destroy (struct lt_objcache *cache);

#endif /* OBJCACHE_H_ */
