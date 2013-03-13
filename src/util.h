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

#ifndef UTIL_H_
#define UTIL_H_

#include "config.h"

/**
 * @file util.h
 * General function utilities for ltproto
 */

/**
 * Initialise pseudo random generator
 * @return opaque data pointer that must be freed by caller
 */
void* init_prng (void);

/**
 * Create new 64 bit pseudo-random number
 * @return pseudo random number
 */
int64_t get_random_seq (void *data);

/**
 * Create new pseudo random int
 * @param data opaque data pointer
 * @return
 */
int get_random_int (void *data);

#define MEM_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#define align_ptr(p, a)                                                   \
    (uintptr_t) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))
#define align_ptr_platform(p)                                                   \
    (uintptr_t) (((uintptr_t) (p) + ((uintptr_t) MEM_ALIGNMENT - 1)) & ~((uintptr_t) MEM_ALIGNMENT - 1))

#define msec_to_tv(msec, tv) do { (tv)->tv_sec = (msec) / 1000; (tv)->tv_usec = ((msec) - (tv)->tv_sec * 1000) * 1000; } while(0)
#define tv_to_msec(tv) (tv)->tv_sec * 1000 + (tv)->tv_usec / 1000

#endif /* UTIL_H_ */
