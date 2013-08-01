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

#if     __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 8)
#  define _GNUC_EXTENSION __extension__
#else
#  define _GNUC_EXTENSION
#endif

#ifdef __GNUC__
#define lt_int_atomic_get(ptr) 								\
  (_GNUC_EXTENSION ({										\
    __sync_synchronize ();									\
    (int) *(ptr);										\
  }))
#define lt_ptr_atomic_set(ptr, nptr)						\
  (_GNUC_EXTENSION ({										\
    *(ptr) = (__typeof__ (*(ptr))) (uintptr_t) (nptr);		\
    __sync_synchronize ();									\
  }))
#else
/* We have no gnuc intriniscs for memory barriers */
#define lt_int_atomic_get(ptr) 								\
  (_GNUC_EXTENSION ({										\
    (int) *(ptr);										\
  }))
#define lt_ptr_atomic_set(ptr, nptr)						\
  (_GNUC_EXTENSION ({										\
    (void) (0 ? (void *) *(ptr) : 0);						\
    *(ptr) = (__typeof__ (*(ptr))) (uintptr_t) (nptr);		\
  }))
#endif

static inline unsigned
lt_int_atomic_cmpxchg (volatile unsigned *loc, unsigned old, unsigned new)
{
	unsigned res;

	__asm __volatile (
			"lock cmpxchg %3, %1;"
			: "=a" (res), "=m" (*loc)
			: "0" (old),
			"r" (new),
			"m" (*loc)
			: "memory");
	return res;
}

static inline unsigned
lt_int_atomic_xchg (volatile unsigned *loc, unsigned new)
{
	unsigned res;

	__asm __volatile ("xchg %0, %1;"
			: "=r" (res),
			"=m" (*loc)
			: "m" (*loc),
			"0" (new)
			: "memory");
	return res;
}


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

#define MEM_ALIGNMENT   16    /* sse optimization */
#define align_ptr(p, a)                                                   \
    (uintptr_t) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))
#define align_ptr_platform(p)                                                   \
    (uintptr_t) (((uintptr_t) (p) + ((uintptr_t) MEM_ALIGNMENT - 1)) & ~((uintptr_t) MEM_ALIGNMENT - 1))

#define msec_to_tv(msec, tv) do { (tv)->tv_sec = (msec) / 1000; (tv)->tv_usec = ((msec) - (tv)->tv_sec * 1000) * 1000; } while(0)
#define tv_to_msec(tv) (tv)->tv_sec * 1000 + (tv)->tv_usec / 1000

/**
 * Wait for memory at pointer to get desired value, changing state to wait state while waiting
 * @param ptr pointer to wait
 * @param desired_value value to wait
 * @param wait_value set this value while waiting
 * @return value got or -1 in case of error
 */
int wait_for_memory_state (volatile int *ptr, int desired_value, int wait_value);

/**
 * Wait for memory at pointer to get desired value, not changing state using futex or monitor
 * @param ptr pointer to wait
 * @param desired_value value to wait
 * @return value got or -1 in case of error
 */
int wait_for_memory_passive (volatile int *ptr, int desired_value, volatile int *ptr2, int val2, const char *msg);

/**
* Wait for memory at pointer to get desired value, not changing state using sleep
 * @param ptr pointer to wait
 * @param desired_value value to wait
 * @return value got or -1 in case of error
 */
int wait_for_memory_sleep (volatile int *ptr, int desired_value, int nsec);

/**
 * Atomically set new value to the pointer and wake up futexes (if any)
 * @param ptr pointer to set
 * @param signalvalue value to emit signal
 * @param newvalue new value
 * @return old value or -1 in case of errror
 */
int signal_memory (volatile int *ptr, int signalvalue, int newvalue);


#endif /* UTIL_H_ */
