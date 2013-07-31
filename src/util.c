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
#include "ltproto_internal.h"
#include "util.h"
#ifdef HAVE_OPENSSL
#include <openssl/rand.h>
#endif
#ifdef HAVE_FUTEX
#include <linux/futex.h>
#include <sys/syscall.h>
#endif
#ifdef HAVE_UMTX_OP
#include <sys/umtx.h>
#endif
/**
 * Initialise pseudo random generator
 */
void *
init_prng (void)
{
	union {
		int iseed;
		long lseed;
	} seed;
	void *res = NULL;
	/* Init pseudo-random generator using openssl if possible */
#ifdef HAVE_OPENSSL

	if (access ("/dev/random", R_OK) != -1) {
		RAND_load_file ("/dev/urandom", 256);
	}
	if (RAND_bytes ((char *)&seed, sizeof (seed)) != 1) {
		seed.lseed = time (NULL);
	}
#else
	/* Unsafe way */
	seed.lseed = time (NULL);
#endif

	srand (seed.iseed);
#ifdef HAVE_ARC4RAND
	/* Arc4random is not thread safe */
# ifndef THREAD_UNSAFE
	res = calloc (sizeof (pthread_mutex_t));
	pthread_mutex_init (res, NULL);
# endif
	arc4stir ();
#endif
#ifdef HAVE_SETSRANDOM_R
	res = calloc (sizeof (struct random_data));
	srandom_r (seed.lseed, (struct random_data *)res);
#endif

	return res;
}

/**
 * Create new 64 bit pseudo-random number
 * @return pseudo random number
 */
int64_t
get_random_seq (void *data)
{
	int64_t res;
	int32_t *p = (int32_t *)&res;

	/* Select the best generator available */
#ifdef HAVE_ARC4RAND
# ifndef THREAD_UNSAFE
	pthread_mutex_lock (data);
# endif
	arc4random_buf (p, sizeof (res));
# ifndef THREAD_UNSAFE
	pthread_mutex_unlock (data);
# endif
#elif defined(HAVE_SETSRANDOM_R)
	/* Compose of two random integers */
	random_r (data, p++);
	random_r (data, p);
#else
	/* Compose of two random integers */
	*p++ = rand ();
	*p = rand();
#endif
	return res;
}


/**
 * Create new 64 bit pseudo-random number
 * @return pseudo random number
 */
int
get_random_int (void *data)
{
	int res;
	int *p = (int *)&res;

	/* Select the best generator available */
#ifdef HAVE_ARC4RAND
# ifndef THREAD_UNSAFE
	pthread_mutex_lock (data);
# endif
	arc4random_buf (p, sizeof (res));
# ifndef THREAD_UNSAFE
	pthread_mutex_unlock (data);
# endif
#elif defined(HAVE_SETSRANDOM_R)
	random_r (data, p);
#else
	*p = rand();
#endif
	return res;
}


int
wait_for_memory_state (volatile int *ptr, int desired_value, int wait_value)
{
	int val;

	for (;;) {
		val = lt_int_atomic_get (ptr);

		if (val == desired_value) {
			break;
		}
		/* Need to spin */
#ifdef HAVE_FUTEX
		if (val == wait_value || __sync_bool_compare_and_swap (ptr, val, wait_value)) {
			if (syscall (SYS_futex, ptr, FUTEX_WAIT, wait_value, NULL, NULL, 0) == -1) {
				return -1;
			}
		}
#elif defined(HAVE_UMTX_OP)
		if (val == wait_value || __sync_bool_compare_and_swap (ptr, val, wait_value)) {
			if (_umtx_op ((void *)ptr, UMTX_OP_WAIT_UINT, wait_value, 0, NULL) == -1) {
				return -1;
			}
		}
#elif defined(HAVE_HAVE_MONITOR_MWAIT)
		for (;;) {
			if (val == wait_value || __sync_bool_compare_and_swap (ptr, val, wait_value)) {
				__asm __volatile("monitor"
						:  "=m" (*(char *)&ptr)
						: "a" (ptr), "c" (0), "d" (0));
				val = lt_ptr_atomic_get (ptr);
				if (val == desired_value) {
					return 0;
				}
				__asm __volatile("mwait"
						:
						: "a" (0), "c" (0));
			}
		}
#else
		errno = ENOSYS;
		return -1;
#endif
	}

	return 0;
}


/**
 * Wait for memory at pointer to get desired value, not changing state
 * @param ptr pointer to wait
 * @param desired_value value to wait
 * @return value got or -1 in case of error
 */
int
wait_for_memory_passive (volatile int *ptr, int desired_value)
{
	int val;

	for (;;) {
		val = lt_int_atomic_get (ptr);

		if (val == desired_value) {
			break;
		}
		/* Need to spin */
#ifdef HAVE_FUTEX
		if (syscall (SYS_futex, ptr, FUTEX_WAIT, val, NULL, NULL, 0) == -1) {
			if (errno == EWOULDBLOCK) {
				continue;
			}
			return -1;
		}
#elif defined(HAVE_UMTX_OP)
		if (_umtx_op ((void *)ptr, UMTX_OP_WAIT_UINT, val, 0, NULL) == -1) {
			if (errno == EWOULDBLOCK) {
				continue;
			}
			return -1;
		}
#elif defined(HAVE_HAVE_MONITOR_MWAIT)
		for (;;) {
			__asm __volatile("monitor"
					:  "=m" (*(char *)&ptr)
					   : "a" (ptr), "c" (0), "d" (0));
			val = lt_int_atomic_get (ptr);
			if (val == desired_value) {
				return 0;
			}
			__asm __volatile("mwait"
					:
					: "a" (0), "c" (0));
		}
#else
		errno = ENOSYS;
		return -1;
#endif
	}

	return 0;
}

/**
* Wait for memory at pointer to get desired value, not changing state using sleep
 * @param ptr pointer to wait
 * @param desired_value value to wait
 * @return value got or -1 in case of error
 */
int
wait_for_memory_sleep (volatile int *ptr, int desired_value, int nsec)
{
	int val, cycles = 0;
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = nsec
	};

	for (;;) {
		val = lt_int_atomic_get (ptr);

		if (val == desired_value) {
			break;
		}
		/* Need to spin */
		(void)nanosleep (&ts, NULL);
		cycles ++;
		if (cycles > 100) {
			errno = ETIMEDOUT;
			return -1;
		}
	}

	return 0;
}

int
signal_memory (volatile int *ptr, int newvalue)
{
	lt_ptr_atomic_set (ptr, newvalue);
#ifdef HAVE_FUTEX
	if (syscall (SYS_futex, ptr, FUTEX_WAKE, 1, NULL, NULL, 0) == -1) {
		return -1;
	}
#elif defined(HAVE_UMTX_OP)
	if (_umtx_op ((void *)ptr, UMTX_OP_WAKE, 1, 0, 0) == -1) {
		return -1;
	}
#endif
	return 0;
}
