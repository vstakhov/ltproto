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
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
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
#ifdef HAVE_CPUID_H
# include <cpuid.h>
#endif
#ifdef HAVE_NUMA_H
# include <numa.h>
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
wait_for_memory_state (volatile int *ptr, int desired_value, int wait_value, int forbidden_value)
{
	int val;

	for (;;) {
		val = lt_int_atomic_get (ptr);

		if (val == desired_value || val == forbidden_value) {
			break;
		}
		/* Need to spin */
#ifdef HAVE_FUTEX
		if (lt_int_atomic_cmpxchg (ptr, val, wait_value) == val) {
			if (syscall (SYS_futex, ptr, FUTEX_WAIT, wait_value, NULL, NULL, 0) == -1) {
				if (errno == EWOULDBLOCK) {
					continue;
				}
				return -1;
			}
		}
#elif defined(HAVE_UMTX_OP)
		if (lt_int_atomic_cmpxchg (ptr, val, wait_value) == val) {
			if (_umtx_op ((void *)ptr, UMTX_OP_WAIT_UINT, wait_value, 0, NULL) == -1) {
				if (errno == EWOULDBLOCK) {
					continue;
				}
				return -1;
			}
		}
#elif defined(HAVE_HAVE_MONITOR_MWAIT)
		for (;;) {
			if (val == wait_value || lt_int_atomic_cmpxchg (ptr, val, wait_value)) {
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
wait_for_memory_passive (volatile int *ptr, int desired_value, volatile int *ptr2, int val2, const char *msg)
{
	int val, oldval2;
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = 1000
	};

	for (;;) {
		val = lt_int_atomic_get (ptr);
		oldval2 = lt_int_atomic_get (ptr2);

		if (val == desired_value) {
			break;
		}
		/* Need to spin */
		lt_int_atomic_cmpxchg (ptr2, oldval2, val2);
#ifdef HAVE_FUTEX
		fprintf (stderr, "wait for %s\n", msg);
		if (syscall (SYS_futex, ptr, FUTEX_WAIT, val, NULL, NULL, 0) == -1) {
			lt_int_atomic_cmpxchg (ptr2, val2, oldval2);
			if (errno == EWOULDBLOCK) {
				continue;
			}
			return -1;
		}
		lt_int_atomic_cmpxchg (ptr2, val2, oldval2);
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

#define BUSY_CYCLES 256

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
		while (cycles++ < BUSY_CYCLES) {
			val = *ptr;

			if (val == desired_value) {
				return 0;
			}
		}
		cycles = 0;
		/* Need to spin */
		sched_yield ();
		//(void)nanosleep (&ts, NULL);
	}

	return 0;
}

int
signal_memory (volatile int *ptr, int signalvalue, int newvalue)
{
	int oldval;

	oldval = lt_int_atomic_xchg (ptr, newvalue);
#ifdef HAVE_FUTEX
	if (oldval & signalvalue) {
		if (syscall (SYS_futex, ptr, FUTEX_WAKE, 1, NULL, NULL, 0) == -1) {
			return -1;
		}
	}
#elif defined(HAVE_UMTX_OP)
	if (oldval & signalvalue) {
		if (_umtx_op ((void *)ptr, UMTX_OP_WAKE, 1, 0, 0) == -1) {
			return -1;
		}
	}
#endif
	return 0;
}

#ifndef HAVE_SETPROCTITLE
static char                    *title_buffer = 0;
static size_t                   title_buffer_size = 0;
static char                    *title_progname, *title_progname_full;
extern char *program_invocation_name, *program_invocation_short_name, **environ;
int
lt_setproctitle (const char *fmt, ...)
{

	if (!title_buffer || !title_buffer_size) {
		errno = ENOMEM;
		return -1;
	}

	memset (title_buffer, '\0', title_buffer_size);

	ssize_t                         written;

	if (fmt) {
		ssize_t                         written2;
		va_list                         ap;

		written = snprintf (title_buffer, title_buffer_size, "%s: ", title_progname);
		if (written < 0 || (size_t) written >= title_buffer_size)
			return -1;

		va_start (ap, fmt);
		written2 = vsnprintf (title_buffer + written, title_buffer_size - written, fmt, ap);
		va_end (ap);
		if (written2 < 0 || (size_t) written2 >= title_buffer_size - written)
			return -1;
	}
	else {
		written = snprintf (title_buffer, title_buffer_size, "%s", title_progname);
		if (written < 0 || (size_t) written >= title_buffer_size)
			return -1;
	}

	written = strlen (title_buffer);
	memset (title_buffer + written, '\0', title_buffer_size - written);

	return 0;
}
/*
  It has to be _init function, because __attribute__((constructor))
  functions gets called without arguments.
*/
int
lt_init_title (int argc, char *argv[], char *envp[])
{
#if defined(DARWIN) || defined(SOLARIS)
	/* XXX: try to handle these OSes too */
	return 0;
#else
	char                           *begin_of_buffer = 0, *end_of_buffer = 0;
	int                            i;

	for (i = 0; i < argc; ++i) {
		if (!begin_of_buffer)
			begin_of_buffer = argv[i];
		if (!end_of_buffer || end_of_buffer + 1 == argv[i])
			end_of_buffer = argv[i] + strlen (argv[i]);
	}

	for (i = 0; envp[i]; ++i) {
		if (!begin_of_buffer)
			begin_of_buffer = envp[i];
		if (!end_of_buffer || end_of_buffer + 1 == envp[i])
			end_of_buffer = envp[i] + strlen (envp[i]);
	}

	if (!end_of_buffer)
		return 0;

	char                           **new_environ = malloc ((i + 1) * sizeof (envp[0]));

	if (!new_environ)
		return 0;

	for (i = 0; envp[i]; ++i) {
		if (!(new_environ[i] = strdup (envp[i])))
			goto cleanup_enomem;
	}
	new_environ[i] = 0;

	if (program_invocation_name) {
		title_progname_full = strdup (program_invocation_name);

		if (!title_progname_full)
			goto cleanup_enomem;

		char                           *p = strrchr (title_progname_full, '/');

		if (p)
			title_progname = p + 1;
		else
			title_progname = title_progname_full;

		program_invocation_name = title_progname_full;
		program_invocation_short_name = title_progname;
	}

	environ = new_environ;
	title_buffer = begin_of_buffer;
	title_buffer_size = end_of_buffer - begin_of_buffer;

	return 0;

  cleanup_enomem:
	for (--i; i >= 0; --i) {
		free (new_environ[i]);
	}
	free (new_environ);
	return 0;
#endif
}
#endif


ssize_t
lt_read (int fd, void *buf, size_t buflen)
{
	ssize_t r;

	for (;;) {
		r = read (fd, buf, buflen);
		if (r == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			return -1;
		}
		break;
	}

	return r;
}

ssize_t
lt_write (int fd, const void *buf, size_t buflen)
{
	ssize_t r;

	for (;;) {
		r = write (fd, buf, buflen);
		if (r == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			return -1;
		}
		break;
	}

	return r;
}

/* Fix broken libnuma */
#ifdef HAVE_NUMA_H
struct bitmask **node_cpu_mask_v2;

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define BYTES_PER_LONG (sizeof(long))
#define CPU_BYTES(x) (round_up(x, BITS_PER_LONG)/8)
#define CPU_LONGS(x) (CPU_BYTES(x) / sizeof(long))

#define test_bit(i,p)  ((p)[(i) / BITS_PER_LONG] &   (1UL << ((i)%BITS_PER_LONG)))
#define set_bit(i,p)   ((p)[(i) / BITS_PER_LONG] |=  (1UL << ((i)%BITS_PER_LONG)))
#define clear_bit(i,p) ((p)[(i) / BITS_PER_LONG] &= ~(1UL << ((i)%BITS_PER_LONG)))
#define array_len(x) (sizeof(x)/sizeof(*(x)))

#define round_up(x,y) (((x) + (y) - 1) & ~((y)-1))

static void
fixed_init_node_cpu_mask_v2 (void)
{
	int nnodes = 17;
	node_cpu_mask_v2 = calloc (nnodes, sizeof(struct bitmask *));
}

int
fixed_numa_parse_bitmap_v2 (char *line, struct bitmask *mask)
{
	int i, ncpus;
	char *p = strchr (line, '\n');
	if (!p)
		return -1;
	ncpus = mask->size;

	for (i = 0; p > line; i++) {
		char *oldp, *endp;
		oldp = p;
		if (*p == ',')
			--p;
		while (p > line && *p != ',')
			--p;
		/* Eat two 32bit fields at a time to get longs */
		if (p > line && sizeof(unsigned long) == 8) {
			oldp--;
			memmove (p, p + 1, oldp - p + 1);
			while (p > line && *p != ',')
				--p;
		}
		if (*p == ',')
			p++;
		if (i >= CPU_LONGS (ncpus))
			return -1;
		mask->maskp[i] = strtoul (p, &endp, 16);
		if (endp != oldp)
			return -1;
		p--;
	}
	return 0;
}


/*
 * test whether a node has cpus
 */
/* This would be better with some locking, but I don't want to make libnuma
 dependent on pthreads right now. The races are relatively harmless. */
/*
 * deliver a bitmask of cpus representing the cpus on a given node
 */
static int
fixed_numa_node_to_cpus_v2 (int node, struct bitmask *buffer)
{
	int err = 0;
	int nnodes = numa_max_node ();
	char fn[64], *line = NULL;
	FILE *f;
	size_t len = 0;
	struct bitmask *mask;

	if (!node_cpu_mask_v2)
		fixed_init_node_cpu_mask_v2 ();

	if (node > nnodes) {
		errno = ERANGE;
		return -1;
	}
	numa_bitmask_clearall (buffer);

	if (node_cpu_mask_v2[node]) {
		/* have already constructed a mask for this node */
		if (buffer->size < node_cpu_mask_v2[node]->size) {
			numa_error ("map size mismatch; abort\n");
			return -1;
		}
		copy_bitmask_to_bitmask (node_cpu_mask_v2[node], buffer);
		return 0;
	}

	/* need a new mask for this node */
	mask = numa_allocate_cpumask ();

	/* this is a kernel cpumask_t (see node_read_cpumap()) */
	sprintf (fn, "/sys/devices/system/node/node%d/cpumap", node);
	f = fopen (fn, "r");
	if (!f || getdelim (&line, &len, '\n', f) < 1) {
		err = -1;
	}
	if (f)
		fclose (f);

	if (line && (fixed_numa_parse_bitmap_v2 (line, mask) < 0)) {
		numa_bitmask_setall (mask);
		err = -1;
	}

	free (line);
	copy_bitmask_to_bitmask (mask, buffer);

	/* slightly racy, see above */
	/* save the mask we created */
	if (node_cpu_mask_v2[node]) {
		/* how could this be? */
		if (mask != buffer)
			numa_bitmask_free (mask);
	}
	else {
		node_cpu_mask_v2[node] = mask;
	}
	return err;
}


/* report the node of the specified cpu */
int
fixed_numa_node_of_cpu (int cpu)
{
	struct bitmask *bmp;
	int ncpus, nnodes, node, ret;

	ncpus = 4096;
	if (cpu > ncpus) {
		errno = EINVAL;
		return -1;
	}
	bmp = numa_bitmask_alloc (ncpus);
	nnodes = numa_max_node ();
	for (node = 0; node <= nnodes; node++) {
		fixed_numa_node_to_cpus_v2 (node, bmp);
		if (numa_bitmask_isbitset (bmp, cpu)) {
			ret = node;
			goto end;
		}
	}
	ret = -1;
	errno = EINVAL;
	end: numa_bitmask_free (bmp);
	return ret;
}
#endif


/**
 * Bind this process to a specific core
 * @param corenum number of core
 */
void
bind_to_core (int corenum, int numa_node)
{
#ifdef HAVE_SCHED_SETAFFINITY
	/* Bind to a single core */
	cpu_set_t mask;
	if (corenum != -1) {
		CPU_ZERO (&mask);
		CPU_SET (corenum, &mask);
		sched_setaffinity (0, sizeof(cpu_set_t), &mask);
	}
#elif defined(HAVE_CPUSET_SETAFFINITY)
	cpuset_t mask;
	if (corenum != -1) {
		CPU_ZERO (&mask);
		CPU_SET (corenum, &mask);
		cpuset_setaffinity (CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof (mask), &mask);
	}
#endif
#ifdef HAVE_NUMA_H
	int node;
	if (numa_available () != -1) {
		if (numa_node == -1 && corenum != -1) {
			node = fixed_numa_node_of_cpu (corenum);
		}
		else {
			node = numa_node;
		}
		if (node != -1) {
			numa_set_preferred (node);
			ltproto_bind_numa (node);
		}
	}
#endif
}
