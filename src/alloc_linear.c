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

/**
 * @file alloc_linear.c
 *
 * Naive apporoach to shared memory allocator: we alloc shmem pieces and push them
 * to tailq. If reader is slower than writer, this allocator won't likely work
 */

/* How much pages are in an arena by default */
const unsigned int default_arena_pages = 512;
/* How much elements can we allow in reused chunks queue */
const unsigned int reused_queue_max = 20;

int linear_init_func (struct lt_allocator_ctx **ctx, uint64_t init_seq);
void * linear_alloc_func (struct lt_allocator_ctx *ctx, size_t size);
struct lt_alloc_tag * linear_gettag_func (struct lt_allocator_ctx *ctx, void *ptr);
void * linear_attachtag_func (struct lt_allocator_ctx *ctx, struct lt_alloc_tag *tag);
void linear_free_func (struct lt_allocator_ctx *ctx, void *addr, size_t size);

struct alloc_chunk;

struct alloc_arena {
	struct lt_alloc_tag tag;			// Tag of shared arena
	u_char *begin;						// Begin of arena
	size_t len;							// Length of arena
	u_char *pos;						// Position of free space pointer
	u_char *last;						// Last byte of arena
	TAILQ_HEAD (, alloc_chunk) chunks;	// Allocated chunks
	TAILQ_ENTRY (alloc_arena) link;
};

struct alloc_chunk {
	u_char *base;						// Base address of chunk
	size_t len;							// Length of chunk
	struct alloc_arena *arena;			// Arena of chunk
	TAILQ_ENTRY (alloc_chunk) link;
	LIST_ENTRY (alloc_chunk) rlink;
};

struct lt_linear_allocator_ctx {
	size_t len;
	size_t bytes_allocated;
	uint64_t seq;
	struct ltproto_ctx *lib_ctx;		// Parent ctx
	TAILQ_HEAD (, alloc_arena) arenas;	// Shared arenas
	LIST_HEAD (, alloc_chunk) free_chunks;	// Free chunks that can be reused
	unsigned int free_chunks_cnt;		// Amount of chunks if free chunk queue
};


allocator_t linear_allocator = {
	.name = "linear allocator",
	.priority = 0,
	.allocator_init_func = linear_init_func,
	.allocator_alloc_func = linear_alloc_func,
	.allocator_gettag_func = linear_gettag_func,
	.allocator_attachtag_func = linear_attachtag_func,
	.allocator_free_func = linear_free_func
};

/**
 * Create and attech shared memory arena
 * @param ctx context
 * @param size size of arena to be created
 * @return zero in case of success or -1 in case of error
 */
static int
create_shared_arena (struct lt_linear_allocator_ctx *ctx, size_t size)
{
	char arena_name[64];
	int fd, flags, serrno;
	struct alloc_arena *new;
	void *map;

	snprintf (arena_name, sizeof (arena_name), "/lin_%lu", (long unsigned)++ctx->seq);
	fd = shm_open (arena_name, O_RDWR | O_CREAT | O_EXCL, 00600);
	if (fd == -1) {
		return -1;
	}
	if (ftruncate (fd, size) == -1) {
		serrno = errno;
		shm_unlink (arena_name);
		close (fd);
		errno = serrno;
		return -1;
	}
#ifdef HAVE_HUGETLB
	flags = MAP_SHARED | MAP_HUGETLB;
#else
	flags = MAP_SHARED;
#endif
	if ((map = mmap (NULL, size, PROT_READ | PROT_WRITE, flags, fd, 0)) == MAP_FAILED) {
		serrno = errno;
		shm_unlink (arena_name);
		close (fd);
		errno = serrno;
		return -1;
	}
	close (fd);
	new = calloc (1, sizeof (struct alloc_arena));
	if (new == NULL) {
		serrno = errno;
		munmap (map, size);
		shm_unlink (arena_name);
		errno = serrno;
		return -1;
	}
	new->begin = map;
	new->last = new->begin + size;
	new->len = size;
	new->pos = new->begin;
	new->tag.seq = ctx->seq;
	TAILQ_INSERT_TAIL(&ctx->arenas, new, link);

	return 0;
}

/**
 * Find or create new alloc chunk
 * @param ctx context
 * @param size size of chunk to be created
 * @return new or reused chunk or NULL if all arenas are full
 */
static struct alloc_chunk*
find_free_chunk (struct lt_linear_allocator_ctx *ctx, size_t size)
{
	struct alloc_chunk *cur, *tmp = NULL;
	size_t minimal_size = SIZE_MAX;

	/* Initially search for chunk that can be reused */
	LIST_FOREACH (cur, &ctx->free_chunks, rlink) {
		if (cur->len >= size && cur->len < minimal_size) {
			tmp = cur;
			minimal_size = cur->len;
			if (minimal_size == cur->len) {
				break;
			}
		}
	}
	if (tmp != NULL) {
		/* We just reuse chunk without arena modifications */
		LIST_REMOVE (tmp, rlink);
		ctx->free_chunks_cnt --;
		return tmp;
	}

	/* We need to find free chunk in some arena */


	return NULL;
}

int
linear_init_func (struct lt_allocator_ctx **ctx, uint64_t init_seq)
{
	struct lt_linear_allocator_ctx *new;

	new = calloc (1, sizeof (struct lt_linear_allocator_ctx));
	assert (new != NULL);
	new->len = sizeof (struct lt_linear_allocator_ctx);
	new->seq = init_seq;

	if (create_shared_arena (new, getpagesize () * default_arena_pages) == -1) {
		/* XXX: handle freeing of objects */
		return -1;
	}

	*ctx = (struct lt_allocator_ctx *)new;

	return 0;
}

void *
linear_alloc_func (struct lt_allocator_ctx *ctx, size_t size)
{
	/* TODO: */
	return NULL;
}

struct lt_alloc_tag *
linear_gettag_func (struct lt_allocator_ctx *ctx, void *ptr)
{
	/* TODO: */
	return NULL;
}
void *
linear_attachtag_func (struct lt_allocator_ctx *ctx, struct lt_alloc_tag *tag)
{
	/* TODO: */
	return NULL;
}

void
linear_free_func (struct lt_allocator_ctx *ctx, void *addr, size_t size)
{
	/* TODO: */
}
