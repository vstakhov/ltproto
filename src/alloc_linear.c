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
#define REUSED_QUEUE_MAX 20

int linear_init_func (struct lt_allocator_ctx **ctx, uint64_t init_seq);
void * linear_alloc_func (struct lt_allocator_ctx *ctx, size_t size);
struct lt_alloc_tag * linear_gettag_func (struct lt_allocator_ctx *ctx, void *ptr);
void * linear_attachtag_func (struct lt_allocator_ctx *ctx, struct lt_alloc_tag *tag);
void linear_free_func (struct lt_allocator_ctx *ctx, void *addr, size_t size);

struct alloc_chunk;

struct alloc_arena {
	struct lt_alloc_tag tag;			// Tag of shared arena
	uintptr_t begin;						// Begin of arena
	size_t len;							// Length of arena
	uintptr_t pos;						// Position of free space pointer
	uintptr_t last;						// Last byte of arena
	size_t free;						// Free space
	TAILQ_HEAD (chunk_head, alloc_chunk) chunks;	// Allocated chunks
	TAILQ_ENTRY (alloc_arena) link;
};

struct alloc_chunk {
	uintptr_t base;						// Base address of chunk
	size_t len;							// Length of chunk
	TAILQ_ENTRY (alloc_chunk) link;
};

struct lt_linear_allocator_ctx {
	size_t len;
	size_t bytes_allocated;
	uint64_t seq;
	struct ltproto_ctx *lib_ctx;		// Parent ctx
	TAILQ_HEAD (ar_head, alloc_arena) arenas;	// Shared arenas
	struct {
		struct alloc_chunk *chunk;
		struct alloc_arena *arena;
	} free_chunks [REUSED_QUEUE_MAX];	// Free chunks that can be reused
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
 * Create and attach shared memory arena
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
	new->begin = (uintptr_t)map;
	new->last = new->begin + size;
	new->len = size;
	new->pos = align_ptr_platform (new->begin);
	new->tag.seq = ctx->seq;
	new->free = new->last - new->pos;
	TAILQ_INIT (&new->chunks);
	TAILQ_INSERT_TAIL (&ctx->arenas, new, link);

	return 0;
}


static inline struct alloc_chunk*
create_chunk (uintptr_t begin, size_t size)
{
	struct alloc_chunk *chunk;

	chunk = malloc (sizeof (struct alloc_chunk));
	assert (chunk != NULL);
	chunk->base = begin;
	chunk->len = size;

	return chunk;
}

/**
 * Search for free chunk in a specified arena
 * @param ctx alloc context
 * @param ar arena to search
 * @param size size of chunk
 * @return new alloc chunk
 */
static struct alloc_chunk*
arena_find_free_chunk (struct lt_linear_allocator_ctx *ctx, struct alloc_arena *ar, size_t size)
{
	struct alloc_chunk *chunk, *cur, *next;
	uintptr_t start, end;

	start = ar->pos;
	end = ar->last;

	if (end - start >= size) {
		/* Trivial case */
		chunk = create_chunk (start, size);
		start = start + size;
		start = align_ptr_platform (start);
	}
	else if (!TAILQ_EMPTY (&ar->chunks)){
		/* Check the space at the beginning */
		start = align_ptr_platform (ar->begin);
		end = TAILQ_FIRST (&ar->chunks)->base;
		if (end - start >= size) {
			chunk = create_chunk (start, size);
			start = start + size;
			start = align_ptr_platform (start);
		}
		else {
			TAILQ_FOREACH (cur, &ar->chunks, link) {
				next = TAILQ_NEXT (cur, link);
				if (next) {
					/* Check for a hole between chunks */
					start = cur->base + cur->len;
					start = align_ptr_platform (start);
					end = next->base;
				}
				else {
					/* Last chunk */
					start = cur->base + cur->len;
					start = align_ptr_platform (start);
					end = ar->begin + ar->len;
				}
				if (end - start >= size) {
					chunk = create_chunk (start, size);
					start = start + size;
					start = align_ptr_platform (start);
					break;
				}
			}
		}
	}
	else {
		/* Illegal case as zone is free, but has not enough space to alloc data requested */
		assert (0);
	}

	ar->pos = start;
	ar->last = end;
	/* XXX: actually it is not correct approach, as we perform aligning */
	ar->free -= size;
	return chunk;
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
	struct alloc_arena *ar;
	size_t minimal_size = SIZE_MAX;
	unsigned int i;
	int sel = -1;

	/* Initially search for chunk that can be reused */
	for (i = 0; i < ctx->free_chunks_cnt; i ++) {
		cur = ctx->free_chunks[i].chunk;
		if (cur->len >= size && cur->len < minimal_size) {
			sel = i;
			minimal_size = cur->len;
			if (minimal_size == cur->len) {
				break;
			}
		}
	}
	if (sel >= 0) {
		/* We just reuse chunk without arena modifications */
		ctx->free_chunks_cnt --;
		tmp = ctx->free_chunks[i].chunk;
		for (i = sel; i < ctx->free_chunks_cnt; i ++) {
			memcpy (&ctx->free_chunks[i], &ctx->free_chunks[i + 1], sizeof (ctx->free_chunks[0]));
		}

		return tmp;
	}

	/* We need to find free chunk in some arena */
	TAILQ_FOREACH_REVERSE (ar, &ctx->arenas, ar_head, link) {
		if (ar->free >= size) {
			cur = arena_find_free_chunk (ctx, ar, size);
		}
	}

	/* We have no arena with suitable free space */
	return NULL;

}

/**
 * Find chunk that contains specified address
 * @param ctx allocator context
 * @param addr address to find
 * @return desired chunk or NULL
 */
static struct alloc_chunk*
find_chunk_for_addr (struct lt_linear_allocator_ctx *ctx, uintptr_t addr, struct alloc_arena **arena)
{
	struct alloc_arena *ar;
	struct alloc_chunk *cur, *next, *prev;
	unsigned int i;

	/* Initially search address in chunks planned to free */
	for (i = 0; i < ctx->free_chunks_cnt; i ++) {
		cur = ctx->free_chunks[i].chunk;
		next = TAILQ_NEXT (cur, link);
		prev = TAILQ_PREV (cur, chunk_head, link);
		if (next && addr >= next->base && addr <= next->base + next->len) {
			*arena = ctx->free_chunks[i].arena;
			return next;
		}
		if (prev && addr >= prev->base && addr <= prev->base + prev->len) {
			*arena = ctx->free_chunks[i].arena;
			return prev;
		}
		if (addr >= cur->base && addr <= cur->base + cur->len) {
			/* Address is in deleted list, that generally means double free corruption */
			assert (0);
		}
	}

	TAILQ_FOREACH_REVERSE (ar, &ctx->arenas, ar_head, link) {
		if (addr >= ar->begin && addr <= ar->begin + ar->len) {
			goto ar_found;
		}
	}
	/* No arena found */
	return NULL;

ar_found:
	/* XXX: naive and slow algorithm */
	TAILQ_FOREACH (cur, &ar->chunks, link) {
		if (addr >= cur->base && addr <= cur->base + cur->len) {
			*arena = ar;
			return cur;
		}
	}

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

	TAILQ_INIT (&new->arenas);

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
	struct alloc_chunk *chunk;
	struct lt_linear_allocator_ctx *real_ctx = (struct lt_linear_allocator_ctx *)ctx;

	assert (size != 0);

	chunk = find_free_chunk (real_ctx, size);
	if (chunk != NULL) {
		return (void *)chunk->base;
	}

	/* Try to alloc new zone */
	if (create_shared_arena (real_ctx, size + getpagesize () * default_arena_pages) == -1) {
		return NULL;
	}

	chunk = find_free_chunk (real_ctx, size);
	if (chunk != NULL) {
		return (void *)chunk->base;
	}

	/* Should not be reached as we've attached arena at least of required size */
	assert (0);
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
	struct alloc_chunk *chunk, *chunk_exp;
	struct alloc_arena *ar, *ar_exp;
	struct lt_linear_allocator_ctx *real_ctx = (struct lt_linear_allocator_ctx *)ctx;
	unsigned int i, max_free = 0;
	int sel = -1;

	assert (addr != NULL);

	chunk = find_chunk_for_addr (real_ctx, (uintptr_t)addr, &ar);

	assert (chunk != NULL && ar != NULL);

	/* Initially we need to push chunk to a free list */
	if (real_ctx->free_chunks_cnt < REUSED_QUEUE_MAX) {
		real_ctx->free_chunks_cnt ++;
		real_ctx->free_chunks[real_ctx->free_chunks_cnt].chunk = chunk;
		real_ctx->free_chunks[real_ctx->free_chunks_cnt].arena = ar;
		return;
	}
	/* We need to expire some chunks in wait queue */
	for (i = 0; i < real_ctx->free_chunks_cnt; i ++) {
		if (real_ctx->free_chunks[i].arena == ar) {
			/* Prefer chunks from this arena */
			sel = i;
			break;
		}
		/* Otherwise expire chunk from the most free arena */
		if (real_ctx->free_chunks[i].arena->free > max_free) {
			sel = i;
			max_free = real_ctx->free_chunks[i].arena->free;
		}
	}
	assert (sel != -1);

	/* Remove expired element completely */
	ar_exp = real_ctx->free_chunks[sel].arena;
	chunk_exp = real_ctx->free_chunks[sel].chunk;
	TAILQ_REMOVE (&ar_exp->chunks, chunk_exp, link);
	ar_exp->free += chunk_exp->len;
	free (chunk_exp);

	/* Insert element to expire queue */
	real_ctx->free_chunks[sel].chunk = chunk;
	real_ctx->free_chunks[sel].arena = ar;
}
