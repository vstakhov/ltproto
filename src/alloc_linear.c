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
#ifdef HAVE_NUMA_H
# include <numa.h>
#endif

/**
 * @file alloc_linear.c
 *
 * Naive apporoach to shared memory allocator: we alloc shmem pieces and push them
 * to tailq. If reader is slower than writer, this allocator won't likely work
 */

/* How much pages are in an arena by default */
const unsigned int default_arena_pages = 256;
/* How much elements can we allow in reused chunks queue */
#define REUSED_QUEUE_MAX 128

int linear_init_func (struct lt_allocator_ctx **ctx, uint64_t init_seq);
void * linear_alloc_func (struct lt_allocator_ctx *ctx, size_t size, struct lt_alloc_tag *tag);
void * linear_attachtag_func (struct lt_allocator_ctx *ctx, struct lt_alloc_tag *tag);
void linear_free_func (struct lt_allocator_ctx *ctx, void *addr, size_t size);
void linear_destroy_func (struct lt_allocator_ctx *ctx);
void linear_set_numa_func (struct lt_allocator_ctx *ctx, int node);

struct alloc_chunk;

struct alloc_arena {
	struct lt_alloc_tag tag;			// Tag of shared arena
	uintptr_t begin;						// Begin of arena
	size_t len;							// Length of arena
	uintptr_t pos;						// Position of free space pointer
	uintptr_t last;						// Last byte of arena
	size_t free;						// Free space
	struct lt_objcache *chunk_cache;	// Object cache for chunks
	struct alloc_chunk *last_chunk;		// Last chunk created
	TAILQ_HEAD (chunk_head, alloc_chunk) chunks;	// Allocated chunks
	TAILQ_ENTRY (alloc_arena) link;
};

struct foreign_alloc_arena {
	uintptr_t begin;					// Begin of arena
	size_t len;							// Length of arena
	uint64_t seq;
	UT_hash_handle hh;
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
	int numa_node;
	struct ltproto_ctx *lib_ctx;		// Parent ctx
	int use_sysv;						// Use sysV shared memory
	TAILQ_HEAD (ar_head, alloc_arena) arenas;	// Shared arenas
	struct {
		struct alloc_chunk *chunk;
		struct alloc_arena *arena;
		int used;
	} free_chunks [REUSED_QUEUE_MAX];	// Free chunks that can be reused
	struct foreign_alloc_arena *attached_arenas;
	unsigned int free_chunks_cnt;		// Amount of chunks if free chunk queue
	unsigned int last_free;
};


allocator_t linear_allocator = {
	.name = "linear allocator",
	.priority = 1,
	.allocator_init_func = linear_init_func,
	.allocator_alloc_func = linear_alloc_func,
	.allocator_attachtag_func = linear_attachtag_func,
	.allocator_free_func = linear_free_func,
	.allocator_destroy_func = linear_destroy_func,
	.allocator_set_numa_node = linear_set_numa_func
};


/**
 * Create and attach shared memory arena using posix shmem
 * @param ctx context
 * @param size size of arena to be created
 * @return zero in case of success or -1 in case of error
 */
static struct alloc_arena *
create_shared_arena_posix (struct lt_linear_allocator_ctx *ctx, size_t size)
{
	char arena_name[64];
	int fd, flags, serrno;
	struct alloc_arena *new;
	void *map;

	snprintf (arena_name, sizeof (arena_name), "/lin_%lu", (long unsigned)++ctx->seq);
	fd = shm_open (arena_name, O_RDWR | O_CREAT | O_EXCL, 00600);
	if (fd == -1) {
		return NULL;
	}
	if (ftruncate (fd, size) == -1) {
		serrno = errno;
		shm_unlink (arena_name);
		close (fd);
		errno = serrno;
		return NULL;
	}
#ifdef HAVE_HUGETLB
	flags = MAP_SHARED;
#else
	flags = MAP_SHARED;
#endif
	if ((map = mmap (NULL, size, PROT_READ | PROT_WRITE, flags, fd, 0)) == MAP_FAILED) {
		serrno = errno;
		shm_unlink (arena_name);
		close (fd);
		errno = serrno;
		return NULL;
	}
#ifdef HAVE_NUMA_H
	if (ctx->numa_node != -1) {
		numa_tonode_memory (map, size, ctx->numa_node);
	}
#endif
	close (fd);

	new = calloc (1, sizeof (struct alloc_arena));
	if (new == NULL) {
		serrno = errno;
		munmap (map, size);
		shm_unlink (arena_name);
		errno = serrno;
		return NULL;
	}

	new->tag.seq = ctx->seq;
	new->begin = (uintptr_t)map;
	return new;
}

/**
 * Create and attach shared memory arena
 * @param ctx context
 * @param size size of arena to be created
 * @return zero in case of success or -1 in case of error
 */
static struct alloc_arena *
create_shared_arena_sysv (struct lt_linear_allocator_ctx *ctx, size_t size)
{
	int id;
	void *map;
	struct alloc_arena *new;

	id = shmget ((int32_t)ctx->seq++, size, IPC_CREAT | IPC_EXCL | 0600);
	if (id == -1) {
		return NULL;
	}

	map = shmat (id, NULL, 0);
	if (map == (void *)-1) {
		return NULL;
	}
#ifdef HAVE_NUMA_H
	if (ctx->numa_node != -1) {
		numa_tonode_memory (map, size, ctx->numa_node);
	}
#endif

	new = calloc (1, sizeof (struct alloc_arena));
	if (new == NULL) {
		shmdt (map);
	}

	new->tag.seq = id;
	new->begin = (uintptr_t)map;
	return new;
}


/**
 * Create and attach shared memory arena using posix shmem
 * @param ctx context
 * @param size size of arena to be created
 * @return zero in case of success or -1 in case of error
 */
static int
create_shared_arena (struct lt_linear_allocator_ctx *ctx, size_t size)
{
	struct alloc_arena *new;

	if (ctx->use_sysv) {
		new = create_shared_arena_sysv (ctx, size);
	}
	else {
		new = create_shared_arena_posix (ctx, size);
	}
	new->chunk_cache = lt_objcache_create (sizeof (struct alloc_chunk));
	new->last = new->begin + size;
	new->len = size;
	new->pos = align_ptr_platform (new->begin);
	new->free = new->last - new->pos;
	TAILQ_INIT (&new->chunks);
	TAILQ_INSERT_TAIL (&ctx->arenas, new, link);

	return 0;
}

static inline struct alloc_chunk*
create_chunk (uintptr_t begin, size_t size, struct alloc_arena *ar, struct alloc_chunk *pos, int insert_pre)
{
	struct alloc_chunk *chunk;

	chunk = lt_objcache_alloc (ar->chunk_cache);
	assert (chunk != NULL);
	chunk->base = begin;
	chunk->len = size;

	if (insert_pre) {
		if (pos) {
			TAILQ_INSERT_BEFORE (pos, chunk, link);
		}
		else {
			TAILQ_INSERT_HEAD (&ar->chunks, chunk, link);
		}
	}
	else {
		if (pos) {
			TAILQ_INSERT_AFTER (&ar->chunks, pos, chunk, link);
		}
		else {
			TAILQ_INSERT_TAIL (&ar->chunks, chunk, link);
		}
	}
	ar->last_chunk = chunk;

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
	struct alloc_chunk *chunk = NULL, *cur, *next;
	uintptr_t start, end;

	start = ar->pos;
	end = ar->last;

	if (end - start > size) {
		/* Trivial case */
		//printf("hui1: %p -> %p, %zd\n", start, end, size);
		chunk = create_chunk (start, size, ar, ar->last_chunk, 0);
		start = start + size;
		start = align_ptr_platform (start);
	}
	else if (!TAILQ_EMPTY (&ar->chunks)){
		/* Check the space at the beginning */
		start = align_ptr_platform (ar->begin);
		end = TAILQ_FIRST (&ar->chunks)->base;
		if (end - start > size) {
			//printf("hui2: %p -> %p, %zd\n", start, end, size);
			chunk = create_chunk (start, size, ar, TAILQ_FIRST (&ar->chunks), 1);
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
					chunk = create_chunk (start, size, ar, cur, 0);
					start = start + size;
					start = align_ptr_platform (start);
					//printf("hui3: %p -> %p, %zd\n", start, end, size);
					break;
				}
			}
		}
	}
	else {
		/* Zone was free */
		start = align_ptr_platform (ar->begin);
		chunk = create_chunk (start, size, ar, NULL, 0);
		start = start + size;
		start = align_ptr_platform (start);
		end = ar->begin + ar->len;
		ar->free = ar->len;
		//printf("hui4: %p -> %p, %zd\n", start, end, size);
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
find_free_chunk (struct lt_linear_allocator_ctx *ctx, size_t size, struct alloc_arena **par)
{
	struct alloc_chunk *cur, *tmp = NULL;
	struct alloc_arena *ar;
	size_t minimal_size = SIZE_MAX;
	unsigned int i;
	int sel = -1;

	/* Initially search for chunk that can be reused */
	for (i = 0; i < REUSED_QUEUE_MAX; i ++) {
		if (!ctx->free_chunks[i].used) {
			continue;
		}
		cur = ctx->free_chunks[i].chunk;
		if (cur->len >= size && cur->len < minimal_size) {
			sel = i;
			minimal_size = cur->len;
			if (minimal_size == size) {
				break;
			}
		}
	}
	if (sel >= 0) {
		/* We just reuse chunk without arena modifications */
		tmp = ctx->free_chunks[sel].chunk;
		*par = ctx->free_chunks[sel].arena;
		//printf("REUSED CHUNK %p\n", tmp);
		ctx->free_chunks_cnt --;
		ctx->free_chunks[sel].used = 0;
#if 0
		for (i = sel; i < ctx->free_chunks_cnt; i ++) {
			memcpy (&ctx->free_chunks[i], &ctx->free_chunks[i + 1], sizeof (ctx->free_chunks[0]));
		}
		memset (&ctx->free_chunks[i + 1], 0, sizeof (ctx->free_chunks[0]));
#endif
		return tmp;
	}

	/* We need to find free chunk in some arena */
	TAILQ_FOREACH_REVERSE (ar, &ctx->arenas, ar_head, link) {
		if (ar->free >= size) {
			cur = arena_find_free_chunk (ctx, ar, size);
			if (cur) {
				*par = ar;
				return cur;
			}
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
find_chunk_for_addr (struct lt_linear_allocator_ctx *ctx, uintptr_t addr, size_t len, struct alloc_arena **arena)
{
	struct alloc_arena *ar;
	struct alloc_chunk *cur, *next, *prev;
	unsigned int i;

	/* Initially search address in chunks planned to free */
	for (i = 0; i < REUSED_QUEUE_MAX; i ++) {
		if (!ctx->free_chunks[i].used) {
			continue;
		}
		cur = ctx->free_chunks[i].chunk;
		next = TAILQ_NEXT (cur, link);
		prev = TAILQ_PREV (cur, chunk_head, link);

		if (next && next->len == len && addr == next->base) {
			*arena = ctx->free_chunks[i].arena;
			return next;
		}
		if (prev && prev->len == len && addr == prev->base) {
			*arena = ctx->free_chunks[i].arena;
			return prev;
		}
		if (cur->len == len && addr == cur->base) {
			/* Address is in deleted list, that generally means double free corruption */
			//printf ("!! ar: %p, chunk: %p, addr: %p, idx: %d\n", ctx->free_chunks[i].arena, cur, addr, i);
			assert (0);
		}
	}

	TAILQ_FOREACH_REVERSE (ar, &ctx->arenas, ar_head, link) {
		if (addr >= ar->begin && addr < ar->begin + ar->len) {
			goto ar_found;
		}
	}
	/* No arena found */
	return NULL;

ar_found:
	/* XXX: naive and slow algorithm */
	TAILQ_FOREACH (cur, &ar->chunks, link) {
		if (addr == cur->base) {
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
	new->numa_node = -1;

	if (getenv ("LTPROTO_USE_SYSV") != NULL) {
		new->use_sysv = 1;
	}

	TAILQ_INIT (&new->arenas);

	if (create_shared_arena (new, getpagesize () * default_arena_pages) == -1) {
		/* XXX: handle freeing of objects */
		return -1;
	}

	*ctx = (struct lt_allocator_ctx *)new;

	return 0;
}

void *
linear_alloc_func (struct lt_allocator_ctx *ctx, size_t size, struct lt_alloc_tag *tag)
{
	struct alloc_chunk *chunk;
	struct alloc_arena *ar = NULL;
	struct lt_linear_allocator_ctx *real_ctx = (struct lt_linear_allocator_ctx *)ctx;

	assert (size != 0);

	chunk = find_free_chunk (real_ctx, size, &ar);
	if (chunk != NULL && ar != NULL) {
		tag->seq = ar->tag.seq;
		tag->id = chunk->base - ar->begin;
		return (void *)chunk->base;
	}

	/* Try to alloc new zone */
	if (create_shared_arena (real_ctx, size + getpagesize () * default_arena_pages) == -1) {
		return NULL;
	}

	chunk = find_free_chunk (real_ctx, size, &ar);
	if (chunk != NULL) {
		tag->seq = ar->tag.seq;
		tag->id = chunk->base - ar->begin;
		return (void *)chunk->base;
	}

	/* Should not be reached as we've attached arena at least of required size */
	assert (0);
	return NULL;
}

static struct foreign_alloc_arena *
attach_sysv_shmem_tag (struct lt_alloc_tag *tag)
{
	struct foreign_alloc_arena *far;
	void *map;
	struct shmid_ds ds;

	map = shmat ((int32_t)tag->seq, NULL, 0);
	if (map == (void *)-1) {
		return NULL;
	}

	shmctl ((int32_t)tag->seq, IPC_STAT, &ds);

	far = calloc (1, sizeof (struct foreign_alloc_arena));
	if (far == NULL) {
		shmdt (map);
		return NULL;
	}
	far->begin = (uintptr_t)map;
	far->len = ds.shm_segsz;
	far->seq = tag->seq;

	return far;
}

static struct foreign_alloc_arena *
attach_posix_shmem_tag (struct lt_alloc_tag *tag)
{
	char arena_name[64];
	struct stat st;
	void *map;
	int fd;
	struct foreign_alloc_arena *far;

	/* Try to attach zone */
	snprintf (arena_name, sizeof (arena_name), "/lin_%lu", (long unsigned)tag->seq);
	fd = shm_open (arena_name, O_RDWR, 00600);
	if (fd == -1) {
		return NULL;
	}

	if (fstat (fd, &st) == -1) {
		close (fd);
		return NULL;
	}

	if ((map = mmap (NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		close (fd);
		return NULL;
	}
	close (fd);
	far = calloc (1, sizeof (struct foreign_alloc_arena));
	if (far == NULL) {
		munmap (map, st.st_size);
		return NULL;
	}
	far->begin = (uintptr_t)map;
	far->len = st.st_size;
	far->seq = tag->seq;

	return far;
}

void *
linear_attachtag_func (struct lt_allocator_ctx *ctx, struct lt_alloc_tag *tag)
{
	struct foreign_alloc_arena *far;
	struct lt_linear_allocator_ctx *real_ctx = (struct lt_linear_allocator_ctx *)ctx;


	HASH_FIND (hh, real_ctx->attached_arenas, &tag->seq, sizeof(tag->seq), far);

	if (far != NULL) {
		assert (tag->id < far->len);
		return (void *)(far->begin + tag->id);
	}
	else {
		if (real_ctx->use_sysv) {
			far = attach_sysv_shmem_tag (tag);
		}
		else {
			far = attach_posix_shmem_tag (tag);
		}
		HASH_ADD (hh, real_ctx->attached_arenas, seq, sizeof(far->seq), far);

		assert (tag->id < far->len);
		return (void *)(far->begin + tag->id);
	}

	return NULL;
}

void
linear_free_func (struct lt_allocator_ctx *ctx, void *addr, size_t size)
{
	struct alloc_chunk *chunk, *chunk_exp, *tmp;
	struct alloc_arena *ar, *ar_exp;
	struct lt_linear_allocator_ctx *real_ctx = (struct lt_linear_allocator_ctx *)ctx;
	int sel = -1, i;

	assert (addr != NULL);

	chunk = find_chunk_for_addr (real_ctx, (uintptr_t)addr, size, &ar);
	//printf ("ar: %p, chunk: %p, addr: %p\n", ar, chunk, addr);

	assert (chunk != NULL && ar != NULL);

	/* Initially we need to push chunk to a free list */
	if (real_ctx->free_chunks_cnt < REUSED_QUEUE_MAX) {
		for (i = 0; i < REUSED_QUEUE_MAX; i ++) {
			if (!real_ctx->free_chunks[i].used) {
				real_ctx->free_chunks[i].chunk = chunk;
				real_ctx->free_chunks[i].arena = ar;
				real_ctx->free_chunks[i].used = 1;
				real_ctx->free_chunks_cnt ++;
				return;
			}
		}
		assert (0);
	}
	/* We need to expire some chunks in wait queue */

	sel = ++real_ctx->last_free % real_ctx->free_chunks_cnt;

	/* Remove expired element completely */
	ar_exp = real_ctx->free_chunks[sel].arena;
	chunk_exp = real_ctx->free_chunks[sel].chunk;
	TAILQ_REMOVE (&ar_exp->chunks, chunk_exp, link);
	ar_exp->free += chunk_exp->len;
	if ((tmp = TAILQ_PREV (chunk_exp, chunk_head, link)) != NULL) {
		ar_exp->pos = tmp->base + tmp->len;
		ar_exp->pos = align_ptr_platform (ar_exp->pos);
		ar->last_chunk = TAILQ_PREV (chunk_exp, chunk_head, link);
	}
	else {
		/* Already aligned */
		ar_exp->pos = chunk_exp->base;
		ar->last_chunk = NULL;
	}

	if ((tmp = TAILQ_NEXT (chunk_exp, link)) != NULL) {
		ar_exp->last = tmp->base;
	}
	else {
		ar_exp->last = chunk_exp->base + chunk_exp->len;
	}

	lt_objcache_free (ar_exp->chunk_cache, chunk_exp);

	/* Insert element to expire queue */
	//printf("chunk insert: %p, len: %zd, idx: %d\n", chunk, chunk->len, sel);
	real_ctx->free_chunks[sel].chunk = chunk;
	real_ctx->free_chunks[sel].arena = ar;
}


void
linear_destroy_func (struct lt_allocator_ctx *ctx)
{
	struct alloc_arena *ar, *tmp_ar;
	struct foreign_alloc_arena *far, *far_tmp;
	struct lt_linear_allocator_ctx *real_ctx = (struct lt_linear_allocator_ctx *)ctx;
	char arena_name[64];

	/* Free all arenas and chunks */
	TAILQ_FOREACH_SAFE (ar, &real_ctx->arenas, link, tmp_ar) {
		if (real_ctx->use_sysv) {
			shmdt ((void *)ar->begin);
			shmctl (ar->tag.seq, IPC_RMID, NULL);
		}
		else {
			munmap ((void *)ar->begin, ar->len);
			snprintf (arena_name, sizeof (arena_name), "/lin_%lu", (long unsigned)ar->tag.seq);
			shm_unlink (arena_name);
		}
		lt_objcache_destroy (ar->chunk_cache);
		HASH_ITER (hh, real_ctx->attached_arenas, far, far_tmp) {
			if (real_ctx->use_sysv) {
				shmdt ((void *)far->begin);
			}
			else {
				munmap ((void *)far->begin, far->len);
			}
			HASH_DEL (real_ctx->attached_arenas, far);
			free (far);

		}
		free (ar);
	}

	free (ctx);
}

void
linear_set_numa_func (struct lt_allocator_ctx *ctx, int node)
{
	ctx->numa_node = node;
}
