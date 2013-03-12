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
int linear_init_func (struct lt_allocator_ctx **ctx, uint64_t init_seq);
void * linear_alloc_func (struct lt_allocator_ctx *ctx, size_t size);
struct lt_alloc_tag * linear_gettag_func (struct lt_allocator_ctx *ctx, void *ptr);
void * linear_attachtag_func (struct lt_allocator_ctx *ctx, struct lt_alloc_tag *tag);
void linear_free_func (struct lt_allocator_ctx *ctx, void *addr, size_t size);


struct lt_linear_allocator_ctx {
	size_t len;
	size_t bytes_allocated;
	uint64_t seq;
	struct ltproto_ctx *lib_ctx;	// Parent ctx
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

int
linear_init_func (struct lt_allocator_ctx **ctx, uint64_t init_seq)
{
	struct lt_linear_allocator_ctx *new;

	new = calloc (1, sizeof (struct lt_linear_allocator_ctx));
	assert (new != NULL);
	new->len = sizeof (struct lt_linear_allocator_ctx);
	new->seq = init_seq;

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
