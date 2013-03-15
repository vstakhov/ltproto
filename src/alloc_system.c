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
 * @file alloc_system.c
 *
 * System malloc allocator, for testing purposes only
 */

int system_init_func (struct lt_allocator_ctx **ctx, uint64_t init_seq);
void * system_alloc_func (struct lt_allocator_ctx *ctx, size_t size);
struct lt_alloc_tag * system_gettag_func (struct lt_allocator_ctx *ctx, void *ptr);
void * system_attachtag_func (struct lt_allocator_ctx *ctx, struct lt_alloc_tag *tag);
void system_free_func (struct lt_allocator_ctx *ctx, void *addr, size_t size);
void system_destroy_func (struct lt_allocator_ctx *ctx);


allocator_t system_allocator = {
	.name = "system allocator",
	.priority = 0,
	.allocator_init_func = system_init_func,
	.allocator_alloc_func = system_alloc_func,
	.allocator_gettag_func = system_gettag_func,
	.allocator_attachtag_func = system_attachtag_func,
	.allocator_free_func = system_free_func,
	.allocator_destroy_func = system_destroy_func
};

int
system_init_func (struct lt_allocator_ctx **ctx, uint64_t init_seq)
{
	*ctx = NULL;
	return 0;
}

void *
system_alloc_func (struct lt_allocator_ctx *ctx, size_t size)
{
	return malloc (size);
}

struct lt_alloc_tag *
system_gettag_func (struct lt_allocator_ctx *ctx, void *ptr)
{
	return NULL;
}

void *
system_attachtag_func (struct lt_allocator_ctx *ctx, struct lt_alloc_tag *tag)
{
	return NULL;
}

void
system_free_func (struct lt_allocator_ctx *ctx, void *addr, size_t size)
{
	free (addr);
}

void
system_destroy_func (struct lt_allocator_ctx *ctx)
{
	return;
}
