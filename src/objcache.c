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
#include <assert.h>

#define BITSPERBYTE	(8*sizeof (char))
#define NBYTES(nbits)	(((nbits) + BITSPERBYTE - 1) / BITSPERBYTE)

struct lt_objcache_page {
	struct lt_objcache_page *next;
	u_int data_offset;
	u_int max_elts;
	u_int cur_elts;
	u_char data[1];
};

struct lt_objcache {
	size_t elt_size;
	size_t page_size;
	struct lt_objcache_page *first_page;
	struct lt_objcache_page *cur_page;
};

/**
 * Allocate new page for objcache
 * @param pagesize page size for object cache
 * @param elt_size element size for object cache
 * @return
 */
static struct lt_objcache_page*
lt_objcache_newpage (size_t page_size, size_t elt_size)
{
	struct lt_objcache_page *new;
	size_t nelts, bmap_len;
	void *ptr;

	ptr = mmap (NULL, page_size, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	assert (ptr != MAP_FAILED);
	new = (struct lt_objcache_page *)ptr;
	new->next = NULL;

	/* Set empty bitmap */
	nelts = ceil ((page_size - sizeof (struct lt_objcache_page)) / (double)elt_size);
	bmap_len = NBYTES(nelts);
	nelts -= ceil ((double)bmap_len / (double)elt_size);
	new->data_offset = bmap_len;
	new->cur_elts = 0;
	new->max_elts = nelts;
	memset (new->data, 0, bmap_len);

	return new;
}

/**
 * Allocate element in page
 * @param page_size size of page
 * @param elt_size size of element
 * @param page page object
 */
static void*
lt_objcache_alloc_page (size_t page_size, size_t elt_size, struct lt_objcache_page *page)
{
	u_char map_byte;
	u_int i, j;
	int cur_offset = -1;

	assert (page->cur_elts < page->max_elts);


	for (i = 0; i < page->max_elts / NBBY && cur_offset == -1; i ++) {
		map_byte = page->data[i];
		if ((map_byte & 0xff) == 0xff) {
			/* Full byte */
			continue;
		}
		for (j = 0; j < NBBY; j ++) {
			if ((map_byte & 0x1) == 0) {
				cur_offset = i * NBBY + j;
				break;
			}
			map_byte >>= 1;
		}
	}

	assert (cur_offset != -1);
	setbit (page->data, cur_offset);
	page->cur_elts ++;
	return page->data + page->data_offset + cur_offset * elt_size;
}

/**
 * Removes element from a page
 * @param elt_size size of element
 * @param page page object
 * @param addr address to clear
 */
static void
lt_objcache_free_page (size_t elt_size, struct lt_objcache_page *page, void *addr)
{
	u_int nelt;

	nelt = ((u_char*)addr - (page->data + page->data_offset)) / elt_size;
	clrbit (page->data, nelt);
	page->cur_elts --;
}

/**
 * Create new object cache
 * @param elt_size size of elements in this cache
 * @return new object cache
 */
struct lt_objcache*
lt_objcache_create (size_t elt_size)
{
	struct lt_objcache *new;

	new = calloc (1, sizeof (struct lt_objcache));
	assert (new != NULL);

	new->elt_size = elt_size;
	new->page_size = 4 * getpagesize ();
	assert (new->page_size > elt_size + sizeof (struct lt_objcache_page) + sizeof (void *));

	new->first_page = lt_objcache_newpage (new->page_size, elt_size);
	new->cur_page = new->first_page;

	return new;
}

/**
 * Allocate element of elt_size form cache
 * @param cache cache object
 */
void*
lt_objcache_alloc (struct lt_objcache *cache)
{
	struct lt_objcache_page *npage, *cpage;

	if (cache->cur_page->cur_elts == cache->cur_page->max_elts) {
		/* Page is full */
		cpage = cache->cur_page->next;
		while (cpage != NULL) {
			if (cpage->cur_elts < cpage->max_elts) {
				cache->cur_page = cpage;
				break;
			}
			cache->cur_page = cpage;
			cpage = cpage->next;
		}
		if (cpage == NULL) {
			npage = lt_objcache_newpage (cache->page_size, cache->elt_size);
			cache->cur_page->next = npage;
			cache->cur_page = npage;
		}
	}

	return lt_objcache_alloc_page (cache->page_size, cache->elt_size, cache->cur_page);
}

/**
 * Allocate element of elt_size form cache and zero memory
 * @param cache cache object
 */
void*
lt_objcache_alloc0 (struct lt_objcache *cache)
{
	void *mem;

	mem = lt_objcache_alloc (cache);
	memset (mem, 0, cache->elt_size);

	return mem;
}

#define IS_ADDR_IN_PAGE(page, pagelen, addr)								\
	(u_char *)(addr) >= (page)->data + (page)->data_offset &&				\
	(u_char *)(addr) < (u_char *)(page) + (uintptr_t)(pagelen) ?			\
	1 : 0
/**
 * Free element from cache
 * @param cache cache object
 * @param addr address to free
 */
void
lt_objcache_free (struct lt_objcache *cache, void *addr)
{
	struct lt_objcache_page *page;

	if (IS_ADDR_IN_PAGE (cache->cur_page, cache->page_size, addr)) {
		page = cache->cur_page;
	}
	else {
		page = cache->first_page;
		while (page) {
			if (IS_ADDR_IN_PAGE (page, cache->page_size, addr)) {
				cache->cur_page = page;
				break;
			}
			page = page->next;
		}
	}
	assert (page != NULL);

	lt_objcache_free_page (cache->elt_size, page, addr);
}

/**
 * Destroy object cache and all associated objects
 * @param cache
 */
void
lt_objcache_destroy (struct lt_objcache *cache)
{
	struct lt_objcache_page *page, *tmp;

	page = cache->first_page;
	while (page) {
		tmp = page;
		page = page->next;
		munmap (tmp, cache->page_size);
	}

	free (cache);
}
