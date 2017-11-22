/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "memlib.h"
#include "mm.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
  /* Team name */
  "​👌​👌​",
  /* First member's full name */
  "Simon Ser",
  /* First member's email address */
  "simon.ser@polytechnique.fr",
  /* Second member's full name (leave blank if none) */
  "",
  /* Second member's email address (leave blank if none) */
  "",
};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

#define BLOCK_TAG_SIZE (ALIGN(sizeof(size_t)))
#define BLOCK_TAG_ALLOCATED_MASK ((size_t)1)
#define BLOCK_TAG_SIZE_MASK (~(size_t)1)

inline size_t block_tag(void *block) {
  size_t *header = block;
  return *header;
}

inline size_t block_size(void *block) {
  return block_tag(block) & BLOCK_TAG_SIZE_MASK;
}

inline void block_set_tag(void *block, size_t size, int allocated) {
  size_t tag = size | (size_t)allocated;

  size_t *header = (size_t *)block;
  *header = tag;

  size_t *footer = (size_t *)((char *)block + size - BLOCK_TAG_SIZE);
  *footer = tag;
}

inline size_t block_payload_size(void *block) {
  return block_size(block) - 2*BLOCK_TAG_SIZE;
}

inline int block_allocated(void *block) {
  return block_tag(block) & BLOCK_TAG_ALLOCATED_MASK;
}

inline void *block_payload(void *block) {
  return (char *)block + BLOCK_TAG_SIZE;
}

void *block_next(void *block) {
  void *next = (char *)block + block_size(block);
  if (next > mem_heap_hi()) {
    return NULL;
  }
  return next;
}

void *block_prev(void *block) {
  if (block <= mem_heap_lo()) {
    return NULL;
  }

  size_t *prev_footer = (size_t *)((char *)block - BLOCK_TAG_SIZE);
  size_t prev_size = *prev_footer & BLOCK_TAG_SIZE_MASK;
  void *prev = (char *)block - prev_size;
  if (prev < mem_heap_lo()) {
    return NULL;
  }
  return prev;
}

void *block_create(size_t payload_size) {
  int size = ALIGN(payload_size + 2*BLOCK_TAG_SIZE);
  void *block = mem_sbrk(size);
  if (block == (void *)-1) {
    return NULL;
  }

  block_set_tag(block, size, 1);
  return block;
}

void *block_from_payload(void *payload) {
  return (char *)payload - BLOCK_TAG_SIZE;
}

inline void block_set_allocated(void *block, int allocated) {
  block_set_tag(block, block_size(block), allocated);
}

int mm_init(void) {
  void *init_block = block_create(0);
  if (init_block == NULL) {
    return -1;
  }
  return 0;
}

void *mm_malloc(size_t size) {
  if (size == 0) {
    return NULL;
  }

  void *block = mem_heap_lo();
  while (block != NULL) {
    if (block_payload_size(block) >= size && !block_allocated(block)) {
      block_set_allocated(block, 1);
      return block_payload(block);
    }

    block = block_next(block);
  }

  block = block_create(size);
  if (block == NULL) {
    return NULL;
  }

  return block_payload(block);
}

#define COALESCE 1

void mm_free(void *payload) {
  if (payload == NULL) {
    return;
  }

  void *block = block_from_payload(payload);
#if COALESCE
  void *prev = block_prev(block);
  void *next = block_next(block);

  int prev_allocated = prev && block_allocated(prev);
  int next_allocated = next && block_allocated(next);
  if (prev && !prev_allocated && next && !next_allocated) {
    size_t new_size = block_size(prev) + block_size(block) + block_size(next);
    block_set_tag(prev, new_size, 0);
  } else if (prev && !prev_allocated) {
    size_t new_size = block_size(prev) + block_size(block);
    block_set_tag(prev, new_size, 0);
  } else if (next && !next_allocated) {
    size_t new_size = block_size(block) + block_size(next);
    block_set_tag(block, new_size, 0);
  } else {
    block_set_allocated(block, 0);
  }
#else
  block_set_allocated(block, 0);
#endif
}

void *mm_realloc(void *payload, size_t size) {
  if (payload == NULL) {
    return mm_malloc(size);
  }
  if (size == 0) {
    mm_free(payload);
    return NULL;
  }

  void *old_payload = payload;
  void *old_block = block_from_payload(old_payload);

  size_t old_size = block_payload_size(old_block);
  size_t new_size = size;

  if (old_size >= new_size) {
    // TODO: shrink old block size, add new free block?
    return old_payload;
  }

  // Find if we can use next blocks without copying memory
  size_t n = 0;
  void *block = block_next(old_block);
  while (block != NULL && !block_allocated(block)) {
    n += block_size(block);
    block = block_next(block);

    if (old_size + n >= new_size) {
      size_t new_size = block_size(old_block) + n;
      block_set_tag(old_block, new_size, 1);
      return old_payload;
    }
  }

  void *new_payload = mm_malloc(new_size);
  if (new_payload == NULL) {
    return NULL;
  }
  memcpy(new_payload, old_payload, old_size);
  mm_free(old_payload);
  return new_payload;
}
