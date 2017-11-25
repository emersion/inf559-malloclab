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

void *block_root = NULL;

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

inline void block_set_size(void *block, size_t size) {
  block_set_tag(block, size, block_allocated(block));
}

inline void *block_from_payload(void *payload) {
  return (char *)payload - BLOCK_TAG_SIZE;
}

void *block_prev_unallocated(void *block) {
  if (!block_allocated(block) || block == block_root) {
    void **ptrs = block_payload(block);
    return ptrs[0];
  }

  void *prev = block_prev(block);
  while (prev != NULL) {
    if (!block_allocated(prev)) {
      return prev;
    }
    prev = block_prev(prev);
  }

  return NULL;
}

void *block_next_unallocated(void *block) {
  if (!block_allocated(block) || block == block_root) {
    void **ptrs = block_payload(block);
    return ptrs[1];
  }

  void *next = block_next(block);
  while (next != NULL) {
    if (!block_allocated(next)) {
      return next;
    }
    next = block_next(next);
  }

  return NULL;
}

void block_set_prev_unallocated(void *block, void *prev) {
  assert(!block_allocated(block));
  assert(!prev || !block_allocated(prev));

  void **ptrs = block_payload(block);
  ptrs[0] = prev;

  if (prev != NULL) {
    void **prev_ptrs = block_payload(prev);
    prev_ptrs[1] = block;
  }
}

void block_set_next_unallocated(void *block, void *next) {
  assert(!block_allocated(block));
  assert(!next || !block_allocated(next));

  void **ptrs = block_payload(block);
  ptrs[1] = next;

  if (next != NULL) {
    void **next_ptrs = block_payload(next);
    next_ptrs[0] = block;
  }
}

void block_set_allocated(void *block) {
  assert(!block_allocated(block));

  void *prev_unallocated = block_prev_unallocated(block);
  void *next_unallocated = block_next_unallocated(block);
  if (prev_unallocated != NULL) {
    block_set_next_unallocated(prev_unallocated, next_unallocated);
  } else if (next_unallocated != NULL) {
    block_set_prev_unallocated(next_unallocated, prev_unallocated);
  }

  block_set_tag(block, block_size(block), 1);
}

void block_set_unallocated(void *block, void *prev, void *next) {
  assert(block_allocated(block));

  block_set_tag(block, block_size(block), 0);
  block_set_prev_unallocated(block, prev);
  block_set_next_unallocated(block, next);

  void **root_ptrs = block_payload(block_root);
  if (root_ptrs[1] == NULL || block < root_ptrs[1]) {
    root_ptrs[1] = block;
  }
  if (root_ptrs[0] == NULL || block > root_ptrs[0]) {
    root_ptrs[0] = block;
  }
}

int mm_init(void) {
  block_root = block_create(2 * sizeof(void *));
  if (block_root == NULL) {
    return -1;
  }

  void **root_payload = block_payload(block_root);
  root_payload[0] = NULL;
  root_payload[1] = NULL;

  return 0;
}

void *mm_malloc(size_t size) {
  if (size == 0) {
    return NULL;
  }

  void *block = block_root;
  while (block != NULL) {
    if (block_payload_size(block) >= size && !block_allocated(block)) {
      block_set_allocated(block);
      return block_payload(block);
    }

    block = block_next_unallocated(block);
  }

  block = block_create(size);
  if (block == NULL) {
    return NULL;
  }

  return block_payload(block);
}

void mm_free(void *payload) {
  if (payload == NULL) {
    return;
  }

  void *block = block_from_payload(payload);
  assert(block_allocated(block));

  void *prev = block_prev(block);
  void *next = block_next(block);

  int prev_allocated = prev && block_allocated(prev);
  int next_allocated = next && block_allocated(next);
  if (prev && !prev_allocated && next && !next_allocated) {
    size_t new_size = block_size(prev) + block_size(block) + block_size(next);
    void *next_unallocated = block_next_unallocated(next);
    block_set_size(prev, new_size);
    block_set_next_unallocated(prev, next_unallocated);
  } else if (prev && !prev_allocated) {
    size_t new_size = block_size(prev) + block_size(block);
    block_set_size(prev, new_size);
  } else if (next && !next_allocated) {
    size_t new_size = block_size(block) + block_size(next);
    void *prev_unallocated = block_prev_unallocated(next);
    void *next_unallocated = block_next_unallocated(next);
    block_set_size(block, new_size);
    block_set_unallocated(block, prev_unallocated, next_unallocated);
  } else {
    void *prev_unallocated = block_prev_unallocated(block);
    void *next_unallocated = block_next_unallocated(block);
    block_set_unallocated(block, prev_unallocated, next_unallocated);
  }
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

    if (old_size + n >= new_size) {
      for (void *b = block_next(old_block); b != NULL && b <= block; b = block_next(b)) {
        block_set_allocated(b);
      }
      size_t new_size = block_size(old_block) + n;
      block_set_size(old_block, new_size);
      return old_payload;
    }

    block = block_next(block);
  }

  void *new_payload = mm_malloc(new_size);
  if (new_payload == NULL) {
    return NULL;
  }
  memcpy(new_payload, old_payload, old_size);
  mm_free(old_payload);
  return new_payload;
}
