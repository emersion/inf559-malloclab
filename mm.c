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

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// TODO: header too big (8 bytes)

#define BLOCK_HEADER_SIZE_MASK (~(size_t)1)

inline size_t *block_header(void *block) {
  return block;
}

inline size_t block_size(void *block) {
  size_t *header = block_header(block);
  return *header & BLOCK_HEADER_SIZE_MASK;
}

inline size_t block_payload_size(void *block) {
  size_t size = block_size(block);
  return size - SIZE_T_SIZE;
}

inline int block_allocated(void *block) {
  size_t *header = block_header(block);
  return *header & 1;
}

inline void *block_payload(void *block) {
  return (char *)block + SIZE_T_SIZE;
}

inline void *block_next(void *block) {
  return (char *)block + block_size(block);
}

inline void block_init(void *block, size_t size, int allocated) {
  size_t *header = block_header(block);
  *header = size | (size_t)allocated;
}

void *block_create(size_t payload_size) {
  int size = ALIGN(payload_size + SIZE_T_SIZE);
  void *block = mem_sbrk(size);
  if (block == (void *)-1) {
    return NULL;
  }

  block_init(block, size, 1);
  return block;
}

void *block_from_payload(void *payload) {
  return (char *)payload - SIZE_T_SIZE;
}

inline void block_set_allocated(void *block, int allocated) {
  size_t *header = block_header(block);
  *header = block_size(block) | (size_t)allocated;
}

int mm_init(void) {
  return 0;
}

void *mm_malloc(size_t size) {
  void *block = mem_heap_lo();
  void *end = mem_heap_hi();
  while (block < end) {
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

void mm_free(void *payload) {
  if (payload == NULL) {
    return;
  }
  block_set_allocated(block_from_payload(payload), 0);
}

void *mm_realloc(void *ptr, size_t size) {
  void *oldptr = ptr;
  void *newptr;
  size_t copySize;

  newptr = mm_malloc(size);
  if (newptr == NULL) {
    return NULL;
  }
  copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
  if (size < copySize) {
    copySize = size;
  }
  memcpy(newptr, oldptr, copySize);
  mm_free(oldptr);
  return newptr;
}
