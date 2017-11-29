/*
 * A simple memory allocator with a segregated LIFO explicit free list.
 *
 * Blocks are grouped by classes of sizes. There is one doubly-linked list per
 * class that contains all unallocated blocks in this class.
 *
 * Structure of blocks:
 *
 *   +---------------+----------------+---------------+
 *   | size_t header | void **payload | size_t footer |
 *   +---------------+----------------+---------------+
 *
 * The header and footer contain both the block's tag.
 *
 * The tag contains the size of the whole block. Since blocks sizes are aligned,
 * the least significant bit is always 0. It's used as a flag which tells
 * whether the block is allocated or not.
 *
 * Structure of the payload of unallocated blocks:
 *
 *   +------------+------------+
 *   | void *prev | void *next |
 *   +------------+------------+
 *
 * `prev` is a pointer to the previous unallocated block, `next` is a pointer to
 * the next one.
 *
 * The very first block of the heap is allocated on initialization and is called
 * the root block. Structure of the root block:
 *
 *   +---------------+---------------+---------------+---------------+------
 *   | void *prev[0] | void *next[0] | void *prev[1] | void *next[1] | ...
 *   +---------------+---------------+---------------+---------------+------
 *
 * Its payload contains one head of free list per class. The `prev` field points
 * to the last unallocated block and the `next` field points to the first one.
 *
 * The API is split into two groups of functions:
 * - `block_*` functions abstract blocks. They generally take the block they
 *   operate on as the first argument. Functions marked as `static` are private
 *   and shouldn't be used by other functions.
 * - `mm_*` functions implement the memory allocator.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "memlib.h"
#include "mm.h"

team_t team = {
  .teamname = "​👌​👌​",
  .name1 = "emersion",
  .id1 = "emersion@localhost",
  .name2 = "",
  .id2 = "",
};

// Single word (4) or double word (8) alignment
#define ALIGNMENT 8

// Rounds up to the nearest multiple of ALIGNMENT
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

// Size of a whole block
#define BLOCK_TAG_SIZE (ALIGN(sizeof(size_t)))
// Tag mask to check if a block is allocated
#define BLOCK_TAG_ALLOCATED_MASK ((size_t)1)
// Tag mask to get a block's size
#define BLOCK_TAG_SIZE_MASK (~(size_t)1)
// Minimum payload size (2 pointers for the free list)
#define BLOCK_MIN_PAYLOAD_SIZE (2 * sizeof(void *))

// Indices for unallocated blocks pointers
#define BLOCK_UNALLOCATED_PREV 0
#define BLOCK_UNALLOCATED_NEXT 1

// List of all classes. Class i contains blocks whose payload sizes are at least
// `block_classes[i]` bytes.
const size_t block_classes[] = {2048, 128, 0};
// Number of block classes
#define BLOCK_CLASSES_NBR (sizeof(block_classes)/sizeof(*block_classes))

// A pointer to the root block
void *block_root = NULL;

// Returns the block's tag.
static size_t block_tag(void *block) {
  size_t *header = block;
  return *header;
}

// Returns the block size in bytes.
size_t block_size(void *block) {
  return block_tag(block) & BLOCK_TAG_SIZE_MASK;
}

// Returns the block's payload size.
size_t block_payload_size(void *block) {
  return block_size(block) - 2*BLOCK_TAG_SIZE;
}

// Sets a block's tag.
static void block_set_tag(void *block, size_t size, int allocated) {
  size_t tag = size | (size_t)allocated;

  size_t *header = (size_t *)block;
  *header = tag;

  size_t *footer = (size_t *)((char *)block + size - BLOCK_TAG_SIZE);
  *footer = tag;
}

// Checks whether or not a block is currently allocated.
int block_allocated(void *block) {
  return block_tag(block) & BLOCK_TAG_ALLOCATED_MASK;
}

// Returns a pointer to the block's payload.
void *block_payload(void *block) {
  return (char *)block + BLOCK_TAG_SIZE;
}

// Returns the next block in the heap, or NULL if it's the last one.
void *block_next(void *block) {
  void *next = (char *)block + block_size(block);
  if (next > mem_heap_hi()) {
    return NULL;
  }
  return next;
}

// Returns the previous block in the heap, or NULL if it's the first one.
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

// Allocates a new block with the given payload size. The newly created block is
// marked allocated. Blocks cannot be destroyed.
//
// Returns NULL on error.
void *block_create(size_t payload_size) {
  // Make sure we have enough space to store two pointers in unallocated blocks
  // payload for the free list
  if (payload_size < BLOCK_MIN_PAYLOAD_SIZE) {
    payload_size = BLOCK_MIN_PAYLOAD_SIZE;
  }

  int size = ALIGN(payload_size + 2*BLOCK_TAG_SIZE);
  void *block = mem_sbrk(size);
  if (block == (void *)-1) {
    return NULL;
  }

  block_set_tag(block, size, 1);
  return block;
}

// Resizes the block. This function should be used carefully as it doesn't
// updates pointers to previous and next unallocated blocks. Moreover, it's the
// caller's responsibility to ensure the new size doesn't make this block end
// in the middle of another block.
//
// Since this function can change a block class, it can only be called on
// allocated blocks.
void block_set_size(void *block, size_t size) {
  assert(block_allocated(block));
  block_set_tag(block, size, block_allocated(block));
}

// Returns a block from its payload.
void *block_from_payload(void *payload) {
  return (char *)payload - BLOCK_TAG_SIZE;
}

// Returns the class of a block having a payload of `payload_size` bytes.
static size_t class_from_payload_size(size_t payload_size) {
  for (size_t i = 0; i < BLOCK_CLASSES_NBR; ++i) {
    if (payload_size >= block_classes[i]) {
      return i;
    }
  }
  assert(0);
}

// Returns the pair (prev, next) of pointers of the free list. `payload_size` is
// used when `block` is the root block.
static void **block_unallocated_ptrs(void *block, size_t payload_size) {
  void **ptrs = block_payload(block);
  if (block == block_root) {
    return &ptrs[2 * class_from_payload_size(payload_size)];
  }
  return ptrs;
}

// Returns the first unallocated block having a payload size of at least
// `payload_size` bytes. `block_next_unallocated` can be used to get more blocks
// having this size.
void *block_first_unallocated(size_t payload_size) {
  void **ptrs = block_unallocated_ptrs(block_root, payload_size);
  void *first = ptrs[BLOCK_UNALLOCATED_NEXT];
  if (first == block_root) {
    return NULL;
  }
  return first;
}

// Returns the previous unallocated block, or NULL if there isn't any. The block
// must be unallocated.
void *block_prev_unallocated(void *block) {
  assert(!block_allocated(block));

  void **ptrs = block_payload(block);
  void *prev = ptrs[BLOCK_UNALLOCATED_PREV];
  if (prev == block_root) {
    return NULL;
  }
  return prev;
}

// Returns the next unallocated block, or NULL if there isn't any. The block
// must be unallocated or the root block.
void *block_next_unallocated(void *block) {
  assert(!block_allocated(block));

  void **ptrs = block_payload(block);
  void *next = ptrs[BLOCK_UNALLOCATED_NEXT];
  if (next == block_root) {
    return NULL;
  }
  return next;
}

// Marks the block as allocated.
//
// This function takes care of updating the free list pointers as necessary.
void block_set_allocated(void *block) {
  assert(!block_allocated(block));

  // Remove the block from the list of unallocated blocks
  void **ptrs = block_payload(block);
  void *prev = ptrs[BLOCK_UNALLOCATED_PREV];
  void *next = ptrs[BLOCK_UNALLOCATED_NEXT];

  void **prev_ptrs = block_unallocated_ptrs(prev, block_payload_size(block));
  prev_ptrs[BLOCK_UNALLOCATED_NEXT] = next;

  void **next_ptrs = block_unallocated_ptrs(next, block_payload_size(block));
  next_ptrs[BLOCK_UNALLOCATED_PREV] = prev;

  // Update block tag
  block_set_tag(block, block_size(block), 1);
}

// Marks the block as unallocated.
//
// This function takes care of updating the free list pointers as necessary.
void block_set_unallocated(void *block) {
  assert(block_allocated(block));

  // Update block tag
  block_set_tag(block, block_size(block), 0);

  // Insert the block at the head of the free list
  void **ptrs = block_payload(block);

  void *prev = block_root;
  void **prev_ptrs = block_unallocated_ptrs(prev, block_payload_size(block));

  void *next = prev_ptrs[BLOCK_UNALLOCATED_NEXT];
  void **next_ptrs = block_unallocated_ptrs(next, block_payload_size(block));

  ptrs[BLOCK_UNALLOCATED_PREV] = prev;
  ptrs[BLOCK_UNALLOCATED_NEXT] = next;

  prev_ptrs[BLOCK_UNALLOCATED_NEXT] = block;
  next_ptrs[BLOCK_UNALLOCATED_PREV] = block;
}

// Checks that the heap is consistent.
#if 0 // debug
void mm_check(void) {
  // For each class
  for (size_t i = 0; i < BLOCK_CLASSES_NBR; ++i) {
    // Loop through the free list
    void *prev = block_root;
    void *block = block_first_unallocated(block_classes[i]);
    while (block != NULL) {
      // The free block must be in the heap
      assert(mem_heap_lo() < block && block < mem_heap_hi());
      // The free block must be marked as unallocated
      assert(!block_allocated(block));

      // Check for doubly-linked free list consistency
      if (prev == block_root) {
        // The first block shouldn't have a previous free block
        assert(block_prev_unallocated(block) == NULL);
      } else {
        assert(block_prev_unallocated(block) == prev);
      }

      prev = block;
      block = block_next_unallocated(block);
    }
  }

  // Loop through all blocks
  void *prev = block_root;
  void *block = block_next(prev);
  while (block != NULL) {
    // The block must be in the heap
    assert(mem_heap_lo() < block && block < mem_heap_hi());

    if (!block_allocated(block)) {
      // Disallow two contiguous unallocated blocks
      assert(prev == NULL || block_allocated(prev));
    }

    prev = block;
    block = block_next(block);
  }
}
#else
inline void mm_check(void) {
  // No-op
}
#endif


// Initializes the memory allocator. Returns zero on success.
//
// This function takes care of allocating and initializing the root block.
int mm_init(void) {
  block_root = block_create(2 * BLOCK_CLASSES_NBR * sizeof(void *));
  if (block_root == NULL) {
    return -1;
  }

  void **ptrs = block_payload(block_root);
  for (size_t i = 0; i < 2 * BLOCK_CLASSES_NBR; ++i) {
    ptrs[i] = block_root;
  }

  return 0;
}

// Allocates a memory block with a payload of `size` bytes.
void *mm_malloc(size_t size) {
  mm_check();

  if (size == 0) {
    return NULL;
  }

  // First try to find a large enough unallocated block
  void *block = block_first_unallocated(size);
  while (block != NULL) {
    if (block_payload_size(block) >= size) {
      block_set_allocated(block);
      return block_payload(block);
    }

    block = block_next_unallocated(block);
  }

  // No block available, allocate a new one
  block = block_create(size);
  if (block == NULL) {
    return NULL;
  }

  return block_payload(block);
}

// Frees a memory block.
//
// This function coalesces free blocks.
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
    // Coalesce `prev`, `block` and `next`
    size_t new_size = block_size(prev) + block_size(block) + block_size(next);
    block_set_allocated(prev);
    block_set_allocated(next);
    block_set_size(prev, new_size);
    block_set_unallocated(prev);
  } else if (prev && !prev_allocated) {
    // Coalesce `prev` and `block`
    size_t new_size = block_size(prev) + block_size(block);
    block_set_allocated(prev);
    block_set_size(prev, new_size);
    block_set_unallocated(prev);
  } else if (next && !next_allocated) {
    // Coalesce block` and `next`
    size_t new_size = block_size(block) + block_size(next);
    block_set_allocated(next);
    block_set_size(block, new_size);
    block_set_unallocated(block);
  } else {
    // Just mark this block as unallocated
    block_set_unallocated(block);
  }

  mm_check();
}

// Re-allocates a memory block with a new payload size.
void *mm_realloc(void *payload, size_t size) {
  if (payload == NULL) {
    return mm_malloc(size);
  }
  if (size == 0) {
    mm_free(payload);
    return NULL;
  }

  mm_check();

  void *old_payload = payload;
  void *old_block = block_from_payload(old_payload);

  size_t old_size = block_payload_size(old_block);
  size_t new_size = size;

  if (old_size >= new_size) {
    // The current block is already large enough
    // TODO: shrink old block size, add new free block?
    return old_payload;
  }

  // Find if we can use next blocks without copying memory
  size_t n = 0;
  void *block = block_next(old_block);
  while (block != NULL && !block_allocated(block)) {
    n += block_size(block);

    if (old_size + n >= new_size) {
      // We found enough unallocated blocks right after this one
      // First mark all blocks as allocated
      for (void *b = block_next(old_block); b != NULL && b <= block; b = block_next(b)) {
        block_set_allocated(b);
      }
      // Then resize this block
      size_t new_size = block_size(old_block) + n;
      block_set_size(old_block, new_size);
      return old_payload;
    }

    block = block_next(block);
  }

  // We need to allocate a brand new block, and copy over the payload
  void *new_payload = mm_malloc(new_size);
  if (new_payload == NULL) {
    return NULL;
  }
  memcpy(new_payload, old_payload, old_size);
  mm_free(old_payload);
  return new_payload;
}
