#include <stddef.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include "lab.h"

double log2(double a);
double mypow(double a, int exp);
double pow2(int exp);
int myceil(double a);

size_t btok(size_t bytes) {
    return (size_t) myceil(log2((double) bytes));
}

struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy) {
    if (pool == NULL || buddy == NULL) {
        return NULL;
    }

    size_t block_size = (size_t)1 << buddy->kval;
    uintptr_t buddy_offset = ((uintptr_t)buddy - (uintptr_t)pool->base) ^ block_size;

    struct avail *buddy_block = (struct avail *)((uintptr_t)pool->base + buddy_offset);
    return buddy_block;
}

void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    if (pool == NULL || size == 0) {
        return NULL;
    }
    size_t required_k = btok(size);
    if (required_k > pool->kval_m) {
        return NULL;
    }
    
    size_t k = required_k;
    while (k <= pool->kval_m && pool->avail[k].tag != BLOCK_AVAIL) {
        k++;
    }
    if (k > pool->kval_m) {
        return NULL;
    }

    while (k > required_k) {
        struct avail *current = &pool->avail[k];
        if (current->next) {
            current->next->prev = current->prev;
        }
        if (current->prev) {
            current->prev->next = current->next;
        }
        current->tag = BLOCK_UNUSED;

        k--;
        uintptr_t buddy_offset = (uintptr_t)current - (uintptr_t)pool->base;
        uintptr_t buddy1_offset = buddy_offset;
        uintptr_t buddy2_offset = buddy_offset + (1 << k);

        struct avail *buddy1 = (struct avail *)((uintptr_t)pool->base + buddy1_offset);
        struct avail *buddy2 = (struct avail *)((uintptr_t)pool->base + buddy2_offset);

        buddy1->kval = k;
        buddy1->tag = BLOCK_AVAIL;
        buddy1->next = &pool->avail[k];
        buddy1->prev = NULL;
        if (pool->avail[k].next) {
            pool->avail[k].next->prev = buddy1;
        }
        pool->avail[k].next = buddy1;

        buddy2->kval = k;
        buddy2->tag = BLOCK_AVAIL;
        buddy2->next = &pool->avail[k];
        buddy2->prev = NULL;
        if (pool->avail[k].next) {
            pool->avail[k].next->prev = buddy2;
        }
        pool->avail[k].next = buddy2;
    }

    struct avail *allocated = &pool->avail[required_k];
    allocated->tag = BLOCK_RESERVED;

    if (allocated->next) {
        allocated->next->prev = allocated->prev;
    }
    if (allocated->prev) {
        allocated->prev->next = allocated->next;
    }

    return (void *)((uintptr_t)allocated + sizeof(struct avail));
}

void buddy_free(struct buddy_pool *pool, void *ptr) {
    if (pool == NULL || ptr == NULL) {
        return;
    }
    struct avail *block = (struct avail *)((uintptr_t)ptr - sizeof(struct avail));
    if (block->tag != BLOCK_RESERVED) {
        fprintf(stderr, "Error: Attempting to free a block that is not reserved.\n");
        return;
    }
    block->tag = BLOCK_AVAIL;
    size_t block_size = (size_t) pow2(block->kval);
    while (block->kval < pool->kval_m) {
        struct avail *buddy = buddy_calc(pool, block);

        if (buddy->tag != BLOCK_AVAIL || buddy->kval != block->kval) {
            break;
        }
        if (buddy->next) {
            buddy->next->prev = buddy->prev;
        }
        if (buddy->prev) {
            buddy->prev->next = buddy->next;
        }
        if (buddy < block) {
            block = buddy;
        }
        block->kval++;
        block_size *= 2;
    }

    block->next = pool->avail[block->kval].next;
    block->prev = &pool->avail[block->kval];
    if (pool->avail[block->kval].next) {
        pool->avail[block->kval].next->prev = block;
    }
    pool->avail[block->kval].next = block;
}

void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size) {
    if (pool == NULL) {
        return NULL;
    }
    if (size == 0) {
        if (ptr != NULL) {
            buddy_free(pool, ptr);
        }
        return NULL;
    }
    if (ptr == NULL) {
        return buddy_malloc(pool, size);
    }

    struct avail *block = (struct avail *)((uintptr_t)ptr - sizeof(struct avail));
    size_t current_size = (size_t) pow2(block->kval);

    size_t required_size = size + sizeof(struct avail);
    if (required_size <= current_size) {
        return ptr;
    }
    void *new_ptr = buddy_malloc(pool, size);
    if (new_ptr == NULL) {
        return NULL;
    }

    size_t copy_size = current_size - sizeof(struct avail);
    memcpy(new_ptr, ptr, copy_size);
    buddy_free(pool, ptr);
    return new_ptr;
}

void buddy_init(struct buddy_pool *pool, size_t size) {
    if (size == 0) size = pow2(DEFAULT_K);
    if (size < pow2(MIN_K)) size = pow2(MIN_K);

    size_t kval = (size_t) myceil(log2((double) size));
    size = pow2(kval);

    void *memory = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        perror("failed to allocate memory\n");
        return;
    }

    pool->kval_m = kval;
    pool->numbytes = size;
    pool->base = memory;

    for (size_t i = 0; i <= kval; i++) {
        pool->avail[i].tag = BLOCK_UNUSED;
        pool->avail[i].kval = i;
        pool->avail[i].next = NULL;
        pool->avail[i].prev = NULL;
    }
    pool->avail[kval].tag = BLOCK_AVAIL;
    pool->avail[kval].next = &pool->avail[kval];
    pool->avail[kval].prev = &pool->avail[kval];
}

void buddy_destroy(struct buddy_pool *pool) {
    if (pool == NULL) {
        return;
    }

    if (pool->base != NULL) {
        if (munmap(pool->base, pool->numbytes) != 0) {
            perror("munmap failed");
        }
    }
    pool->kval_m = 0;
    pool->numbytes = 0;
    pool->base = NULL;
    memset(pool->avail, 0, sizeof(pool->avail));
}

int myMain(int argc, char** argv) {
    return 0;
}

// Helpers

double log2(double a) {
    uint64_t val = (uint64_t) a;
    size_t retVal = 0;
    while (val > 1) {
        val >>= 1;
        retVal++;
    }
    return retVal;
}

double mypow(double a, int exp) {
    if (exp == 0) return 1;
    bool reci = false;
    if (exp < 0) {
        reci = true;
        exp = -exp;
    }
    double retVal = 1;
    for (int i = 0; i < exp; i++) {
        retVal *= a;
    }
    if (reci) return 1 / retVal;
    return retVal;
}

double pow2(int exp) {
    return 1 << exp;
}

int myceil(double a) {
    int val = (int) a;
    return val + (a > val);
}