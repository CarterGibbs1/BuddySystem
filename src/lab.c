#include <stddef.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "lab.h"

size_t btok(size_t bytes) {
    unsigned int counter = 0;
    bytes--;
    while (bytes > 0) {
        bytes >>= 1;
        counter++;
    }
    return counter;
}

struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy) {
    if (pool == NULL || buddy == NULL) {
        return NULL;
    }
    size_t block_size = UINT64_C(1) << buddy->kval;
    uintptr_t buddy_offset = ((uintptr_t) buddy - (uintptr_t) pool->base) ^ block_size;
    return (struct avail *) ((uintptr_t) pool->base + buddy_offset);
}

void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    // Find block
    unsigned int j = 0;
    for (j = 0; j <= pool->kval_m; j++) {
        if (pool->avail[j].next != &pool->avail[j]) {
            break;
        }
    }
    if (j > pool->kval_m) {
        perror("buddy: malloc failed!");
        return NULL;
    }
    // Remove from list
    struct avail *L = pool->avail[j].next;
    struct avail *P = L->next;
    pool->avail[j].next = P;
    P->prev = &pool->avail[j];
    L->tag = BLOCK_RESERVED;
    // Split required?
    while (j != 0) {
        // Split
        j--;
        P = L + (UINT64_C(1) << j);
        P->tag = BLOCK_AVAIL;
        P->kval = j;
        P->next = &pool->avail[j];
        P->prev = &pool->avail[j];
        pool->avail[j].next = P;
        pool->avail[j].prev = P;
    }
    return L;
}

void buddy_free(struct buddy_pool *pool, void *ptr) {
    struct avail *L = (struct avail *) ptr;
    unsigned short k = L->kval;
    struct avail *P = buddy_calc(pool, L);
    goto S1;

    // Is buddy available?
    S1:
        if (k == pool->kval_m || P->tag == BLOCK_RESERVED || (P->tag == BLOCK_AVAIL && P->kval != k)) {
            goto S3;
        }
    // combine with buddy
    S2:
        P->prev->next = P->next;
        P->next->prev = P->prev;
        k++;
        if (P < L) L = P;
        goto S1;
    // Put on list
    S3:
        L->tag = BLOCK_AVAIL;
        P = pool->avail[k].next;
        L->next = P;
        P->prev = L;
        L->kval = k;
        L->prev = &pool->avail[k];
        pool->avail[k].next = L;
}

void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size) {
    
}

void buddy_init(struct buddy_pool *pool, size_t size) {
    if (size == 0) size = UINT64_C(1) << DEFAULT_K;
    pool->kval_m = btok(size);
    pool->numbytes = UINT64_C(1) << pool->kval_m;

    pool->base = mmap(NULL, pool->numbytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool->base == MAP_FAILED) {
        perror("buddy: could not allocate memory pool!");
    }

    for (unsigned int i = 0; i < pool->kval_m; i++) {
        pool->avail[i].next = &pool->avail[i];
        pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    pool->avail[pool->kval_m].next = pool->base;
    pool->avail[pool->kval_m].prev = pool->base;
    struct avail *ptr = (struct avail *) pool->base;
    ptr->tag = BLOCK_AVAIL;
    ptr->kval = pool->kval_m;
    ptr->next = &pool->avail[pool->kval_m];
    ptr->prev = &pool->avail[pool->kval_m];
}

void buddy_destroy(struct buddy_pool *pool) {
    int status = munmap(pool->base, pool->numbytes);
    if (status == -1) {
        perror("buddy: destroying memory failed!");
    }
}