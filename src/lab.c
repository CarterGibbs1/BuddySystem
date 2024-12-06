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

/**
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy) {
    if (pool == NULL || buddy == NULL) {
        return NULL;
    }

    uintptr_t buddy_address = (uintptr_t) buddy;
    uintptr_t offset = UINT64_C(1) << buddy->kval;
    return (struct avail *)(buddy_address ^ offset);
}
*/


struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy) {
    if (pool == NULL || buddy == NULL) {
        return NULL;
    }

    uintptr_t buddy_address = (uintptr_t) buddy;
    uintptr_t offset = UINT64_C(1) << buddy->kval;
    uintptr_t address = buddy_address - (uintptr_t) pool->base;
    uintptr_t index = address ^ offset;
    return (struct avail *) ((uintptr_t) pool->base + index);
}


/**
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy) {
    intptr_t b = (intptr_t) buddy - (intptr_t) pool->base;

    if (b % (1 << (buddy->kval + 1)) == 0) {
        return (struct avail *)((b + (1 << buddy->kval)) + (intptr_t) pool->base);
    }
    return (struct avail *)((b - (1 << buddy->kval)) + (intptr_t) pool->base);
}
*/

void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    if (size == 0 || pool == NULL) {
        return NULL;
    }
    //printf("Start:\n");
    //printBuddyPool(pool);
    // Find block
    unsigned int j = 0;
    unsigned int k = btok(size + sizeof(struct avail));
    //printf("k: %u\n",k);
    for (j = k; j <= pool->kval_m; j++) {
        if (pool->avail[j].next != &pool->avail[j]) {
            break;
        }
    }
    if (j > pool->kval_m) {
        perror("buddy: malloc failed!");
        errno = ENOMEM;
        return NULL;
    }
    // Remove from list
    struct avail *L = pool->avail[j].next;
    struct avail *P = L->next;
    pool->avail[j].next = P;
    P->prev = &pool->avail[j];
    L->tag = BLOCK_RESERVED;
    //printAvailBlock(L);
    // Split required?
    //printf("j: %u\n", j);
    while (j != k) {
        // Split
        L->kval--;
        j--;
        //printf("L:\n");
        //printAvailBlock(L);
        P = (struct avail *) ((uintptr_t)L + (UINT64_C(1) << j));
        intptr_t b = (intptr_t) buddy_calc(pool, L);
        intptr_t d = b ^ (intptr_t) P;
        P->tag = BLOCK_AVAIL;
        P->kval = j;
        P->next = &pool->avail[j];
        P->prev = &pool->avail[j];
        pool->avail[j].next = P;
        pool->avail[j].prev = P;
        //printf("P:\n");
        //printAvailBlock(P);
    }
    //printBuddyPool(pool);
    return (void *)(((struct avail *) L) + 1);
}

/*
void buddy_free(struct buddy_pool *pool, void *ptr) {
    if (ptr == NULL) return;
    struct avail *L = ((struct avail *) ptr) - 1;
    unsigned short k = L->kval;
    //printf("L: %p\n", (void *) L);
    struct avail *P = buddy_calc(pool, L);
    printf("P: %p\n", (void *) P);
    //struct avail *L = (struct avail *) ptr;
    //unsigned short k = L->kval;
    //struct avail *P = buddy_calc(pool, L);
    //printAvailBlock(L);
    //printAvailBlock(P);
    // Is buddy available?
    while (!(k == pool->kval_m || P->tag == BLOCK_RESERVED || (P->tag == BLOCK_AVAIL && P->kval != k))) {
        //printf("start: \n");
        //printBuddyPool(pool);
        // combine with buddy
        P->prev->next = P->next;
        P->next->prev = P->prev;
        L->kval++;
        k++;
        if (P < L) L = P;

        P = buddy_calc(pool, L);
    }
    // Put on list
    L->tag = BLOCK_AVAIL;
    P = pool->avail[k].next;
    L->next = P;
    P->prev = L;
    L->kval = k;
    L->prev = &pool->avail[k];
    pool->avail[k].next = L;
    //printBuddyPool(pool);
}
*/


void buddy_free(struct buddy_pool *pool, void *ptr) {
    if (ptr == NULL) return;
    struct avail *L = (struct avail *) ptr - 1;
    unsigned short k = L->kval;
    struct avail *P;
    goto S1;

    S1:
        P = buddy_calc(pool, L);
        if (P == NULL || k == pool->kval_m || P->tag == BLOCK_RESERVED || (P->tag == BLOCK_AVAIL && P->kval != k)) {
            goto S3;
        }
        goto S2;
    S2:
        P->prev->next = P->next;
        P->next->prev = P->prev;
        k++;
        L->kval = k;
        P->kval = k;
        if (P < L) L = P;
        goto S1;
    S3:
        L->tag = BLOCK_AVAIL;
        P = pool->avail[L->kval].next;
        L->next = P;
        P->prev = L;
        L->kval = k;
        L->prev = &(pool->avail[k]);
        pool->avail[k].next = L;
}

void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size) {
    if (ptr == NULL) {
        return buddy_malloc(pool, size);
    }

    if (size == 0) {
        buddy_free(pool, ptr);
        return NULL;
    }

    // get metadata of block
    struct avail *L = ((struct avail *)ptr) - 1;
    unsigned int old_k = L->kval;
    size_t old_block_size = UINT64_C(1) << old_k;
    //size_t old_user_size = old_block_size - sizeof(struct avail);

    unsigned int new_k = btok(size + sizeof(struct avail));
    if (new_k == old_k) {
        return ptr;
    } else if (new_k < old_k) {
        // shrink block
        unsigned int j = old_k;
        struct avail *P;
        while (j > new_k) {
            // Split
            L->kval--;
            j--;
            P = (struct avail *)(((void *)L) + (UINT64_C(1) << j));
            P->tag = BLOCK_AVAIL;
            P->kval = j;
            P->next = &pool->avail[j];
            P->prev = &pool->avail[j];
            pool->avail[j].next = P;
            pool->avail[j].prev = P;
        }
        L->kval = new_k;
        return ptr;
    } else {
        // grow block
        void *new_ptr = buddy_malloc(pool, size);
        if (new_ptr == NULL) {
            return NULL;
        }

        size_t copy_size = old_block_size - sizeof(struct avail);
        if (size < old_block_size - sizeof(struct avail)) {
            copy_size = size;
        }
        memcpy(new_ptr, ptr, copy_size);
        buddy_free(pool, ptr);
        return new_ptr;
    }
}


void buddy_init(struct buddy_pool *pool, size_t size) {
    if (size == 0) size = UINT64_C(1) << DEFAULT_K;
    pool->kval_m = btok(size);
    pool->numbytes = UINT64_C(1) << pool->kval_m;

    pool->base = mmap(NULL, pool->numbytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool->base == MAP_FAILED) {
        perror("buddy: could not allocate memory pool!");
    }

    for (unsigned int i = 0; i <= pool->kval_m; i++) {
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

// Debug Methods
void printBuddyPool(struct buddy_pool *pool) {
    for (unsigned int i = 0; i < pool->kval_m; i++) {
        struct avail *curr = &pool->avail[i];
        struct avail *first = curr;
        if (curr != NULL) {
            do {
                printf("%p -> ", curr);
                curr = curr->next;
            } while (curr != first && curr != NULL);
        }
        if (curr == first) {
            printf("first\n");
        } else {
            printf("%p\n", curr);
        }   
    }
}

void printAvailBlock(struct avail *block) {
    printf("addr : %p\n", block);
    printf("tag  : %hu\n", block->tag);
    printf("k_val: %hu\n", block->kval);
    printf("\n");
}