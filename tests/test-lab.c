#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include "harness/unity.h"
#include "../src/lab.h"


#define TEST_K DEFAULT_K


void setUp(void) {
  // set stuff up here
}

void tearDown(void) {
  // clean stuff up here
}

/**
 * Check the pool to ensure it is full.
 */
void check_buddy_pool_full(struct buddy_pool *pool)
{
  //A full pool should have all values 0-(kval-1) as empty
  for (size_t i = 0; i < pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }

  //The avail array at kval should have the base block
  assert(pool->avail[pool->kval_m].next->tag == BLOCK_AVAIL);
  assert(pool->avail[pool->kval_m].next->next == &pool->avail[pool->kval_m]);
  assert(pool->avail[pool->kval_m].prev->prev == &pool->avail[pool->kval_m]);

  //Check to make sure the base address points to the starting pool
  //If this fails either buddy_init is wrong or we have corrupted the
  //buddy_pool struct.
  assert(pool->avail[pool->kval_m].next == pool->base);
}

/**
 * Check the pool to ensure it is empty.
 */
void check_buddy_pool_empty(struct buddy_pool *pool)
{
  //An empty pool should have all values 0-(kval) as empty
  for (size_t i = 0; i <= pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }
}

/**
 * Test allocating 1 byte to make sure we split the blocks all the way down
 * to MIN_K size. Then free the block and ensure we end up with a full
 * memory pool again
 */
void test_buddy_malloc_one_byte(void)
{
  fprintf(stderr, "->Test allocating and freeing 1 byte\n");
  struct buddy_pool pool;
  int kval = TEST_K;
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  void *mem = buddy_malloc(&pool, 1);
  //Make sure correct kval was allocated
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests the allocation of one massive block that should consume the entire memory
 * pool and makes sure that after the pool is empty we correctly fail subsequent calls.
 */
void test_buddy_malloc_one_large(void)
{
  fprintf(stderr, "->Testing size that will consume entire memory pool\n");
  struct buddy_pool pool;
  size_t bytes = UINT64_C(1) << TEST_K;
  buddy_init(&pool, bytes);

  //Ask for an exact K value to be allocated. This test makes assumptions on
  //the internal details of buddy_init.
  size_t ask = bytes - sizeof(struct avail);
  void *mem = buddy_malloc(&pool, ask);
  assert(mem != NULL);

  //Move the pointer back and make sure we got what we expected
  struct avail *tmp = (struct avail *)mem - 1;
  assert(tmp->kval == TEST_K);
  assert(tmp->tag == BLOCK_RESERVED);
  check_buddy_pool_empty(&pool);

  //Verify that a call on an empty tool fails as expected and errno is set to ENOMEM.
  void *fail = buddy_malloc(&pool, 5);
  assert(fail == NULL);
  assert(errno = ENOMEM);

  //Free the memory and then check to make sure everything is OK
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

void test_malloc_many_chunks(void)
{
    fprintf(stderr, "->Testing allocation of many small chunks\n");
    struct buddy_pool pool;
    size_t pool_size = UINT64_C(1) << TEST_K;
    buddy_init(&pool, pool_size);

    size_t alloc_size = UINT64_C(1) << 20;
    size_t num_allocations = 0;
    size_t max_allocations = pool_size / (UINT64_C(1) << btok(alloc_size + sizeof(struct avail)));

    // this is to keep track of all allocations for easy freeing
    void **allocations = malloc(max_allocations * sizeof(void *));
    assert(allocations != NULL);

    for (unsigned int i = 0; i < max_allocations; i++)
    {
        void *ptr = buddy_malloc(&pool, alloc_size);
        //printAvailBlock((struct avail *) ptr - 1);
        assert(ptr != NULL);
        allocations[num_allocations++] = ptr;
    }
    //printBuddyPool(&pool);
    // test to check not enough memory error.
    void *ptr = buddy_malloc(&pool, alloc_size);
    assert(ptr == NULL);
    assert(errno == ENOMEM);
    assert(num_allocations > 0);
    fprintf(stderr, "Allocated %zu blocks of %zu bytes\n", num_allocations, alloc_size);
    for (size_t i = 0; i < num_allocations; i++)
    {
        //printf("Start:\n");
        //printBuddyPool(&pool);
        buddy_free(&pool, allocations[i]);
    }
    //printBuddyPool(&pool);
    //printf("Start:\n");
    //printBuddyPool(&pool);
    //printBuddyPool(&pool);
    free(allocations);
    check_buddy_pool_full(&pool);
    buddy_destroy(&pool);
}

void test_malloc_not_enough_memory(void)
{
    fprintf(stderr, "->Testing allocation of too large block\n");
    struct buddy_pool pool;
    size_t pool_size = UINT64_C(1) << TEST_K;
    buddy_init(&pool, pool_size);

    // too large
    size_t alloc_size = pool_size + 1;
    void *ptr = buddy_malloc(&pool, alloc_size);
    assert(ptr == NULL);
    assert(errno == ENOMEM);
    check_buddy_pool_full(&pool);
    buddy_destroy(&pool);
}

void test_malloc_then_realloc_grow(void)
{
    fprintf(stderr, "->Testing reallocating a block to a larger size\n");
    struct buddy_pool pool;
    buddy_init(&pool, (size_t) (UINT64_C(1) << TEST_K));

    size_t initial_size = UINT64_C(1) << 16;
    size_t larger_size = UINT64_C(1) << 17;

    // initial
    void *ptr = buddy_malloc(&pool, initial_size);
    assert(ptr != NULL);
    memset(ptr, 0xAA, initial_size);

    //printf("Before:\n");
    //printBuddyPool(&pool);

    // perform realloc
    void *new_ptr = buddy_realloc(&pool, ptr, larger_size);
    assert(new_ptr != NULL);

    // verify data unchanged
    unsigned char *data = (unsigned char *)new_ptr;
    for (size_t i = 0; i < initial_size; i++)
    {
        assert(data[i] == 0xAA);
    }

    //printf("After:\n");
    //printBuddyPool(&pool);

    buddy_free(&pool, new_ptr);
    check_buddy_pool_full(&pool);
    buddy_destroy(&pool);
}

void test_malloc_then_realloc_shrink(void)
{
    fprintf(stderr, "->Testing reallocating a block to a smaller size\n");
    struct buddy_pool pool;
    buddy_init(&pool, (size_t) (UINT64_C(1) << TEST_K));

    size_t initial_size = 128;
    size_t smaller_size = 64;

    // initial
    void *ptr = buddy_malloc(&pool, initial_size);
    assert(ptr != NULL);

    unsigned char *data = (unsigned char *)ptr;
    for (size_t i = 0; i < initial_size; i++)
    {
        data[i] = (unsigned char)(i % 256);
    }

    // realloc
    void *new_ptr = buddy_realloc(&pool, ptr, smaller_size);
    assert(new_ptr != NULL);

    // verify data unchanged (up to new size)
    unsigned char *new_data = (unsigned char *)new_ptr;
    for (size_t i = 0; i < smaller_size; i++)
    {
        assert(new_data[i] == (unsigned char)(i % 256));
    }

    buddy_free(&pool, new_ptr);
    check_buddy_pool_full(&pool);
    buddy_destroy(&pool);
}


void test_realloc_size_0(void)
{
    fprintf(stderr, "->Testing realloc with size 0 (should free the block)\n");
    struct buddy_pool pool;
    buddy_init(&pool, (size_t)(UINT64_C(1) << TEST_K));

    // initial
    size_t alloc_size = 64;
    void *ptr = buddy_malloc(&pool, alloc_size);
    assert(ptr != NULL);
    
    // realloc with size 0 (should free block)
    void *new_ptr = buddy_realloc(&pool, ptr, 0);
    assert(new_ptr == NULL);

    check_buddy_pool_full(&pool);
    buddy_destroy(&pool);
}

void test_realloc_not_enough_memory(void)
{
    fprintf(stderr, "->Testing realloc when not enough memory is available\n");
    struct buddy_pool pool;
    size_t pool_size = UINT64_C(1) << TEST_K;
    buddy_init(&pool, pool_size);

    size_t initial_size = pool_size / 2;
    size_t large_size = pool_size;

    // initial
    void *ptr = buddy_malloc(&pool, initial_size);
    assert(ptr != NULL);

    // realloc
    void *new_ptr = buddy_realloc(&pool, ptr, large_size);
    assert(new_ptr == NULL);
    assert(errno == ENOMEM);

    // original pointer should still work
    memset(ptr, 0xAA, initial_size);
    buddy_free(&pool, ptr);
    check_buddy_pool_full(&pool);
    buddy_destroy(&pool);
}

void test_free_null_pointer(void)
{
    fprintf(stderr, "->Testing free of a NULL pointer (should do nothing)\n");
    struct buddy_pool pool;
    buddy_init(&pool, 0);

    buddy_free(&pool, NULL);
    check_buddy_pool_full(&pool);
    buddy_destroy(&pool);
}

void test_malloc_zero_size(void)
{
    fprintf(stderr, "->Testing malloc of size 0 (should return NULL)\n");
    struct buddy_pool pool;
    buddy_init(&pool, 0);

    void *ptr = buddy_malloc(&pool, 0);
    assert(ptr == NULL);
    check_buddy_pool_full(&pool);
    buddy_destroy(&pool);
}

void test_realloc_null_pointer(void)
{
    fprintf(stderr, "->Testing realloc with NULL pointer (should behave like malloc)\n");
    struct buddy_pool pool;
    buddy_init(&pool, (size_t) (UINT64_C(1) << TEST_K));

    size_t alloc_size = 64;
    void *ptr = buddy_realloc(&pool, NULL, alloc_size);
    assert(ptr != NULL);
    buddy_free(&pool, ptr);
    check_buddy_pool_full(&pool);
    buddy_destroy(&pool);
}



/**
 * Tests to make sure that the struct buddy_pool is correct and all fields
 * have been properly set kval_m, avail[kval_m], and base pointer after a
 * call to init
 */
void test_buddy_init(void)
{
  fprintf(stderr, "->Testing buddy init\n");
  //Loop through all kval MIN_k-DEFAULT_K and make sure we get the correct amount allocated.
  //We will check all the pointer offsets to ensure the pool is all configured correctly
  for (size_t i = MIN_K; i <= DEFAULT_K; i++)
    {
      size_t size = UINT64_C(1) << i;
      struct buddy_pool pool;
      buddy_init(&pool, size);
      check_buddy_pool_full(&pool);
      buddy_destroy(&pool);
    }
}


int main(void) {
  time_t t;
  unsigned seed = (unsigned)time(&t);
  fprintf(stderr, "Random seed:%d\n", seed);
  srand(seed);
  printf("Running memory tests.\n");

  UNITY_BEGIN();

  RUN_TEST(test_buddy_init);
  //RUN_TEST(test_buddy_malloc_one_byte);
  //RUN_TEST(test_buddy_malloc_one_large);
  //RUN_TEST(test_malloc_many_chunks);
  //RUN_TEST(test_malloc_not_enough_memory);
  //RUN_TEST(test_free_null_pointer);
  //RUN_TEST(test_malloc_then_realloc_grow);
  //RUN_TEST(test_malloc_then_realloc_shrink);
  //RUN_TEST(test_malloc_zero_size);
  //RUN_TEST(test_realloc_not_enough_memory);
  //RUN_TEST(test_realloc_null_pointer);
  //RUN_TEST(test_realloc_size_0);
return UNITY_END();
}