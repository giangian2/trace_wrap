#ifndef RING_BUFFER_H
#define RING_BUFFER_H
#define RING_CAP 4096
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    size_t current_index;      /* next slot to write */
    size_t total;               /* elements ever inserted, never capped */
} RingHeader;

#define GET_HEADER(r)       ((RingHeader*)(r) - 1)
#define ring_index(r)        ((r) ? GET_HEADER(r)->current_index : (size_t)0)
#define ring_total(r)         ((r) ? GET_HEADER(r)->total : (size_t)0)
/* live entries currently held, saturated at RING_CAP */
#define ring_count(r)          (ring_total(r) < RING_CAP ? ring_total(r) : (size_t)RING_CAP)
/* physical slot holding the k-th oldest live entry (k = 0 is the oldest) */
#define ring_at(r,k)             ((ring_index(r) + RING_CAP - ring_count(r) + (k)) % RING_CAP)
#define ring_free(r)        ((r) ? free(GET_HEADER(r)) : (void)0)
#define ring_insert(r,val)                                                             \
    (                                                                                  \
        (r) = (r) ? (r) : create_ring_buffer(sizeof(*(r))),                            \
        (r)[GET_HEADER(r)->current_index] = (val),                                     \
        GET_HEADER(r)->total++,                                                        \
        GET_HEADER(r)->current_index = (GET_HEADER(r)->current_index + 1) % RING_CAP    \
    )

/* By default we need to set current_index and total to 0 on creation */
static inline void *create_ring_buffer(size_t elem_size){
    RingHeader *h = (RingHeader*)malloc(sizeof(RingHeader) + (elem_size*RING_CAP));
    if(h == NULL){
        printf("Error allocating ring buffer of size (byte) : %zu", (sizeof(RingHeader) + (elem_size*RING_CAP)));
        return NULL;
    }
    h->current_index = 0;
    h->total = 0;
    return (void*)(h + 1);
}

#endif
