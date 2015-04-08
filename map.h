#ifndef MAP_H
#define MAP_H

#include <stdlib.h>
#include <inttypes.h>

typedef union Key Key;
typedef struct Bucket Bucket;
typedef struct Map Map;

union Key
{
    int i;
    unsigned u;
    uint64_t u64;
    size_t sz;
    ssize_t ssz;
    void *ptr;
};

struct Bucket
{
    Bucket *next;

    Key k;
    char v[];
};

struct Map
{
    size_t elemsz;
    size_t nbuckets;
    Bucket **buckets;
    size_t (*hash)(Key);
    int (*cmp)(Key, Key);
};

int mapinit(Map *map,
        size_t elemsz,
        size_t nbuckets,
        size_t (*hash)(Key),
        int (*cmp)(Key, Key));
void *mapinsert(Map *map,
          Key k);
void *mapfind(Map *map,
              Key k);
void mapremove(Map *map,
          Key k);

#endif
