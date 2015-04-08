#include "map.h"

int
mapinit(Map *map,
        size_t elemsz,
        size_t nbuckets,
        size_t (*hash)(Key),
        int (*cmp)(Key, Key))
{
    map->hash = hash;
    map->cmp = cmp;

    map->elemsz = elemsz;
    map->nbuckets = nbuckets;
    map->buckets = calloc(nbuckets, sizeof(void *));
    return map->buckets ? 0 : -1;
}

void *
mapinsert(Map *map,
          Key k)
{
    size_t h = map->hash(k) % map->nbuckets;
    Bucket *b = malloc(sizeof(Bucket) + map->elemsz);
    if (!b) { return NULL; }

    b->k = k;
    b->next = map->buckets[h];
    map->buckets[h] = b;

    return b->v;
}

void *
mapfind(Map *map,
        Key k)
{
    size_t h = map->hash(k) % map->nbuckets;
    Bucket *b;

    for (b = map->buckets[h]; b; b = b->next) {
        if (map->cmp(k, b->k) == 0) { return b->v; }
    }

    return NULL;
}

void
mapremove(Map *map,
          Key k)
{
    size_t h = map->hash(k) % map->nbuckets;
    Bucket *b, *p;

    for (p = NULL, b = map->buckets[h]; b; p = b, b = b->next) {
        if (map->cmp(k, b->k) == 0) {
            if (p) {
                p->next = b->next;
            } else {
                map->buckets[h] = b->next;
            }
            free(b);
            return;
        }
    }
}
