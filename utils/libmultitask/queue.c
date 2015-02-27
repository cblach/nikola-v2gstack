#include <u.h>
#include <libc.h>
#include <multitask.h>
#include "multitask-impl.h"

void
queueinit( Queue *q )
{
    lockinit(&q->lock);
    q->begin = nil;
    q->end = nil;
}

void
qwait( Queue *q )
{
    Task *t = _taskdequeue();
    atomic_store(&t->next, nil);

    lock(&q->lock);
    if (!q->begin) {
        q->begin = t;
    } else {
        atomic_store(&((Task *)q->end)->next, t);
    }
    q->end = t;
    unlock(&q->lock);

    taskyield();
}

ulong
qwake( Queue *q,
       ulong n )
{
    ulong i;

    lock(&q->lock);
    for (i = 0; i < n; ++i) {
        Task *t = q->begin;
        if (!t) { break; }

        q->begin = atomic_load(&t->next);
        _taskready(t);
    }
    unlock(&q->lock);

    return i;
}
