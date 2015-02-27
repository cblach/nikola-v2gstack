#include <u.h>
#include <libc.h>
#include <multitask.h>
#include "multitask-impl.h"

#include <pthread.h>

typedef struct Rendez Rendez;

struct Rendez
{
    Rendez *next;
    void *tag;
    void *value;
    Task *task;
};

#define HTSZ 16
static struct { Rendez *r; Lock l; } ht[HTSZ];

static void
init( void )
{
    uint i;
    for (i = 0; i < HTSZ; ++i) {
        ht[i].r = nil;
        lockinit(&ht[i].l);
    }
}

static uint
hash( void *p )
{
    byte *d = (byte *)&p;
    uint i, h = 0;

    for (i = 0; i < sizeof(void *); ++i) {
        h = d[i] + (h << 6) + (h << 16) - h;
    }
    return h;
}

void *
rendez( void *tag,
        void *value )
{
    static pthread_once_t htonce = PTHREAD_ONCE_INIT;
    uint h = hash(tag) % HTSZ;
    Rendez *r, *p, sr;

    pthread_once(&htonce, init);

    _threadblocksigs();
    lock(&ht[h].l);
    for (p = nil, r = ht[h].r; r != nil; p = r, r = r->next) {
        if (r->tag == tag) {
            /* found the same tag, exchange values */
            void *rval = r->value;
            r->value = value;

            /* pull struct out of ht */
            if (p) {
                p->next = r->next;
            } else {
                ht[h].r = r->next;
            }

            /* resume the waiting task */
            unlock(&ht[h].l);
            _threadunblocksigs();
            _taskready(r->task);

            return rval;
        }
    }

    /* no such rendezvous tag, so fill one out and insert it */
    sr.tag = tag;
    sr.value = value;
    sr.task = _taskdequeue();
    sr.next = ht[h].r;
    ht[h].r = &sr;

    /* unlock and wait for rendezvous */
    unlock(&ht[h].l);
    _threadunblocksigs();
    taskyield();

    /* return exchanged value */
    return sr.value;
}

void
arendezinit( ARendez *r )
{
    atomic_init(&r->task, nil);
}

void *
arendez( ARendez *r,
         void *value )
{
    Task *t;

    /* save rendez value before we try to insert ourselves */
    _threadblocksigs();
    t = _taskdequeue();
    t->rendval = value;

    while (1) {
        void *other = nil;

        /* exchange whatever is in the slot for a nil */
        if ((other = atomic_exchange(&r->task, nil)) != nil) {
            Task *o = other;

            /* exchange values */
            other = o->rendval;
            o->rendval = value;

            /* put both tasks back as ready */
            _taskundequeue(t);
            _threadunblocksigs();
            _taskready(o);

            /* return exchanged value */
            return other;
        }

        /* if it was nil to begin with, try to park ourselves in the slot */
        if (atomic_compare_exchange_weak(&r->task, &other, t)) {
            _threadunblocksigs();
            taskyield();

            /* after yield returns the value has been exchanged */
            return t->rendval;
        }
    }
}
