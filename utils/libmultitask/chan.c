#include <u.h>
#include <libc.h>
#include <multitask.h>
#include "multitask-impl.h"

typedef struct LibmultitaskChanInternalWaiter CWaiter;
typedef struct LibmultitaskChanInternalQueue CQueue;
typedef struct LibmultitaskChanInternalAltState AltState;

struct LibmultitaskChanInternalAltState
{
    atomic_flag popped;
    Chan *completer;
    Task *task;
};

typedef struct Elem Elem;

struct Elem
{
    _Atomic(uint32) lap;
    char data[];
};

static char _closed = '\0';
static void *const closed = &_closed;

#define HEAPBIT 0x80

void
_chaninit( Chan *c,
           size_t elemsz,
           size_t nelem,
           void *buf,
           bool heap,
           int type )
{
    c->type = (uint8)(type | (heap ? HEAPBIT : 0));

    assert(elemsz <= (uint16)-1 && nelem <= (uint32)-1);
    c->elemsz = (uint16)elemsz;
    c->nelem = (uint32)nelem;
    if (elemsz == 0) {
        atomic_init(&c->count, 0);
    } else {
        if ((c->buf = buf) != nil) {
            uint32 i;
            for (i = 0; i < c->nelem; ++i) {
                atomic_init(&((Elem *)c->buf + i)->lap, 0);
            }
        }
    }
    atomic_store(&c->sendx, 0);
    atomic_store(&c->recvx, (uint64)1 << 32);

    atomic_init(&c->sendq.first, nil);
    atomic_init(&c->sendq.last, nil);
    atomic_init(&c->recvq.first, nil);
    atomic_init(&c->recvq.last, nil);

    c->refs = 0;
    atomic_init(&c->closed, false);
    lockinit(&c->lock);

    c->tqi = 0;
}

int
chaninit( Chan *c,
          size_t elemsz,
          size_t nelem )
{
    void *buf = nil;

    if (elemsz > (uint16)-1 - sizeof(Elem) ||
        nelem > (uint32)-1) { return -1; }

    if (nelem > 0 && elemsz > 0) {
        buf = calloc(nelem, sizeof(Elem) + elemsz);
        if (!buf) { return -1; }
    }
    _chaninit(c, elemsz, nelem, buf, false, CTNORMAL);

    return 0;
}

Chan *
channew( size_t elemsz,
         size_t nelem )
{
    Chan *c;
    void *buf = nil;

    if (elemsz > (uint16)-1 - sizeof(Elem) ||
        nelem > (uint32)-1) { return nil; }

    if (elemsz > 0 && nelem > 0) {
        c = xcalloc(sizeof(*c), nelem, sizeof(Elem) + elemsz);
        buf = c + 1;
    } else {
        c = malloc(sizeof(*c));
    }
    if (!c) { return nil; }

    _chaninit(c, elemsz, nelem, buf, true, CTNORMAL);

    return c;
}

static inline void
_chanref( Chan *c )
{
    c->refs++;
}

static ulong
_chanunref( Chan *c )
{
    ulong refs = c->refs--;
    if (refs == 0) {
        switch (c->type & ~HEAPBIT) {
            case CTTIME: _tchanfree(c); break;
            case CTIO: _iochanfree(c); break;
        }

        unlock(&c->lock);

        if (c->elemsz > 0) {
            free((c->type & HEAPBIT) ? c : c->buf);
        }
    }
    return refs;
}

void
chanfree( Chan *c )
{
    CWaiter *w;

    lock(&c->lock);
    atomic_store(&c->closed, true);

    if ((w = atomic_load(&c->sendq.first)) == nil) {
        w = atomic_load(&c->recvq.first);
    }
    while (w) {
        if (!atomic_flag_test_and_set(&w->state->popped)) {
            w->popped = true;
            w->state->completer = closed;

            _taskready(w->state->task);
        }
        w = w->next;
    }
    atomic_store(&c->sendq.first, nil);
    atomic_store(&c->sendq.last, nil);
    atomic_store(&c->recvq.first, nil);
    atomic_store(&c->recvq.last, nil);

    if (_chanunref(c) != 0) {
        unlock(&c->lock);
    }
}

static inline void
chancpy( void *dst,
         const void *src,
         size_t sz )
{
    if (dst && src) { memcpy(dst, src, sz); }
}

static inline CWaiter *
getwaiter( CQueue *q )
{
    CWaiter *w;

    for (w = atomic_load(&q->first); w; w = w->next) {
        if (w->next) {
            w->next->prev = nil;
        } else {
            atomic_store(&q->last, nil);
        }
        atomic_store(&q->first, w->next);

        w->popped = true;
        if (!atomic_flag_test_and_set(&w->state->popped)) { return w; }
    }

    return nil;
}

static inline void
removewaiter( CQueue *q,
              CWaiter *w )
{
    if (w->popped) { return; }
    w->popped = true;

    if (w->next) {
        w->next->prev = w->prev;
    } else {
        atomic_store(&q->last, w->prev);
    }

    if (w->prev) {
        w->prev->next = w->next;
    } else {
        atomic_store(&q->first, w->next);
    }
}

static inline void
putwaiter( CQueue *q,
           CWaiter *w )
{
    CWaiter *l = atomic_load(&q->last);

    w->next = nil;
    w->prev = nil;
    w->popped = false;
    if (l) {
        w->prev = l;
        l->next = w;
    } else {
        atomic_store(&q->first, w);
    }
    atomic_store(&q->last, w);
}

static inline int
syncop( Chan *c,
        const void *cv,
        void *v,
        int op,
        bool nb )
{
    CQueue *selfq, *otherq;
    CWaiter *w;

    if (atomic_load(&c->closed)) { return -1; }

    if (op == CHANSEND) {
        selfq = &c->sendq;
        otherq = &c->recvq;
    } else {
        selfq = &c->recvq;
        otherq = &c->sendq;
    }

    if (nb) {
        /* non-block fast path */
        if (!atomic_load(&otherq->first)) { return 0; }
    }

    _threadblocksigs();
    lock(&c->lock);
    if (atomic_load(&c->closed)) {
        unlock(&c->lock);
        _threadunblocksigs();
        return -1;
    }
    /* look for a blocked receiver and communicate if available */
    if ((w = getwaiter(otherq)) != nil) {
        size_t elemsz = c->elemsz;
        unlock(&c->lock);
        _threadunblocksigs();

        if (op == CHANSEND) {
            chancpy(w->v, cv, elemsz);
        } else {
            chancpy(v, w->cv, elemsz);
        }
        w->state->completer = c;
        _taskready(w->state->task);
        return 1;
    }

    if (nb) {
        /* tried to send but wasn't able and we're non-blocking */
        unlock(&c->lock);
        _threadunblocksigs();
        return 0;
    } else {
        /* block and wait for receiver */
        AltState as = {
            .popped = ATOMIC_FLAG_INIT,
            .completer = nil,
            .task = _taskdequeue()
        };
        CWaiter cw = {
            .state = &as,
        };
        if (op == CHANSEND) {
            cw.cv = cv;
        } else {
            cw.v = v;
        }
        putwaiter(selfq, &cw);
        unlock(&c->lock);
        _threadunblocksigs();

        taskyield();
        assert(as.completer);
        if (as.completer == closed) { return -1; }
        return 1;
    }
}

static inline int
asyncopnb( Chan *c,
           const void *cv,
           void *v,
           int op )
{
    _Atomic(uint64) *px = (op == CHANSEND) ? &c->sendx : &c->recvx;

    while (1) {
        uint32 pos, lap, elap;
        uint64 x, newx;
        Elem *e;

        if (atomic_load(&c->closed)) { return -1; }

        x = atomic_load(px);
        pos = (uint32)(x & 0xFFFFFFFF);
        lap = (uint32)((x >> 32) & 0xFFFFFFFF);

        e = (Elem *)((byte *)c->buf + pos * (sizeof(Elem) + c->elemsz));
        elap = atomic_load(&e->lap);

        if (lap == elap) {
            /* calculate the new lap||pos value, taking care to wrap around
             * properly */
            if (pos + 1 < c->nelem) {
                newx = x + 1;
            } else {
                newx = (uint64)(lap + 2) << 32;
            }
            if (!atomic_compare_exchange_weak(px, &x, newx)) {
                /* failed to claim the slot, try again */
                continue;
            }
            /* fill in data and mark as ready */
            if (op == CHANSEND) {
                chancpy(e->data, cv, c->elemsz);
            } else {
                chancpy(v, e->data, c->elemsz);
            }
            atomic_store(&e->lap, elap + 1);
            return 1;
        } else {
            uint32 r = lap - elap;
            /* check if we're at the buffer's end */
            if (*(int32 *)&r > 0) { return 0; }
        }
        /* raced and failed. Try again. */
    }
}

static inline bool
asyncready( Chan *c,
            int op )
{
    uint32 pos, lap, elap;
    uint64 x;
    Elem *e;

    x = atomic_load((op == CHANSEND) ? &c->sendx : &c->recvx);
    pos = (uint32)(x & 0xFFFFFFFF);
    lap = (uint32)((x >> 32) & 0xFFFFFFFF);

    e = (Elem *)((byte *)c->buf + pos * (sizeof(Elem) + c->elemsz));
    elap = atomic_load(&e->lap);

    return (lap == elap);
}

static inline int
nullopnb( Chan *c,
          int op )
{
    while (1) {
        uint32 count, newcount;

        if (atomic_load(&c->closed)) { return -1; }

        count = atomic_load(&c->count);
        if (op == CHANSEND) {
            if (count >= c->nelem) { return 0; }
            newcount = count + 1;
        } else {
            if (count == 0) { return 0; }
            newcount = count - 1;
        }

        if (atomic_compare_exchange_weak(&c->count, &count, newcount)) {
            return 1;
        }
    }
}

static inline bool
nullready( Chan *c,
           int op )
{
    uint32 count = atomic_load(&c->count);
    if (op == CHANSEND) {
        if (count < c->nelem) { return true; }
    } else {
        if (count > 0) { return true; }
    }
    return false;
}

static inline int
asyncop( Chan *c,
         const void *cv,
         void *v,
         int op,
         bool nb )
{
    CQueue *selfq, *otherq;
    bool null = (c->elemsz == 0);

    if (op == CHANSEND) {
        selfq = &c->sendq;
        otherq = &c->recvq;
    } else {
        selfq = &c->recvq;
        otherq = &c->sendq;
    }

    while (1) {
        int r = null ? nullopnb(c, op) : asyncopnb(c, cv, v, op);

        if (r != 0) {
            if (r == -1) { return -1; }

            /* we modified the buffer. Try to wake someone up to act on it */
            if (atomic_load(&otherq->first) != nil) {
                CWaiter *w;

                _threadblocksigs();
                lock(&c->lock);
                w = getwaiter(otherq);
                unlock(&c->lock);
                _threadunblocksigs();

                if (w) { _taskready(w->state->task); }
            }
            return 1;
        } else if (nb) {
            return 0;
        } else {
            /* channel buffer is full */
            AltState as = {
                .popped = ATOMIC_FLAG_INIT,
                .completer = nil,
                .task = _taskdequeue()
            };
            CWaiter cw = {
                .state = &as
            };
            if (op == CHANSEND) {
                cw.cv = cv;
            } else {
                cw.v = v;
            }

            _threadblocksigs();
            lock(&c->lock);
            if (atomic_load(&c->closed)) {
                unlock(&c->lock);
                _threadunblocksigs();
                _taskundequeue(as.task);
                return -1;
            }

            putwaiter(selfq, &cw);
            if (null ? nullready(c, op) : asyncready(c, op)) {
                /* someone modified the buffer, making us ready to act */
                removewaiter(selfq, &cw);
                unlock(&c->lock);
                _threadunblocksigs();
                _taskundequeue(as.task);
                continue;
            }
            unlock(&c->lock);
            _threadunblocksigs();

            taskyield();
            if (as.completer == closed) { return -1; }
            /* after blocking, try to act again */
        }
    }
}

static inline bool
isready( Chan *c,
         int op )
{
    if (c->elemsz == 0) {
        return nullready(c, op);
    } else if (c->nelem == 0) {
        CQueue *q = (op == CHANSEND) ? &c->recvq : &c->sendq;
        if (atomic_load(&q->first) != nil) { return true; }
        return false;
    } else {
        return asyncready(c, op);
    }
}

static inline int
chanop( Chan *c,
        const void *cv,
        void *v,
        int op,
        bool nb )
{
    if (c->elemsz == 0) {
        cv = nil;
        v = nil;
    } else if (c->nelem == 0) {
        return syncop(c, cv, v, op, nb);
    }
    return asyncop(c, cv, v, op, nb);
}

int
chansend( Chan *c,
          const void *v )
{
    return chanop(c, v, nil, CHANSEND, false);
}

int
chansendnb( Chan *c,
            const void *v )
{
    return chanop(c, v, nil, CHANSEND, true);
}

int
chanrecv( Chan *c,
          void *v )
{
    return chanop(c, nil, v, CHANRECV, false);
}

int
chanrecvnb( Chan *c,
            void *v )
{
    return chanop(c, nil, v, CHANRECV, true);
}

int
alt( Alt *alts )
{
    uint i, j, nalts = 0;
    int nb = 0;

    for (i = 0; alts[i].op != CHANEND && alts[i].op != CHANENDNB; ++i) {
        /* we can't actually reorder the alts themselves so instead we use our
         * implementation defined indices to index into the array. Here we
         * condense them into the smallest necessary set excluding all CHANNOPs
         * so that we don't have to parse those later. They still have a
         * cost in cache misses (potentially) but this should minimize the
         * actual parsing cost. */
        alts[nalts].impl.sorder = i;

        if (!alts[i].c) { alts[i].op = CHANNOP; }
        if (i > INT_MAX) { return -1; }

        /* also create a randomized selection order */
        switch (alts[i].op) {
            case CHANSEND:
            case CHANRECV:
                if (nalts > 0) {
                    uint j = (uint)rand() % (nalts + 1);
                    if (j != nalts) {
                        uint tmp = alts[nalts].impl.sorder;
                        alts[nalts].impl.sorder = alts[j].impl.sorder;
                        alts[j].impl.sorder = tmp;
                    }
                }
                ++nalts;
                break;

            case CHANNOP:
                break;

            default:
                return -1;
        }
    }
    nb = (alts[i].op == CHANENDNB) ? (int)i : 0;
    if (nalts == 0) { return -1; }

    /* reduce to single operation if only one alt is alive */
    if (nalts == 1) {
        Alt *a = &alts[alts[0].impl.sorder];
        return (a->op == CHANSEND) ?
            (nb ? chansendnb(a->c, a->cv) : chansend(a->c, a->cv)) :
            (nb ? chanrecvnb(a->c, a->v)  : chanrecv(a->c, a->v));
    }

    while (1) {
        AltState as;
        Alt *completer;

        /* Phase 1 - look for a channel that's ready to go */
        for (i = 0; i < nalts; ++i) {
            Alt *a = &alts[alts[i].impl.sorder];
            if (((a->op == CHANSEND) ?
                chansendnb(a->c, a->cv) :
                chanrecvnb(a->c, a->v)) == 1) {
                return (int)(a - alts);
            }
        }
        if (nb) { return nb; }

        atomic_flag_clear(&as.popped);
        as.completer = nil;
        as.task = _taskdequeue();

        /* Phase 2 - block on all channels */
        _threadblocksigs();
        for (i = 0; i < nalts; ++i) {
            Alt *a = &alts[alts[i].impl.sorder];
            Chan *c = a->c;
            CWaiter *cw = &a->impl.waiter;
            CQueue *q;

            cw->state = &as;
            if (a->op == CHANSEND) {
                cw->cv = a->cv;
                q = &c->sendq;
            } else {
                cw->v = a->v;
                q = &c->recvq;
            }

            lock(&c->lock);
            if (atomic_load(&c->closed)) {
                unlock(&c->lock);
                break;
            }

            putwaiter(q, cw);
            if (isready(c, a->op)) {
                removewaiter(q, cw);
                unlock(&c->lock);
                break;
            }
            _chanref(c);
            unlock(&c->lock);
        }
        _threadunblocksigs();
        if (i == nalts) {
            taskyield();
        } else {
            if (!atomic_flag_test_and_set(&as.popped)) {
                _taskundequeue(as.task);
            } else {
                taskyield();
            }
        }

        /* Phase 3 - remove ourselves from all channels */
        completer = nil;
        _threadblocksigs();
        for (j = 0; j < i; ++j) {
            Alt *a = &alts[alts[j].impl.sorder];
            Chan *c = a->c;
            CQueue *q = (a->op == CHANSEND) ? &c->sendq : &c->recvq;

            lock(&c->lock);
            if (atomic_load(&c->closed)) {
                a->op = CHANNOP;
            } else {
                removewaiter(q, &a->impl.waiter);
            }
            if (_chanunref(c) != 0) {
                unlock(&c->lock);
            }

            if (c == as.completer) { completer = a; }
        }
        _threadunblocksigs();

        if (as.completer == closed) { return -1; }
        if (completer) { return (int)(completer - alts); }

        /* if we reach here it's because we were awoken by an async channel and
         * must now try again to complete our task */
    }
}
