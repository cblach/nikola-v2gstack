#include <u.h>
#include <libc.h>
#include <multitask.h>
#include "multitask-impl.h"

/* TODO: make this lock free */

/*
 * Let's get some rationale. Locks only work on an OS level. Queueing locks are
 * different in that they also support user-space threads.
 *
 * When waking someone from the queue you might worry that if that task that
 * just released the lock tries to reacquire the lock then it will starve the
 * waiters. Not so, as we don't actually release the lock but basically just
 * transfer ownership. If the task tries to re-lock it will be queued.
 * Completely fair.
 */

void
qlockinit( QLock *l )
{
    lockinit(&l->l);
    atomic_init(&l->locked, 0);
    l->begin = nil;
    l->end = nil;
}

void
qlock( QLock *l )
{
    int i;

    if (atomic_exchange(&l->locked, 1) == 0) { return; }

    lock(&l->l);
    if ((i = atomic_exchange(&l->locked, 1)) != 0) {
        Task *t = _taskdequeue();

        atomic_store(&t->next, nil);
        if (l->begin) {
            atomic_store(&((Task *)l->end)->next, t);
        } else {
            l->begin = t;
        }
        l->end = t;
    }
    unlock(&l->l);

    /* we will have acquired the lock upon returning from yield */
    if (i != 0) { taskyield(); }
}

int
qtrylock( QLock *l )
{
    if (atomic_exchange(&l->locked, 1) == 0) { return 1; }
    return 0;
}

void
qunlock( QLock *l )
{
    Task *t;

    lock(&l->l);
    t = l->begin;
    if (t) {
        l->begin = atomic_load(&t->next);
    } else {
        atomic_store(&l->locked, 0);
    }
    unlock(&l->l);

    if (t) { _taskready(t); }
}

void
qrwlockinit(QRWLock *l)
{
    lockinit(&l->l);
    l->locked = 0;
    l->rwait = 0;
    l->rbegin = nil;
    l->rend = nil;
    l->wbegin = nil;
    l->wend = nil;
}

void
qrlock( QRWLock *l )
{
    ulong e;

    lock(&l->l);
    if ((e = l->locked) == (ulong)-1) {
        /* someone is writing */
        Task *t = _taskdequeue();

        atomic_store(&t->next, nil);
        if (l->rbegin) {
            atomic_store(&((Task *)l->rend)->next, t);
        } else {
            l->rbegin = t;
        }
        l->rend = t;
        l->rwait++;
    } else {
        /* either unlocked or reading */
        e = ++l->locked;
        assert(e != (ulong)-1);
    }
    unlock(&l->l);

    if (e == (ulong)-1) { taskyield(); }
}

int
qtryrlock( QRWLock *l )
{
    ulong e;

    lock(&l->l);
    if ((e = l->locked) != (ulong)-1) {
        e = ++l->locked;
        assert(e != (ulong)-1);
    }
    unlock(&l->l);

    return (e != (ulong)-1);
}

void
qrunlock( QRWLock *l )
{
    Task *revive = nil;

    lock(&l->l);
    if (--l->locked == 0) {
        if (l->wbegin) {
            revive = l->wbegin;
            l->wbegin = atomic_load(&revive->next);
            l->locked = (ulong)-1;
        }
    }
    unlock(&l->l);

    if (revive) { _taskready(revive); }
}

void
qwlock( QRWLock *l )
{
    ulong e;

    lock(&l->l);
    if ((e = l->locked) == 0) {
        /* no one is reading or writing */
        l->locked = (ulong)-1;
    } else {
        /* reading or writing is going on */
        Task *t = _taskdequeue();

        atomic_store(&t->next, nil);
        if (l->wbegin) {
            atomic_store(&((Task *)l->wend)->next, t);
        } else {
            l->wbegin = t;
        }
        l->wend = t;
    }
    unlock(&l->l);

    if (e != 0) { taskyield(); }
}

int
qtrywlock( QRWLock *l )
{
    ulong e;

    lock(&l->l);
    if ((e = l->locked) == 0) {
        l->locked = (ulong)-1;
    }
    unlock(&l->l);

    return (e == 0);
}

void
qwunlock( QRWLock *l )
{
    Task *revive = nil;
    ulong numr = 0;

    lock(&l->l);
    if (l->wbegin) {
        /* prefer writers to readers */
        revive = l->wbegin;
        numr = 1;
        l->wbegin = atomic_load(&revive->next);
    } else if (l->rbegin) {
        /* when reviving readers, revive all of them */
        revive = l->rbegin;
        numr = l->rwait;

        l->rbegin = nil;
        l->rend = nil;
        l->rwait = 0;

        l->locked = numr;
    }
    unlock(&l->l);

    while (numr-- > 0) {
        assert(revive);
        _taskready(revive);
        revive = atomic_load(&revive->next);
    }
}
