#include <u.h>
#include <libc.h>
#include <multitask.h>

#include <pthread.h>

void
lockinit(Lock *l)
{
    int r = pthread_mutex_init(&l->pmtx, nil);
    assert(r == 0 && "pthread_mutex_init failed");
}

void
lock(Lock *l)
{
    int r = pthread_mutex_lock(&l->pmtx);
    assert(r == 0 && "pthread_mutex_lock failed");
}

bool
trylock(Lock *l)
{
    int r = pthread_mutex_trylock(&l->pmtx);
    switch (r) {
        case 0: return true;
        case EBUSY: return false;
    }
    assert(!"pthread_mutex_trylock failed");
    return false;
}

void
unlock(Lock *l)
{
    int r = pthread_mutex_unlock(&l->pmtx);
    assert(r == 0 && "pthread_mutex_unlock failed");
}

void
rwlockinit(RWLock *l)
{
    int r = pthread_rwlock_init(&l->prwl, nil);
    assert(r == 0 && "pthread_rwlock_init failed");
}

void
rlock(RWLock *l)
{
    int r = pthread_rwlock_rdlock(&l->prwl);
    assert(r == 0 && "pthread_rwlock_rdlock failed");
}

bool
tryrlock(RWLock *l)
{
    int r = pthread_rwlock_tryrdlock(&l->prwl);
    switch (r) {
        case 0: return true;
        case EBUSY: return false;
    }
    assert(!"pthread_rwlock_tryrdlock failed");
    return false;
}

void
runlock(RWLock *l)
{
    int r = pthread_rwlock_unlock(&l->prwl);
    assert(r == 0 && "pthread_rwlock_(rd)unlock failed");
}

void
wlock(RWLock *l)
{
    int r = pthread_rwlock_wrlock(&l->prwl);
    assert(r == 0 && "pthread_rwlock_wrlock failed");
}

bool
trywlock(RWLock *l)
{
    int r = pthread_rwlock_trywrlock(&l->prwl);
    switch (r) {
        case 0: return true;
        case EBUSY: return false;
    }
    assert(!"pthread_rwlock_trywrlock failed");
    return false;
}

void
wunlock(RWLock *l)
{
    int r = pthread_rwlock_unlock(&l->prwl);
    assert(r == 0 && "pthread_rwlock_(wr)unlock failed");
}
