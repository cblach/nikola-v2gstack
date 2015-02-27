#include <u.h>
#include <libc.h>
#include <multitask.h>
#include "multitask-impl.h"

static TimeQueue timeq;

static uvlong
timecb( Chan *c )
{
    chansendnb(c, nil);
    return 0;
}

static int
init( void )
{
    static atomic_int inited = ATOMIC_VAR_INIT(0);
    static Lock initlock = LOCKINIT;

    if (atomic_load(&inited) == 0) {
        lock(&initlock);
        if (atomic_load(&inited) == 0) {
            if (_tqinit(&timeq, timecb) != 0) {
                unlock(&initlock);
                return -1;
            }
            atomic_store(&inited, 1);
        }
        unlock(&initlock);
    }

    return 0;
}

int
tchaninit( Chan *c )
{
    if (init() != 0) { return -1; }
    _chaninit(c, 0, 1, nil, false, CTTIME);
    return _tqalloc(&timeq);
}

Chan *
tchannew( void )
{
    Chan *c;

    if (init() != 0) { return nil; }

    c = malloc(sizeof(Chan));
    if (!c) { return nil; }

    _chaninit(c, 0, 1, nil, true, CTTIME);
    if (_tqalloc(&timeq) != 0) {
        free(c);
        return nil;
    }

    return c;
}

void
_tchanfree( Chan *c )
{
    _tqremove(&timeq, c, true, false);
}

void
tchanset( Chan *c,
          uvlong nsec )
{
    _tqinsert(&timeq, c, nsec, true);
}

int
tchansleep( Chan *c,
            uvlong nsec )
{
    tchanset(c, nsec);
    return chanrecv(c, nil);
}
