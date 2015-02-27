#include <u.h>
#include <libc.h>
#include <multitask.h>
#include "multitask-impl.h"

#include <signal.h>
#include <pthread.h>
#include <semaphore.h>

struct Tls
{
    Task *cur;
    Task *ready;
    _Atomic(Task *) readyend;
    Task readystub;

    uint ntasks;
    bool popped;
    sem_t sem;
    sigset_t oldsigs;
    jmp_buf ptctx;
};

static thread_local Tls *tasks;

noreturn void
_taskstart( Task *t )
{
    t->fn(t->arg);
    taskexit();
}

static inline bool
enqueue( Task *t )
{
    Task *p;
    bool sig;

    atomic_store(&t->next, nil);
    p = atomic_exchange(&t->tls->readyend, t);
    sig = (uintptr)p & 1;
    p = (Task *)((uintptr)p & ~(uintptr)1);
    atomic_store(&p->next, t);

    return sig;
}

void
_taskready( Task *t )
{
    if (enqueue(t)) {
        int r = sem_post(&t->tls->sem);
        assert(r == 0 && "sem_post failing == implementation error");
    }
}

Task *
_taskdequeue( void )
{
    assert(!tasks->popped && "_taskdequeue() called twice on the same task");
    tasks->popped = true;
    return tasks->cur;
}

void
_taskundequeue( Task *t )
{
    (void)t;
    assert(tasks->popped && "_taskundequeue() called before _taskdequeue()");
    assert(t == tasks->cur && "_taskundequeue() called with wrong task");
    tasks->popped = false;
}

#if 0
/* This is unnecessary simply because we don't want to use signals, however it
 * has been properly integrated into everything that technically needs it so it
 * could potentially be useful some day. */

static sigset_t allsigs;

static void
allsigsinit( void )
{
    int e = sigfillset(&allsigs);
    assert(e == 0);
}

void
_threadblocksigs( void )
{
    static pthread_once_t oncesigs = PTHREAD_ONCE_INIT;
    int e;

    pthread_once(&oncesigs, allsigsinit);

    e = pthread_sigmask(SIG_SETMASK, &allsigs, &tasks->oldsigs);
    assert(e == 0);
}

void
_threadunblocksigs( void )
{
    int e = pthread_sigmask(SIG_SETMASK, &tasks->oldsigs, nil);
    assert(e == 0);
}
#else
void _threadblocksigs(void) { }
void _threadunblocksigs(void) { }
#endif

static inline void
inittask( Task *t,
          void *mptr,
          void (*fn)(void *),
          void *arg,
          void *stack,
          size_t stacksize )
{
    atomic_init(&t->next, nil);
    t->stacksize = stacksize;
    t->stack = stack;
    t->dead = false;
    t->tls = tasks;
    t->fn = fn;
    t->arg = arg;
    t->mem = mptr;
}

static inline Task *
alloctask( void (*fn)(void *),
           void *arg,
           size_t stacksize,
           bool nostack )
{
    Task *t;
    size_t ssz = 0;
    byte *mem;

    if (!nostack) {
        if (stacksize < MINSTACKSIZE) { stacksize = MINSTACKSIZE; }
        stacksize = (stacksize + 63U) & ~63U;
        ssz = stacksize;

        /* overflow check */
        if ((size_t)-1 - stacksize < sizeof(Task)) { return nil; }
    }

    mem = aligned_alloc(64, ssz + sizeof(Task));
    if (!mem) { return nil; }

    t = (Task *)&mem[ssz];
    inittask(t, mem, fn, arg, &mem[ssz], stacksize);

    /* stack should be aligned to 64-byte boundary */
    assert(((uintptr)t->stack & (uintptr)63U) == 0);

    return t;
}

static inline void
freetask( Task *t )
{
    free(t->mem);
}

static inline Task *
rrtask( void )
{
    Task *q, *c = tasks->cur;
    bool calive = !c->dead && !tasks->popped;

    /* really fast single task path */
    if (calive && tasks->ntasks == 1) { return nil; }

    q = tasks->ready;
    while (1) {
        Task *n;

        n = atomic_load(&q->next);
        if (q == &tasks->readystub) {
            /* we got the stub element so look at the next one */
            if (!n) {
                /* no elements in queue but we're still good to go */
                if (calive) { return nil; }

                /* only the stub element is left in the queue so wait. */
                goto popwait;
            }
            tasks->ready = n;
            q = n;
            n = atomic_load(&n->next);
        }

        if (n) {
            /* popped an element from the queue */
            tasks->ready = n;
            goto trypopq;
        }

        if (q != atomic_load(&tasks->readyend)) {
            /* Time delay where readyend has been swapped but next hasn't yet.
             * This is a good time to spin as we cannot pop the single element
             * left in the queue without letting this insertion finish */
            _taskspin();
            continue;
        }

        /* push back stub element */
        enqueue(&tasks->readystub);

        /* try to extract element again */
        n = atomic_load(&q->next);
        if (n) {
            tasks->ready = n;
            goto trypopq;
        }

        if (calive) {
            /* no other tasks in queue but we're ready fast-path */
            return nil;
        }

        /* still don't have an element after all that: wait */
popwait:
        {
            Task *w = (Task *)((uintptr)q | 1);
            Task *a = q;
            if (atomic_compare_exchange_weak(&tasks->readyend, &a, w)) {
                while (sem_wait(&tasks->sem) != 0) {
                    assert(errno == EINTR && "sem_wait did what?!");
                }
            }
            continue;
        }

trypopq:
        /* if q is dead, free it and try again */
        if (q->dead) {
            assert(q != &tasks->readystub);
            freetask(q);
            q = tasks->ready;
            continue;
        }
        /* if c was not popped or is dead, reinsert it into the list. In the
         * first case so that it can be rescheduled and in the latter case so
         * the above code can cull it once we jump away from its stack */
        if (!tasks->popped || c->dead) { enqueue(c); }
        tasks->popped = false;
        return q;
    }
}

static void *
threadstart( void *arg )
{
    Tls tls;
    Task *t = arg;
    int r;

    /* init tls */
    tasks = &tls;
    tls.cur = t;
    tls.ready = &tls.readystub;
    atomic_init(&tls.readyend, &tls.readystub);
    atomic_init(&tls.readystub.next, nil);
    tls.readystub.tls = &tls;
    tls.readystub.dead = false;
    tls.ntasks = 1;
    tls.popped = false;
    r = sem_init(&tls.sem, 0, 0);
    assert(r == 0 && "sem_init failed; fix your libpthread");

    /* use the OS-assigned stack */
    t->stack = &tls;
    t->tls = &tls;

    /* switch to new task */
    if (setjmp(tls.ptctx) == 0) {
        _taskstart(t);
    }
    /* after the last exit, we go here */

    /* reap all dead tasks */
    t = tls.ready;
    while (t) {
        Task *n = atomic_load(&t->next);
        if (t != &tls.readystub) { freetask(t); }
        t = n;
    }

    /* should be a nop barring a terrible libc */
    r = sem_destroy(&tls.sem);
    assert(r == 0 && "sem_destroy failed; murder your libpthread");

    return nil;
}

typedef struct Mainargs Mainargs;

struct Mainargs
{
    int argc;
    char **argv;
};

static void
mainstart( void *arg )
{
    Mainargs *a = arg;
    threadmain(a->argc, a->argv);
}

int
main( int argc,
      char *argv[] )
{
    static byte altstack[ALTSTACKSIZE];
    static const stack_t as = {
        .ss_sp = altstack,
        .ss_flags = 0,
        .ss_size = sizeof(altstack)
    };

    Mainargs arg = { argc, argv };
    Task t;

    /* we need to set up an alternative stack for signal handlers as they would
     * otherwise clobber the shit out of everything with small stacks */
    if (sigaltstack(&as, nil) != 0) { assert(!"sigaltstack shouldn't fail"); }

    /* the main thread has infinite stack, so just give it arbitrary size */
    inittask(&t, nil, mainstart, &arg, nil, ((size_t)-1) / 2);
    threadstart(&t);

    /* when main returns it will call exit() but by calling pthread_exit
     * instead we will allow all threads to keep on living after main returns.
     * This way, you need to manually call exit() to kill the pid */
    pthread_exit(nil);
    return 0; /* unreached */
}

int
threadcreate( void (*fn)(void *),
              void *arg,
              size_t stacksize )
{
    Task *t;
    pthread_attr_t attr;
    pthread_t pt;
    int e;

    /* calculate the actual stack size */
    stacksize += sizeof(Tls) + 64;
    if (stacksize < PTHREAD_STACK_MIN) { stacksize = PTHREAD_STACK_MIN; }

    /* allocate a stackless task */
    t = alloctask(fn, arg, stacksize, true);
    if (!t) { return -1; }

    /* give the pthread proper attributes, including adjusted stack size */
    if (pthread_attr_init(&attr) != 0) { goto errout; }
    if (pthread_attr_setstacksize(&attr, t->stacksize) != 0 ||
        pthread_attr_setguardsize(&attr, 0) != 0 ||
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
        goto attrout;
    }

    e = pthread_create(&pt, &attr, threadstart, t);

    /* clean up */
    pthread_attr_destroy(&attr);
    if (e != 0) { goto errout; }

    return 0; /* TODO: generate thread id */

attrout:
    pthread_attr_destroy(&attr);
errout:
    freetask(t);
    return -1;
}

int
taskcreate( void (*fn)(void *),
            void *arg,
            size_t stacksize )
{
    Task *t = alloctask(fn, arg, stacksize, false);
    if (!t) { return -1; }

    t->tls->ntasks++;

    _tasksetjmp(t->ctx, t->stack, t);
    _taskready(t);

    return 0; /* TODO: generate task id */
}

size_t
taskstack( void )
{
    byte c = 0;

    return tasks->cur->stacksize - (size_t)((byte *)tasks->cur->stack - &c);
}

void
taskyield( void )
{
    Task *t = rrtask();

    /* rrtask will return nil if there's no need to switch contexts */
    if (t) {
        Task *c = tasks->cur;

        /* swap contexts */
        fegetenv(&c->fctx);
        if (setjmp(c->ctx) == 0) {
            tasks->cur = t;
            longjmp(t->ctx, 1);
        } else {
            fesetenv(&c->fctx);
        }
    }
}

noreturn void
taskexit( void )
{
    Task *c = tasks->cur;

    /* mark thread as dead so it will be culled later */
    c->dead = true;

    if (--tasks->ntasks == 0) {
        /* push self to queue so the OS thread can reap us */
        enqueue(c);
        /* jump back to the OS thread that spawned us */
        longjmp(tasks->ptctx, 1);
    }
    /* perform a non-returning yield */
    taskyield();

    assert(!"taskyield() should not return in taskexit()");
    abort();
}
