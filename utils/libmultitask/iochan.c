#include <u.h>
#include <libc.h>
#include <multitask.h>
#include "multitask-impl.h"

#include <semaphore.h>
#include <pthread.h>
#include <signal.h>

typedef struct IOBegin IOBegin;
typedef struct IOThread IOThread;

struct IOBegin
{
    Chan *c;
    Task *t;
};

struct IOThread
{
    struct {
        _Atomic(uint32) lap;
        ssize_t val;
    } buf;

    /* state stuff */
    atomic_int state;
    volatile uvlong timeout;
    Task *volatile canceler;
    ARendez killrend;
    sem_t sem;

    /* itc */
    Task *volatile task;
    volatile IOFunc proc;
    byte argbuf[128];

    /* pthread stuff */
    pthread_t ptid;
};

enum {
    WAITING = -1,
    RUNNING = 0, /* doubles as cancel atomic */
    CANCELED = 1,
    MORIBUND = 2,
};

enum {
    DEFTIMEOUT = 1000,
    SIGCANCEL = SIGUSR1,
};

static sigset_t sigs;
static TimeQueue cancelq;

static void
iothread( void *arg )
{
    IOThread io;
    Chan calloc;
    Chan *c;

    {
        IOBegin *iobeg = arg;
        int r;

        if (!iobeg->c) { iobeg->c = &calloc; }
        c = iobeg->c;
        _chaninit(c, sizeof(ssize_t), 1, &io, false, CTIO);

        /* initialize everything and dequeue ourselves */
        atomic_init(&io.state, WAITING);
        arendezinit(&io.killrend);
        io.timeout = 0;
        io.canceler = nil;
        io.task = _taskdequeue();
        io.proc = nil;
        io.ptid = pthread_self();

        /* according to posix these can't fail lest you give bad args */
        r = sem_init(&io.sem, 0, 0);
        assert(r == 0 && "sem_init failed in iothread");
        r = pthread_sigmask(SIG_SETMASK, &sigs, nil);
        assert(r == 0 && "pthread_sigmask failed in iothread");

        /* "rendezvous" the creating task */
        _taskready(iobeg->t);
    }

    while (1) {
        IOFunc proc;
        ssize_t r;

        /* yield until we get a command */
        taskyield();

        /* fetch and run proc */
        proc = io.proc;
        if (!proc) { break; }
        r = proc(io.argbuf, &io.state);

        /* get ready for another round */
        io.task = _taskdequeue();
        switch (atomic_exchange(&io.state, WAITING)) {
            case MORIBUND:
                /* this looks racy but since iocall doesn't actually tell you
                 * whether or not it was successful it just ensures that no one
                 * screws with our Task pointer after this */
                if (atomic_exchange(&io.state, MORIBUND) == WAITING) {
                    _taskundequeue(io.task);
                }
                proc = nil;
                /* fall through */
            case CANCELED:
                /* we must send before rendezvousing with the canceler */
                if (proc) { chansendnb(c, &r); }

                /* this request was cancelled so someone is waiting for us */
                while (sem_wait(&io.sem) != 0) {
                    assert(errno == EINTR && "sem_wait shouldn't fail!");
                }
                _taskready(io.canceler);
                break;

            default:
                /* We send non-blocking for a couple of reasons. First off it
                 * doesn't even make sense to block here. Second, since we've
                 * dequeue'd ourselves already, blocking would be illegal */
                chansendnb(c, &r);
                break;
        }
        if (!proc) { break; }
    }

    /* on sane systems this is a nop */
    sem_destroy(&io.sem);

    /* since returning from this function will free the IOThread, we need to
     * control it gracefully */
    arendez(&io.killrend, nil);
}

static uvlong
cancelcb( Chan *c )
{
    IOThread *io = c->buf;

    /* the basic idea here is to do exponential backoff signalling until the
     * cancellation is successful */
    if (atomic_load(&io->state) != WAITING) {
        pthread_kill(io->ptid, SIGCANCEL);
        return io->timeout *= 2;
    }

    return 0;
}

static void
xsig( int sig )
{
    (void)sig;
    /* empty because signals can go fuck a goat */
}

static int
init( void )
{
    static atomic_int inited = ATOMIC_VAR_INIT(0);
    static Lock initlock = LOCKINIT;

    if (atomic_load(&inited) == 0) {
        int r = 0;

        lock(&initlock);
        if (atomic_load(&inited) == 0) {
            struct sigaction sa;

            /* create a sigset with only SIGCANCEL unblocked */
            if ((r = sigfillset(&sigs)) != 0) { goto errout; }
            if ((r = sigdelset(&sigs, SIGCANCEL)) != 0) { goto errout; }

            /* register a dummy signal handler */
            sa.sa_handler = xsig;
            sa.sa_flags = SA_ONSTACK;
            if ((r = sigfillset(&sa.sa_mask)) != 0) { goto errout; }
            if ((r = sigaction(SIGCANCEL, &sa, nil)) != 0) { goto errout; }

            /* init time queue (last because it's stateful) */
            if ((r = _tqinit(&cancelq, cancelcb)) != 0) { goto errout; }

            atomic_store(&inited, 1);
        }
errout:
        unlock(&initlock);

        if (r) { return -1; }
    }

    return 0;
}

static Chan *
newio( Chan *c,
       size_t extrastack )
{
    IOBegin iobeg;

    /* initialize signal stuff */
    if (init() != 0) { return nil; }
    if (_tqalloc(&cancelq) != 0) { return nil; }

    /* dequeue self and wait for the created thread to put us back */
    iobeg.c = c;
    iobeg.t = _taskdequeue();

    /* create the thread. The thread will init the channel */
    if (threadcreate(iothread, &iobeg, 1024 + extrastack) < 0) {
        /* undequeue because the thread wasn't created */
        _taskundequeue(iobeg.t);
        _tqremove(&cancelq, c, true, false);
        return nil;
    }

    /* wait for the thread to be created and initialized */
    taskyield();

    assert(iobeg.c);
    return iobeg.c;
}

int
iochaninit( Chan *c,
            size_t extrastack )
{
    return newio(c, extrastack) ? 0 : -1;
}

Chan *
iochannew( size_t extrastack )
{
    return newio(nil, extrastack);
}

static inline bool
_iocancel( Chan *c,
           int state )
{
    IOThread *io = c->buf;
    int r = RUNNING;

    if (!atomic_compare_exchange_strong(&io->state, &r, state)) {
        return false;
    }

    /* synchronize with the io thread */
    io->canceler = _taskdequeue();
    r = sem_post(&io->sem);
    assert(r == 0 && "sem_post shouldn't fail!");

    /* try to kill the current call */
    pthread_kill(io->ptid, SIGCANCEL);
    /* do the timeout dance */
    io->timeout = DEFTIMEOUT;
    _tqinsert(&cancelq, c, DEFTIMEOUT, false);
    taskyield();
    _tqremove(&cancelq, c, (state == MORIBUND), false);

    return true;
}

void
_iochanfree( Chan *c )
{
    IOThread *io = c->buf;

    /* The channel lock is acquired here so to avoid races we need to unlock it
     * first. However upon return we're expected to hold the lock.
     * What we want to avoid is:
     * - the proc has run (or is running)
     * - we acquire the lock
     * - someone else cancels the proc before us
     * - chansendnb cannot acquire the lock because we hold it
     */
    unlock(&c->lock);
    while (!_iocancel(c, MORIBUND)) {
        int r = WAITING;
        if (atomic_compare_exchange_strong(&io->state, &r, MORIBUND)) {
            /* in here we don't need to release the lock, as the iothread will
             * not try to chansendnb anything */
            io->proc = nil;
            _taskready(io->task);
            /* remove from cancellation queue. If we had successfully canceled
             * instead it would have been done for us, but we didn't. */
            _tqremove(&cancelq, c, true, false);
            break;
        }
    }
    lock(&c->lock);
    /* finally we can free the IOThread */
    arendez(&io->killrend, nil);
    /* don't try to free this buffer. It's on the stack of the iothread */
    c->buf = nil;
}

/* TODO: When musl gets reliable cancellation, use that */
ssize_t
iocancel( Chan *c )
{
    ssize_t ret = 0;

    _iocancel(c, CANCELED);
    if (chanrecvnb(c, &ret) != 1) { return 0; }
    return ret;
}

void
iocall( Chan *c,
        IOFunc proc,
        const void *args,
        size_t argsz )
{
    IOThread *io = c->buf;
    Task *t;
    int r = WAITING;

    assert(argsz <= sizeof(io->argbuf));

    /* only one task may use the iochan at a time. Not properly managing this
     * yourself means you're doing something wrong. */
    if (!atomic_compare_exchange_strong(&io->state, &r, RUNNING)) { return; }

    /* save proc and parameters */
    io->proc = proc;
    if (argsz > 0) { memcpy(io->argbuf, args, argsz); }

    /* when waiting the iothread simply pops its only task. We put it back */
    t = io->task;
    assert(t);
    _taskready(t);
}

typedef struct IOOpen IOOpen;
typedef struct IOOp IOOp;
typedef struct IONSleep IONSleep;
typedef struct IOWait IOWait;

struct IOOpen
{
    const char *pathname;
    int flags;
    mode_t mode;
};

struct IOOp
{
    int rdwr;
    int fd;
    union {
        void *buf;
        const void *cbuf;
    };
    size_t count;
    off_t offset;
};

struct IOWrite
{
    int fd;
    const void *buf;
    size_t count;
    off_t offset;
};

struct IONSleep
{
    uvlong ns;
    uvlong *left;
};

struct IOWait
{
    pid_t pid;
    int *status;
    int options;
};

static ssize_t
xioopen( void *args,
         atomic_int *cancel )
{
    IOOpen *a = args;
    int r = (a->flags & O_CREAT
#ifdef O_TMPFILE
            || (a->flags & O_TMPFILE) == O_TMPFILE
#endif
            ) ?
        open(a->pathname, a->flags, a->mode) :
        open(a->pathname, a->flags);
    (void)cancel;
    return (r < 0) ? (-errno) : r;
}

static ssize_t
xioop( void *args,
       atomic_int *cancel )
{
    IOOp *a = args;
    ssize_t r = a->rdwr ?
        write(a->fd, a->cbuf, a->count) :
        read(a->fd, a->buf, a->count);
    (void)cancel;
    return (r < 0) ? (-errno) : r;
}

static ssize_t
xioopn( void *args,
        atomic_int *cancel )
{
    IOOp *a = args;
    size_t n = 0;

    while (!atomic_load(cancel) && n < a->count) {
        ssize_t r = a->rdwr ?
            write(a->fd, (const char *)a->cbuf + n, a->count - n) :
            read(a->fd, (char *)a->buf + n, a->count - n);
        if (r < 0) {
            if (errno == EINTR) { continue; }
            return -errno;
        }
        if (r == 0) { break; }
        n += (size_t)r;
    }

    return (ssize_t)n;
}

static ssize_t
xionsleep( void *args,
           atomic_int *cancel )
{
    IONSleep *a = args;
    uvlong r = nsleep(a->ns);
    (void)cancel;
    if (a->left) { *a->left = r; }
    return (r == 0) ? 0 : (-1);
}

static ssize_t
xiowait( void *args,
         atomic_int *cancel )
{
    IOWait *a = args;
    pid_t r = waitpid(a->pid, a->status, a->options);
    (void)cancel;
    return (r < 0) ? (-errno) : r;
}

void
ioopen( Chan *c,
        const char *pathname,
        int flags,
        mode_t mode )
{
    IOOpen a = {
        .pathname = pathname,
        .flags = flags,
        .mode = mode
    };
    iocall(c, xioopen, &a, sizeof(a));
}

void
ioread( Chan *c,
        int fd,
        void *buf,
        size_t count )
{
    IOOp a = {
        .rdwr = 0,
        .fd = fd,
        .buf = buf,
        .count = count,
    };
    iocall(c, xioop, &a, sizeof(a));
}

void
ioreadn( Chan *c,
         int fd,
         void *buf,
         size_t count )
{
    IOOp a = {
        .rdwr = 0,
        .fd = fd,
        .buf = buf,
        .count = count,
    };
    iocall(c, xioopn, &a, sizeof(a));
}

void
iowrite( Chan *c,
         int fd,
         const void *buf,
         size_t count )
{
    IOOp a = {
        .rdwr = 1,
        .fd = fd,
        .cbuf = buf,
        .count = count,
    };
    iocall(c, xioop, &a, sizeof(a));
}

void
iowriten( Chan *c,
          int fd,
          const void *buf,
          size_t count )
{
    IOOp a = {
        .rdwr = 1,
        .fd = fd,
        .cbuf = buf,
        .count = count,
    };
    iocall(c, xioopn, &a, sizeof(a));
}

void
ionsleep( Chan *c,
          uvlong ns,
          uvlong *left )
{
    IONSleep a = {
        .ns = ns,
        .left = left
    };
    if (left) { *left = ns; }
    iocall(c, xionsleep, &a, sizeof(a));
}

void
iowait( Chan *c,
        pid_t pid,
        int *status,
        int options )
{
    IOWait a = {
        .pid = pid,
        .status = status,
        .options = options
    };
    iocall(c, xiowait, &a, sizeof(a));
}
