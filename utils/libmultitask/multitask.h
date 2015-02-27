AUTOLINK(multitask)

#include <pthread.h>
#include <stdatomic.h>

#ifndef thread_local
#define thread_local _Thread_local
#endif

/*
 * Threading
 */

#define MINSTACKSIZE 128

void threadmain(int argc, char *argv[]);
int threadcreate(void (*fn)(void *), void *arg, size_t stacksize);
int taskcreate(void (*fn)(void *), void *arg, size_t stacksize);
size_t taskstack(void);
void taskyield(void);
noreturn void taskexit(void);

/*
 * Reference counting
 */

typedef struct Ref Ref;

struct Ref
{
    atomic_ulong refs;
};

void refinit(Ref *r);
void ref(Ref *r);
ulong unref(Ref *r);

/*
 * Threaded locks
 */

typedef struct Lock Lock;
typedef struct RWLock RWLock;

struct Lock
{
    pthread_mutex_t pmtx;
};

struct RWLock
{
    pthread_rwlock_t prwl;
};

#define LOCKINIT {PTHREAD_MUTEX_INITIALIZER}
#define RWLOCKINIT {PTHREAD_RWLOCK_INITIALIZER}

void lockinit(Lock *l);
void lock(Lock *l);
bool trylock(Lock *l);
void unlock(Lock *l);

void rwlockinit(RWLock *l);
void rlock(RWLock *l);
bool tryrlock(RWLock *l);
void runlock(RWLock *l);
void wlock(RWLock *l);
bool trywlock(RWLock *l);
void wunlock(RWLock *l);

/*
 * Task-aware locks
 */

typedef struct QLock QLock;
typedef struct QRWLock QRWLock;

struct QLock
{
    Lock l;
    atomic_int locked;
    void *begin, *end;
};

struct QRWLock
{
    Lock l;
    ulong locked;
    ulong rwait;
    void *rbegin, *rend;
    void *wbegin, *wend;
};

#define QLOCKINIT {LOCKINIT, ATOMIC_VAR_INIT(0), nil, nil}
#define QRWLOCKINIT {LOCKINIT, 0, 0, nil, nil, nil, nil}

void qlockinit(QLock *l);
void qlock(QLock *l);
int qtrylock(QLock *l);
void qunlock(QLock *l);

void qrwlockinit(QRWLock *l);
void qrlock(QRWLock *l);
int qtryrlock(QRWLock *l);
void qrunlock(QRWLock *l);
void qwlock(QRWLock *l);
int qtrywlock(QRWLock *l);
void qwunlock(QRWLock *l);

/*
 * Task queue
 */
typedef struct Queue Queue;

struct Queue
{
    void *begin, *end;
    Lock lock;
};

void queueinit(Queue *q);
void qwait(Queue *q);
ulong qwake(Queue *q, ulong n);

/*
 * Channel communication
 */

struct LibmultitaskChanInternalWaiter;
struct LibmultitaskChanInternalAltState;

typedef struct Chan Chan;

struct Chan
{
    uint8 type;

    /* buffer (implemented as a queue) */
    uint16 elemsz;
    uint32 nelem;
    union {
        void *buf;
        _Atomic(uint32) count;
    };
    _Atomic(uint64) sendx, recvx;

    /* queueing which must be protected by a lock */
    struct LibmultitaskChanInternalQueue {
        _Atomic(struct LibmultitaskChanInternalWaiter *) first, last;
    } sendq, recvq;

    /* resource management */
    atomic_bool closed;
    ulong refs;
    Lock lock;

    /* index for time queue */
    size_t tqi;
};

int chaninit(Chan *c, size_t elemsz, size_t nelem);
Chan *channew(size_t elemsz, size_t nelem);
void chanfree(Chan *chan);
int chansend(Chan *c, const void *v);
int chansendnb(Chan *c, const void *v);
int chanrecv(Chan *c, void *v);
int chanrecvnb(Chan *c, void *v);

enum {
    CHANNOP,
    CHANSEND,
    CHANRECV,
    CHANEND,
    CHANENDNB,
};

typedef struct Alt Alt;

struct Alt
{
    Chan *c;
    union { void *v; const void *cv; };
    int op;

    /* implementation stuff */
    struct {
        uint sorder; /* selection order  */

        struct LibmultitaskChanInternalWaiter {
            struct LibmultitaskChanInternalWaiter *prev, *next;
            struct LibmultitaskChanInternalAltState *state;
            bool popped;
            union { void *v; const void *cv; };
        } waiter;
    } impl;
};

int alt(Alt *alts);

/*
 * Timeout channels
 */

int tchaninit(Chan *c);
Chan *tchannew(void);
void tchanset(Chan *c, uvlong nsec);
int tchansleep(Chan *c, uvlong nsec);

/*
 * IO Channels
 */

typedef ssize_t (*IOFunc)(void *args, atomic_int *cancel);

int iochaninit(Chan *c, size_t extrastack);
Chan *iochannew(size_t extrastack);
void iocall(Chan *c, IOFunc proc, const void *args, size_t argsz);
ssize_t iocancel(Chan *c);

void ioopen(Chan *c, const char *pathname, int flags, mode_t mode);
void ioread(Chan *c, int fd, void *buf, size_t count);
void ioreadn(Chan *c, int fd, void *buf, size_t count);
void iowrite(Chan *c, int fd, const void *buf, size_t count);
void iowriten(Chan *c, int fd, const void *buf, size_t count);
void ionsleep(Chan *c, uvlong ns, uvlong *left);
void iowait(Chan *c, pid_t pid, int *status, int options);

/*
 * Waiting on multiple channels
 */


/*
 * Rendezvous synchronization points
 */

void *rendez(void *tag, void *value);

/*
 * Atomic rendezvous points
 */

typedef struct ARendez ARendez;

struct ARendez
{
    _Atomic(void *) task;
};

void arendezinit(ARendez *r);
void *arendez(ARendez *r, void *value);
