#include <u.h>
#include <libc.h>
#include <multitask.h>

Chan c1, c2, c3;
atomic_int x = ATOMIC_VAR_INIT(123);

#define OK(x) \
    do { \
        int __e; \
        if ((__e = (x)) != 1) { \
            fprint(2, #x " returned %d\n", __e); \
            abort(); \
        } \
    } while (0)

static inline int
okn( int x,
     const char *str )
{
    if (x < 0) {
        fprint(2, "%s failed\n", str);
        abort();
    }
    return x;
}
#define OKN(x) okn((x), #x)

#define RECV(c, v) \
    do { \
        OK(chanrecv((c), (v))); \
        fprint(1, "%s recv: %d\n", __func__, *(int *)(v)); \
        fflush(stdout); \
    } while (0)

#define SEND(c, v) \
    do { \
        fprint(1, "%s send: %d\n", __func__, *(int *)(v)); \
        fflush(stdout); \
        OK(chansend((c), (v))); \
    } while (0)

static ssize_t
xiosleep( void *args,
          atomic_int *cancel )
{
    struct timespec ts;
    uvlong ns = *(uvlong *)args;
    int r;

    ts.tv_sec = (time_t)(ns / 1000000000);
    ts.tv_nsec = (long)(ns % 1000000000);
    r = nanosleep(&ts, nil);
    assert(atomic_load(cancel) != 0);
    return (r < 0) ? (-errno) : r;
}

static void
iosleep( Chan *c,
         uvlong ns )
{
    iocall(c, xiosleep, &ns, sizeof(ns));
}

static void
sendtask( void *arg )
{
    Chan *c = arg;
    int y = atomic_fetch_add(&x, 1);

    sleep(5);
    SEND(c, &y);
}

static byte buf[1024];

void
threadmain( int argc,
            char *argv[] )
{
    Chan tc;
    Chan ioc;
    Alt alts[3];
    ssize_t sr;
    int fd, i = ~0;

    (void)argc;
    (void)argv;

    OKN(chaninit(&c1, sizeof(int), 0));
    OKN(chaninit(&c2, sizeof(int), 1));
    OKN(chaninit(&c3, sizeof(int), 32));
    OKN(tchaninit(&tc));
    OKN(iochaninit(&ioc, 0));

    OKN(threadcreate(sendtask, &c1, 8 * 1024));

    RECV(&c1, &i);

    OKN(threadcreate(sendtask, &c2, 8 * 1024));
    sleep(3);
    OKN(threadcreate(sendtask, &c2, 8 * 1024));
    sleep(3);
    RECV(&c2, &i);
    RECV(&c2, &i);

    for (i = 0; i < 4; ++i) {
        OKN(threadcreate(sendtask, &c3, 8 * 1024));
    }
    sleep(7);
    RECV(&c3, &i);
    RECV(&c3, &i);
    RECV(&c3, &i);
    RECV(&c3, &i);

    alts[0].c = &tc;
    alts[0].v = nil;
    alts[0].op = CHANRECV;
    alts[1].c = &c1;
    alts[1].v = &i;
    alts[1].op = CHANRECV;
    alts[2].op = CHANEND;
    OKN(threadcreate(sendtask, &c1, 8 * 1024));
    tchanset(&tc, (uvlong)3 * 1000000000);
    switch (OKN(alt(alts))) {
        case 0: fprint(1, "Timeout as expected\n"); break;
        case 1: fprint(1, "Unexpected recv\n");
        default:
            abort();
    }
    RECV(&c1, &i);

    ioopen(&ioc, "/etc/resolv.conf", O_RDONLY, 0);
    OK(chanrecv(&ioc, &sr));
    fd = (int)sr;
    fprint(1, "ioopen got fd %d\n", fd); fflush(stdout);
    if (fd < 0) { abort(); }
    ioread(&ioc, fd, buf, sizeof(buf));
    OK(chanrecv(&ioc, &sr));
    if (sr <= 0) {
        fprint(1, "Error reading /etc/resolv.conf: %s\n", strerror(-(int)sr));
        abort();
    } else {
        fprint(1, "(some) /etc/resolv.conf contents:\n%.*s\n", (int)sr, buf);
        fflush(stdout);
    }

    iosleep(&ioc, (uvlong)4 * 1000000000);
    tchanset(&tc, (uvlong)6 * 1000000000);
    alts[0].c = &tc;
    alts[0].v = nil;
    alts[0].op = CHANRECV;
    alts[1].c = &ioc;
    alts[1].v = nil;
    alts[1].op = CHANRECV;
    alts[2].op = CHANEND;
    sleep(2);
    iocancel(&ioc);
    switch (OKN(alt(alts))) {
        case 0: break;
        case 1:
            fprint(1, "iochan was not interrupted\n");
            abort();
    }
    fprint(1, "iochan appears to be cancelled\n"); fflush(stdout);

    exit(0);
}
