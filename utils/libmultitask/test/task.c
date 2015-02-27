#include <u.h>
#include <libc.h>
#include <multitask.h>

int c = 0;
void *rend = (void *)0xdeadbeef;
void *ra = (void *)0x12345678;
void *rb = (void *)0x87654321;
ARendez arend;

static void
thrd( void *arg )
{
    (void)arg;
    sleep(3);
    fprint(1, "thrd: %p %p\n", rb, rendez(rend, ra));
    fprint(1, "thrd: %p %p\n", rb, arendez(&arend, ra));
}

static void
t1( void *arg )
{
    float f = 1.0f;
    (void)arg;
    while (c < 10) {
        fprint(1, "%d\n", (int)f);
        c++;
        taskyield();
    }
}

static void
t2( void *arg )
{
    float f = 2.0f;
    (void)arg;
    while (c < 10) {
        fprint(1, "%d\n", (int)f);
        c++;
        if (c >= 5) {
            fprint(1, "t2: %p %p\n", ra, rendez(rend, rb));
            fprint(1, "t2: %p %p\n", ra, arendez(&arend, rb));
            sleep(1);
            fprint(1, "exiting\n");
        }
        taskyield();
    }
}

static void
t3( void *arg )
{
    float f = 3.0f;
    (void)arg;
    while (c < 10) {
        fprint(1, "%d\n", (int)f);
        c++;
        taskyield();
    }
}

void
threadmain( int argc,
            char *argv[] )
{
    (void)argc;
    (void)argv;

    arendezinit(&arend);
    taskcreate(t1, nil, 8 * 1024);
    taskcreate(t2, nil, 8 * 1024);
    taskcreate(t3, nil, 8 * 1024);
    threadcreate(thrd, nil, 8 * 1024);
}
