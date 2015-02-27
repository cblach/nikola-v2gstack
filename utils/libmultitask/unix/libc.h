#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <setjmp.h>
#include <fenv.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define nil ((void *)0)

#ifndef noreturn
#define noreturn _Noreturn
#endif

#ifndef thread_local
#define thread_local _Thread_local
#endif

typedef unsigned char byte;

typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long long uvlong;

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;
typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;

typedef uintptr_t uintptr;

static inline void *
xmalloc( size_t base,
         size_t extra )
{
    if ((size_t)-1 - base < extra) { return nil; }
    return malloc(base + extra);
}

static inline void *
xcalloc( size_t base,
         size_t nmemb,
         size_t msize )
{
    if (msize && nmemb > (size_t)-1 / msize) { return nil; }
    return xmalloc(base, msize * nmemb);
}

static inline uvlong
nsleep( uvlong ns )
{
#define NS 1000000000
    struct timespec left, ts = { .tv_sec = ns / NS, .tv_nsec = ns % NS };
    int r = nanosleep(&ts, &left);
    assert(r == 0 || (r < 0 && errno == EINTR));
    return (r == 0) ? 0 : ((uvlong)left.tv_sec * NS + (uvlong)ts.tv_nsec);
#undef NS
}
