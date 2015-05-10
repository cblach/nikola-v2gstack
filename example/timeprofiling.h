#ifndef TIMEPROFILING_H
#define TIMEPROFILING_H
#include <time.h>
extern int enable_timeprofiling;

typedef struct tentry tentry;
struct tentry {
    char label[64];
    struct timespec t;
};
typedef struct tlog tlog;
struct tlog {
    char title[128];
    tentry entry[128];
    int n;
    struct timespec reference;
};
void tl_init(tlog *tl, const char* title);
void tl_register(tlog *tl, const char *label);
void tl_print(tlog* tl);
#endif
