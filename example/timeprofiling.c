#include "timeprofiling.h"
#include "string.h"
#include <stdio.h>

int enable_timeprofiling = 0;

void tl_init(tlog *tl, const char* title) {
    clock_gettime(CLOCK_MONOTONIC, &tl->reference);
    strcpy(tl->title, title);
    tl->n = 0;
}

void tl_register(tlog *tl, const char *label)
{
    if (enable_timeprofiling && tl->n < 128) {
        tentry *tent = &tl->entry[tl->n];
        strcpy(tent->label, label);
        clock_gettime(CLOCK_MONOTONIC, &tent->t);
        tl->n++;
    }
}

void tl_print(tlog* tl)
{
    int i;
    struct timespec *ref = &tl->reference;
    struct timespec temp;
    if (enable_timeprofiling) {
        printf("=== %s ===\n", tl->title);
        for (i = 0; i < tl->n; i++) {
            temp.tv_sec = tl->entry[i].t.tv_sec - ref->tv_sec;
		    temp.tv_nsec = tl->entry[i].t.tv_nsec - ref->tv_nsec;
            printf("%s: %luus\n", tl->entry[i].label, temp.tv_sec * 1000000 + temp.tv_nsec /1000);
        }
        printf("=======\n");
    }
}
