#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "multitask.h"
#include "map.h"
#include <inttypes.h>
#include <unistd.h>
#include "v2gstack.h"
Map session_map;
QLock session_map_mutex;

static size_t hash( Key k )
{
    return (size_t) k.u64 & 0xFFFFFFFF;
}

static int cmp(Key k1, Key k2)
{
    if( k1.u64 == k2.u64 ) {
        return 0;
    }
    return -1;
}

int gen_random_data( void* dest, size_t dest_len ){
    int fd = open( "/dev/urandom", O_RDONLY );
    int len = 0;
    if (fd == -1){
        perror("gen_random_data: open /dev/urandom");
        return -1;
    }
    while ( len < dest_len ){
        ssize_t result = read( fd, (char*)dest + len, dest_len - len);
        if ( result < 0 ){
            perror("gen_random_data: read");
            close(fd);
            return -1;
        }
        len += result;
    }
    close(fd);
    return 0;
}

/*
// Up to 1024 bytes dest
int gen_random_data_base(unsigned char base, void* dest, size_t dest_len)
{
    size_t i;
    size_t entropy_len;
    byte rnd[1024];
    if (dest_len > 1024) {
        printf("gen_random_data_base: dest_len is %zu, maximum is 1024\n", dest_len)
        return -1;
    }
    entropy_len = dest_len * base /
    if (gen_random_data(rnd, dest_len) != 0) {
        return -1;
    }
    for (i = 0; i < dest_len; i++) {
        dest[i] = rnd[i] % base;
    }
    return 0;
}*/


void session_lock(session_t* session)
{
    if (session == NULL) {
        return;
    }
    qlock(&session->mutex);
}
void session_unlock(session_t* session)
{
    if (session == NULL) {
        return;
    }
    qunlock(&session->mutex);
}

int init_sessions()//
{
    int err = mapinit( &session_map,
             sizeof(session_t*),
             256,
             &hash,
             &cmp );
    if( err == -1 ) {
        printf("main: map_create failed\n");
        return -1;
    }
    qlockinit( &session_map_mutex );
    return 0;
}

session_t* session_lookup( uint64_t sessionid )
{
    if (sessionid == 0) {
        return NULL;
    }
    union Key k = { .u64 = sessionid };
    qlock( &session_map_mutex );
    session_t** sessionpp =  (session_t**)mapfind( &session_map, k );
    if (sessionpp == NULL) {
        printf("session_lookup: invalid session\n");
        return NULL;
    }
    session_lock(*sessionpp);
    (*sessionpp)->refcount++;
    if ((*sessionpp)->refcount > 4) {
        printf("session_lookup: %d references to the same session, code error is likely\n", (*sessionpp)->refcount);
    }
    session_unlock(*sessionpp);
    qunlock( &session_map_mutex );

    return *sessionpp;
}

session_t* session_new()
{
    union Key k;
    // Must be hex binary
    int err = gen_random_data( &k.u64, 8);
    if( err != 0 ) {
        return NULL;
    }
    qlock( &session_map_mutex );
    session_t** sessionpp = (session_t**)mapinsert( &session_map, k );
    if (sessionpp == NULL) {
        return NULL;
    }
    *sessionpp = malloc(sizeof(session_t));
    printf("pointer=%p %p\n", sessionpp, (session_t**)mapfind( &session_map, k ));
    if (*sessionpp == NULL) {
        return NULL;
    }
    memset(*sessionpp, 0, sizeof(session_t));
    qunlock( &session_map_mutex );
    (*sessionpp)->id = k.u64;
    (*sessionpp)->status = SESSION_ACTIVE;
    (*sessionpp)->refcount = 1;
    return *sessionpp;
}


session_t* session_lookup_exi(struct v2gEXIDocument* exiIn)
{
    uint64_t sessionid;
    memcpy(&sessionid, exiIn->V2G_Message.Header.SessionID.bytes, 8);
    return session_lookup(sessionid);
}


void session_terminate( session_t* session )
{
    union Key k = { .u64 = session->id };
    qlock( &session_map_mutex );
    mapremove( &session_map, k );
    session->status = SESSION_TERMINATED;
    qunlock( &session_map_mutex );
}

void session_pause(session_t* session, bool pause)
{
    session->status = SESSION_PAUSED;
}

void session_remove_ref(session_t* session)
{
    if (session == NULL) {
        return;
    }
    session_lock(session);
    session->refcount--;
    if (session->refcount == 0 && session->status == SESSION_TERMINATED) {
        free(session);
        printf("Succesfully freed session\n");
    } else if(session->refcount < 0) {
        printf("session_remove_ref: Negative session ref-count\n");
    }
    session_unlock(session);
}
