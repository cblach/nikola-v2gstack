#include <errno.h>
#include <string.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <inttypes.h>
#include "multitask.h"
#include <assert.h>
#include <time.h>
#include <limits.h>

#define SDP_ENFORCE_STRICT_SECURITY_REQUIREMENT 1
#define SDP_VERSION 0x01
#define SDP_INVERSE_VERSION 0xfe
#define SDP_HEADER_LEN 8
#define SDP_REQ_TYPE 0x9000
#define SDP_RESP_TYPE 0x9001
#define SDP_REQ_PAYLOAD_LEN 2
#define SDP_RESP_PAYLOAD_LEN 20
#define SDP_SRV_PORT 15118
#define SDP_MAX_TRIES 50
#define SDP_TRY_DELAY 250ULL //ms
typedef uint8_t byte;

#define TIME_MICROSECOND 1000
#define TIME_MILLISECOND ( TIME_MICROSECOND * 1000 )
#define TIME_SECOND ( TIME_MILLISECOND * 1000 )
// ff::1
static const uint8_t SDP_MULTICAST_ADDR[16] = {0xff, 0x02, 0, 0,
                                               0, 0, 0, 0,
                                               0, 0, 0, 0,
                                               0, 0, 0, 1};
struct evse_sdp_listen_args{
    char* if_name;
    uint16_t tls_port;
};
typedef unsigned long long uvlong;

static inline uvlong nsleep( uvlong ns )
{
    struct timespec left, ts = { .tv_sec = ns / TIME_SECOND, .tv_nsec = ns % TIME_SECOND };
    int r = nanosleep(&ts, &left);
    assert(r == 0 || (r < 0 && errno == EINTR));
    return (r == 0) ? 0 : ((uvlong)left.tv_sec * TIME_SECOND + (uvlong)ts.tv_nsec);
}

static void print_byte_arr( byte* arr, size_t n )
{
    int i;
    printf("[");
    // Highly ineffictive but whatever it's TESTING!! :D
    for( i = 0; i < n; i++) {
        printf( " %02x", arr[i] );
    }
    printf(" ]\n");
}

static void write_header( byte* buf,
                       uint16_t payload_type,
                       uint32_t payload_len )
{
    buf[0] = SDP_VERSION; // Version
    buf[1] = SDP_INVERSE_VERSION; // Inverse version
    buf[2] = (payload_type >> 8) & 0xff; // Payload type byte hi
    buf[3] = payload_type & 0xff; // Payload type lo
    buf[4] = (payload_len >> 24) & 0xff; // Payload length byte 1 (MSB)
    buf[5] = (payload_len >> 16) & 0xff; // Payload length byte 2
    buf[6] = (payload_len >> 8) & 0xff; // Payload length byte 3
    buf[7] = payload_len & 0xff; // Payload length part 4 (LSB)
}

static int validate_header(byte* buf, uint16_t expected_payload_type,
                    uint32_t expected_payload_len){
    uint16_t payload_type;
    uint32_t payload_len;
    if (buf[0] != SDP_VERSION) {
        printf("validate_header: invalid sdp version\n");
        return -1;
    }
    if (buf[1] != SDP_INVERSE_VERSION) {
        printf("validate_header: invalid inverse sdp version\n");
        return -1;
    }
    payload_type = (buf[2] << 8) + buf[3];
    if (payload_type != expected_payload_type) {
        printf("validate_header: invalid payload type, expected %u, received %u\n", expected_payload_type, payload_type);
        return -1;
    }
    payload_len = (buf[4] << 24) + (buf[5] << 16) + (buf[6] << 8) + buf[7];
    if (payload_len != expected_payload_len) {
        printf("validate_header: invalid payload length\n");
        return -1;
    }
    return 0;
}

int get_interface_ipv6_address( char* if_name,
                                    struct sockaddr_in6* addr  )
{
    struct ifaddrs *ifa, *ifa_o;
    int err = getifaddrs(&ifa);
    if (err == -1) {
        return -1;
    }
    ifa_o = ifa; // original pointer, used for freeing
    // === Loop through all interface names and  ===
    // ===    find the corresponding address     ===
    for (; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET6
            && strcmp( ifa->ifa_name, if_name ) == 0) {
            memcpy( addr, (struct sockaddr_in6 *)(ifa->ifa_addr), sizeof(struct sockaddr_in6));
            freeifaddrs(ifa_o);
            return 0;
        }
    }
    freeifaddrs(ifa_o);
    return -1;
}

//====================================
//          EV (Client)
//====================================

typedef struct{
    int sockfd;
    struct sockaddr_in6* addr;
} ioargs;

// === Slave function for the SDP client ===
// === Attempts to send the SDP message SDP_MAX_TRIES (50) times
// === using the multicast address provided on the provided socket===
static ssize_t request_writer(void* args, atomic_int *cancel) {
    ioargs* wargs = args;
    byte buf[SDP_HEADER_LEN+SDP_REQ_PAYLOAD_LEN];
    byte* payload = buf + SDP_HEADER_LEN;
    ssize_t sentsz;
    int i = 0;
    // === Set Multicast Data ===
    write_header(buf, SDP_REQ_TYPE, SDP_REQ_PAYLOAD_LEN);
    payload[0] = 0x00;
    payload[1] = 0x00;
    // Keep sending up to 50 multicast messages until cancelled
    while (i < SDP_MAX_TRIES && atomic_load(cancel) == 0) {
        printf("Broadcasting multicast message, try %d\n", i+1);
        sentsz = sendto(wargs->sockfd, buf,
                        SDP_HEADER_LEN + SDP_REQ_PAYLOAD_LEN,
                        0, (struct sockaddr *)wargs->addr,
                        sizeof(struct sockaddr_in6));
        if (sentsz != 8+SDP_REQ_PAYLOAD_LEN) {
            if (sentsz == -1) {
                perror("sendto");
            }
            return -1;
        }
        nsleep(SDP_TRY_DELAY * TIME_MILLISECOND);
        i++;
    }
    if (i == SDP_MAX_TRIES) {
        printf("Unable to find EVSE, stopping discovery\n");
    }
    return 0;
}

// === Second slave function to the SDP client ===
// === Attempts to read unicast responses from an SDP server ===
static ssize_t response_reader( void* args, atomic_int *cancel ){
    ioargs* rargs = args;
    byte buf[512];
    byte* payload = buf + SDP_HEADER_LEN;
    int err;
    ssize_t len;
    byte secc_security, secc_transport_protocol;
    while(atomic_load(cancel) == 0) {
        len = recv(rargs->sockfd, buf, SDP_HEADER_LEN+SDP_RESP_PAYLOAD_LEN, 0);
        if (len != SDP_HEADER_LEN + SDP_RESP_PAYLOAD_LEN) {
            if (len == -1) {
                perror("recv");
                return -1;
            }
            continue;
        }
        err = validate_header(buf, SDP_RESP_TYPE, SDP_RESP_PAYLOAD_LEN);
        if (err != 0) {
            printf("ev_sdp_resp_reader: validate_header error\n");
            continue;
        }
        secc_security = payload[18];
        if (SDP_ENFORCE_STRICT_SECURITY_REQUIREMENT
            && secc_security != 0x00) {
            printf("ev_sdp_resp_reader: evse does not support TLS, discarding\n");
            continue;
        }
        secc_transport_protocol = payload[19];
        if (secc_transport_protocol != 0x00) {
            printf("ev_sdp_resp_reader: evse does not support TCP, discarding\n");
            continue;
        }
        break;
    }
    memcpy(rargs->addr->sin6_addr.s6_addr, payload, 16);
    memcpy(&rargs->addr->sin6_port, payload + 16, 2 );
    printf("Succesful SDP response from EVSE\n");
    return 0;
}

int ev_sdp_discover_evse( char* if_name, struct sockaddr_in6* evse_addr )
{
    int sock, err;
    ssize_t ret;
    struct sockaddr_in6 dest;
    Chan *iocr = iochan(1048576 - PTHREAD_STACK_MIN);
    Chan *iocw = iochan(1048576 - PTHREAD_STACK_MIN);;
    Alt alts[] = {{ .c  = iocr, .v  = &ret, .op = CHANRECV },
                  { .c  = iocw, .v  = &ret, .op = CHANRECV },
                  { .op = CHANEND }};
    unsigned int if_index;
    ioargs rargs, wargs;
	if (iocr == NULL || iocw == NULL) {
	    printf("slac_sendrecvloop: iochan error\n");
	    if (iocr != NULL) {
	        chanfree(iocr);
	    }
	    if (iocw != NULL) {
	        chanfree(iocw);
	    }
	    return -1;
	}
    // === Get interface index ===
    if_index = if_nametoindex(if_name);
    if (if_index == 0) {
        perror("interface_index");
        return -1;
    }
    evse_addr->sin6_family = AF_INET6;
    evse_addr->sin6_scope_id = if_index;
    // === Set up socket ===
    printf("Setting up socket\n");
    sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        return -1;
    }
    // === Specify the socket used for multicast ===
    err = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &if_index, sizeof(if_index));
    if (err < 0) {
        perror("setsockopt");
        close(sock);
        return -1;
    }
    // === Send the multicast message ===
    memset((char *)&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    dest.sin6_port   = htons(SDP_SRV_PORT);
    memcpy( &dest.sin6_addr.s6_addr, SDP_MULTICAST_ADDR, 16);
    printf("Preparing to send\n");
    fflush(stdout);
    rargs.sockfd = sock;
    rargs.addr = evse_addr;
    wargs.sockfd = sock;
    wargs.addr = &dest;
    iocall(iocr, &response_reader, &rargs, sizeof(ioargs));
    iocall(iocw, &request_writer, &wargs, sizeof(ioargs));
    // === Receive responses from iocalls ===
    // === If the send channel times out, no SDP server has responded in time ===
    switch (alt(alts)) {
        case 0: // Done reading response
            iocancel(iocw);
            printf("received response\n");
            err = ret;
            break;
        case 1: // Done writing and no response -> error
            iocancel(iocr);
            err = -1;
            break;
        default:
            printf("critical ev_sdp_discover_evse: alt error\n");
            abort();
    }

    printf("done, returning with %d\n", err);
    chanfree(iocr);
    chanfree(iocw);
    close(sock);
    return err;
}

//==================================================
//                  EVSE (server)
//==================================================

void evse_sdp_respond(char* if_name, struct sockaddr_in6 raddr, uint16_t tls_port)
{
    byte buf[SDP_HEADER_LEN+SDP_RESP_PAYLOAD_LEN];
    ssize_t sentSz;
    byte* payload = buf + SDP_HEADER_LEN;
    struct sockaddr_in6 laddr;
    uint16_t port_bigendian = htons( tls_port );
    // === Create ipv6 udp socket ===
    int sock = socket( AF_INET6, SOCK_DGRAM, IPPROTO_UDP );
    if (sock < 0) {
        perror("socket");
        exit(-1);
    }
    if (get_interface_ipv6_address(if_name, &laddr)){
        perror("if_name_to_ipv6_addr");
        return;
    }
    // === Write sdp response packet ===
    write_header(buf, SDP_RESP_TYPE, SDP_RESP_PAYLOAD_LEN);
    memcpy(payload, laddr.sin6_addr.s6_addr, 16);
    memcpy(payload + 16, &port_bigendian, 2);
    payload[18] = 0; // Signal TLS support
    payload[19] = 0; // Set protocol to TCP
    // === Send sdp response packet ===
    print_byte_arr(raddr.sin6_addr.s6_addr, sizeof(struct sockaddr_in6));
    printf("======SEND\n");
    sentSz = sendto(sock, buf,
                    SDP_HEADER_LEN+SDP_RESP_PAYLOAD_LEN, 0,
                    (struct sockaddr *)&raddr, sizeof(struct sockaddr_in6));
    if (sentSz < SDP_HEADER_LEN+SDP_RESP_PAYLOAD_LEN) {
        perror( "sendto");
    }
    close(sock);
}

void evse_sdp_listen_discovery_msg( void* args )
{
    char if_name[IFNAMSIZ];
    uint16_t tls_port = ((struct evse_sdp_listen_args*)args)->tls_port;
    struct sockaddr_in6 laddr = {
        .sin6_family = AF_INET6,
        .sin6_addr = in6addr_any,
        .sin6_port = htons( SDP_SRV_PORT),
    };
    int sock, err, len;
    struct ipv6_mreq mreq;
    struct sockaddr_in6 raddr;
    size_t raddr_len = sizeof( raddr );
    strcpy(if_name, ((struct evse_sdp_listen_args*)args)->if_name );
    rendez(args, NULL);
    printf("start listen %s fjhjh\n", if_name);
    // === Get interface index ===
    unsigned int if_index = if_nametoindex(if_name);
    if (if_index == 0) {
        perror("interface_index");
        exit(-1);
    }
    //sock = announce("udp![::1]:15118");
    sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        exit(-1);
    }
    // === Bind socket to SDP_SRV_PORT ===
    err = bind(sock, (struct sockaddr *) &laddr, sizeof(laddr));
    if (err != 0) {
        close( sock );
        perror("bind");
        exit(-1);
    }
    // === Join Multicast Group ===
    memset( &mreq, 0, sizeof(mreq) );
    memcpy( &mreq.ipv6mr_multiaddr,
            SDP_MULTICAST_ADDR,
            sizeof(mreq.ipv6mr_multiaddr) );
    mreq.ipv6mr_interface = if_index;
    err = setsockopt( sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
    if (err != 0) {
        close( sock );
        perror( "IPV6_JOIN_GROUP" );
        exit(-1);
    }
    // === Keep receiving SDP requests ===
    printf("Receive SDP requests\n");
    for (;;) {
        byte buf[1024];
        len = recvfrom(sock, buf, 1024, 0,
                       (struct sockaddr *)&raddr,
                       (socklen_t *)&raddr_len );
        if (len != SDP_HEADER_LEN + SDP_REQ_PAYLOAD_LEN) {
            if (len == -1) {
                perror( "recvfrom" );
                exit(-1);
            }
            printf("evse_sdp_listen_discovery_msg: invalid length\n");
            continue;
        }
        err = validate_header(buf, SDP_REQ_TYPE, SDP_REQ_PAYLOAD_LEN);
        if (err != 0) {
            printf("evse_sdp_listen_discovery_msg: invalid header\n");
            continue;
        }
        printf("start responding\n");
        /*data[len] = '\0';
        printf( "Received 0x%zu bytes: %s\n", len, data );

        print_byte_arr( raddr.sin6_addr.s6_addr, sizeof( raddr.sin6_addr ) );
        printf("Port: %d\n", ntohs( raddr.sin6_port ));*/
        // === Respond to SDP request ===
        // for( i = 0 ; i < 50 ; i ++ )
        evse_sdp_respond(if_name, raddr, tls_port);
        // sleep( 250ms)
        // }
    }
    close(sock);
}

void sdp_listen(char* if_name, int tls_port) {
    struct evse_sdp_listen_args sdp_args = {
        .if_name = if_name,
        .tls_port = tls_port,
    };
    printf("start listen %s\n", if_name);
    threadcreate(evse_sdp_listen_discovery_msg, &sdp_args, 1024 * 1024);
    rendez(&sdp_args, NULL);
    printf("huehue\n");
}

/*
    mreq6.ipv6mr_multiaddr = ((SOCKADDR_IN6 *)resmulti->ai_addr)->sin6_addr;
mreq6.ipv6mr_interface = ((SOCKADDR_IN6 *)reslocal->ai_addr)->sin6_scope_id;

//setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq6, sizeof(mreq6));

    bzero((char *)&addr, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sa_addr.in6_addr = htonl(INADDR_ANY);
    addr.sa_port = htons(EXAMPLE_PORT);
    addrlen = sizeof(addr);

    if (argc > 1) {
      // send
      addr.sin_addr.s_addr = inet_addr(EXAMPLE_GROUP);
      while (1) {
     time_t t = time(0);
     sprintf(message, "time is %-24.24s", ctime(&t));
     printf("sending: %s\n", message);
     cnt = sendto(sock, message, sizeof(message), 0,
	          (struct sockaddr *) &addr, addrlen);
     if (cnt < 0) {
        perror("sendto");
        exit(1);
     }
}*/
