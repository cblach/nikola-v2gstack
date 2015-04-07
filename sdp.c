#include "nikolav2g.h"
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
#define SDP_SECURITY_TLS 0x00
#define SDP_SECURITY_NONE 0x10
#define SDP_MAX_TRIES 50
#define SDP_TRY_DELAY 250ULL //ms
typedef uint8_t byte;

#define TIME_MICROSECOND 1000
#define TIME_MILLISECOND (TIME_MICROSECOND * 1000)
#define TIME_SECOND (TIME_MILLISECOND * 1000)
// ff::1
static const uint8_t SDP_MULTICAST_ADDR[16] = {0xff, 0x02, 0, 0,
                                               0, 0, 0, 0,
                                               0, 0, 0, 0,
                                               0, 0, 0, 1};

typedef unsigned long long uvlong;

static inline uvlong nsleep(uvlong ns)
{
    struct timespec left, ts = { .tv_sec = ns / TIME_SECOND, .tv_nsec = ns % TIME_SECOND };
    int r = nanosleep(&ts, &left);
    assert(r == 0 || (r < 0 && errno == EINTR));
    return (r == 0) ? 0 : ((uvlong)left.tv_sec * TIME_SECOND + (uvlong)ts.tv_nsec);
}

static void print_byte_arr(byte *arr, size_t n)
{
    int i;
    if (chattyv2g) fprintf(stderr, "[");
    // Highly ineffictive but whatever it's TESTING!! :D
    for (i = 0; i < n; i++) {
        if (chattyv2g) fprintf(stderr, " %02x", arr[i]);
    }
    if (chattyv2g) fprintf(stderr, " ]\n");
}

static void write_header(byte *buf,
                         uint16_t payload_type,
                         uint32_t payload_len)
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

static int validate_header(byte *buf, uint16_t expected_payload_type,
                    uint32_t expected_payload_len) {
    uint16_t payload_type;
    uint32_t payload_len;
    if (buf[0] != SDP_VERSION) {
        if (chattyv2g) fprintf(stderr, "validate_header: invalid sdp version\n");
        return -1;
    }
    if (buf[1] != SDP_INVERSE_VERSION) {
        if (chattyv2g) fprintf(stderr, "validate_header: invalid inverse sdp version\n");
        return -1;
    }
    payload_type = (buf[2] << 8) + buf[3];
    if (payload_type != expected_payload_type) {
        if (chattyv2g) fprintf(stderr, "validate_header: invalid payload type, expected %u, received %u\n", expected_payload_type, payload_type);
        return -1;
    }
    payload_len = (buf[4] << 24) + (buf[5] << 16) + (buf[6] << 8) + buf[7];
    if (payload_len != expected_payload_len) {
        if (chattyv2g) fprintf(stderr, "validate_header: invalid payload length\n");
        return -1;
    }
    return 0;
}

int get_interface_ipv6_address(const char *if_name,
                                  struct sockaddr_in6 *addr)
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
            && strcmp(ifa->ifa_name, if_name) == 0) {
            memcpy(addr, (struct sockaddr_in6 *)(ifa->ifa_addr), sizeof(struct sockaddr_in6));
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

typedef struct ioargs ioargs_t;
struct ioargs{
    int sockfd;
    struct sockaddr_in6 *addr;
    byte security;
};

// === Slave function for the SDP client ===
// === Attempts to send the SDP message SDP_MAX_TRIES (50) times
// === using the multicast address provided on the provided socket===
static ssize_t request_writer(void *args, atomic_int *cancel) {
    ioargs_t *wargs = args;
    byte buf[SDP_HEADER_LEN+SDP_REQ_PAYLOAD_LEN];
    byte *payload = buf + SDP_HEADER_LEN;
    ssize_t sentsz;
    int i = 0;
    byte security = wargs->security;
    // === Set Multicast Data ===
    write_header(buf, SDP_REQ_TYPE, SDP_REQ_PAYLOAD_LEN);
    payload[0] = security; // TLS or TCP
    payload[1] = 0x00; // TCP = underlying protocol not matter what
    // Keep sending up to 50 multicast messages until cancelled
    while (i < SDP_MAX_TRIES && atomic_load(cancel) == 0) {
        if (chattyv2g) fprintf(stderr, "Broadcasting SDP multicast request, try %d\n", i+1);
        sentsz = sendto(wargs->sockfd, buf,
                        SDP_HEADER_LEN + SDP_REQ_PAYLOAD_LEN,
                        0, (struct sockaddr *)wargs->addr,
                        sizeof(struct sockaddr_in6));
        if (sentsz != 8+SDP_REQ_PAYLOAD_LEN) {
            if (sentsz == -1) {
                if (chattyv2g) fprintf(stderr, "%s: %m\n", "sendto");
            }
            return -1;
        }
        nsleep(SDP_TRY_DELAY * TIME_MILLISECOND);
        i++;
    }
    if (i == SDP_MAX_TRIES) {
        if (chattyv2g) fprintf(stderr, "Unable to find EVSE, stopping discovery\n");
    }
    return 0;
}

// === Second slave function to the SDP client ===
// === Attempts to read unicast responses from an SDP server ===
static ssize_t response_reader(void *args, atomic_int *cancel)
{
    ioargs_t *rargs = args;
    byte buf[512];
    byte *payload = buf + SDP_HEADER_LEN;
    int err;
    ssize_t len;
    byte expected_secc_security = rargs->security;
    byte secc_security, secc_transport_protocol;
    while(atomic_load(cancel) == 0) {
        len = recv(rargs->sockfd, buf, SDP_HEADER_LEN+SDP_RESP_PAYLOAD_LEN, 0);
        if (len != SDP_HEADER_LEN + SDP_RESP_PAYLOAD_LEN) {
            if (len == -1) {
                if (chattyv2g) fprintf(stderr, "%s: %m\n", "recv");
                return -1;
            }
            continue;
        }
        err = validate_header(buf, SDP_RESP_TYPE, SDP_RESP_PAYLOAD_LEN);
        if (err != 0) {
            if (chattyv2g) fprintf(stderr, "ev_sdp_resp_reader: validate_header error\n");
            continue;
        }
        secc_security = payload[18];
        if (secc_security != expected_secc_security) {
            if (chattyv2g) fprintf(stderr, "ev_sdp_resp_reader: evse does not support the chosen protocol, discarding\n");
            continue;
        }
        secc_transport_protocol = payload[19];
        if (secc_transport_protocol != 0x00) {
            if (chattyv2g) fprintf(stderr, "ev_sdp_resp_reader: evse does not support TCP as underlying transport, discarding\n");
            continue;
        }
        break;
    }
    memcpy(rargs->addr->sin6_addr.s6_addr, payload, 16);
    memcpy(&rargs->addr->sin6_port, payload + 16, 2);
    if (chattyv2g) fprintf(stderr, "Succesful SDP response from EVSE\n");
    return 0;
}

int ev_sdp_discover_evse(const char *if_name,
                         struct sockaddr_in6 *evse_addr,
                         bool tls_enabled)
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
    ioargs_t rargs, wargs;
	if (iocr == NULL || iocw == NULL) {
	    if (chattyv2g) fprintf(stderr, "slac_sendrecvloop: iochan error\n");
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
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "interface_index");
        return -1;
    }
    evse_addr->sin6_family = AF_INET6;
    evse_addr->sin6_scope_id = if_index;
    // === Set up socket ===
    if (chattyv2g) fprintf(stderr, "Setting up socket\n");
    sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        return -1;
    }
    // === Specify the socket used for multicast ===
    err = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &if_index, sizeof(if_index));
    if (err < 0) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "setsockopt");
        close(sock);
        return -1;
    }
    // === Send the multicast message ===
    memset((char *)&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    dest.sin6_port   = htons(SDP_SRV_PORT);
    memcpy(&dest.sin6_addr.s6_addr, SDP_MULTICAST_ADDR, 16);
    rargs.sockfd = sock;
    rargs.addr = evse_addr;
    rargs.security = tls_enabled ? SDP_SECURITY_TLS : SDP_SECURITY_NONE;
    wargs.sockfd = sock;
    wargs.addr = &dest;
    wargs.security = tls_enabled ? SDP_SECURITY_TLS : SDP_SECURITY_NONE;
    iocall(iocr, &response_reader, &rargs, sizeof(ioargs_t));
    iocall(iocw, &request_writer, &wargs, sizeof(ioargs_t));
    // === Receive responses from iocalls ===
    // === If the send channel times out, no SDP server has responded in time ===
    switch (alt(alts)) {
        case 0: // Done reading response
            iocancel(iocw);
            if (chattyv2g) fprintf(stderr, "received response\n");
            err = ret;
            break;
        case 1: // Done writing and no response -> error
            iocancel(iocr);
            err = -1;
            break;
        default:
            if (chattyv2g) fprintf(stderr, "critical ev_sdp_discover_evse: alt error\n");
            abort();
    }
    chanfree(iocr);
    chanfree(iocw);
    close(sock);
    return err;
}

//==================================================
//                  EVSE (server)
//==================================================

void evse_sdp_respond(const char *if_name, struct sockaddr_in6 raddr,
                      uint16_t port, byte secc_security)
{
    byte buf[SDP_HEADER_LEN+SDP_RESP_PAYLOAD_LEN];
    ssize_t sentSz;
    byte *payload = buf + SDP_HEADER_LEN;
    struct sockaddr_in6 laddr;
    uint16_t port_bigendian = htons(port);
    // === Create ipv6 udp socket ===
    int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "socket");
        exit(-1);
    }
    if (get_interface_ipv6_address(if_name, &laddr)) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "if_name_to_ipv6_addr");
        return;
    }
    // === Write sdp response packet ===
    write_header(buf, SDP_RESP_TYPE, SDP_RESP_PAYLOAD_LEN);
    memcpy(payload, laddr.sin6_addr.s6_addr, 16);
    memcpy(payload + 16, &port_bigendian, 2);
    payload[18] = secc_security; // Signal 0x01 for TCP only or 0x00 for TLS
    payload[19] = 0; // Set underlying protocol to TCP (no choice)
    // === Send sdp response packet ===
    print_byte_arr(raddr.sin6_addr.s6_addr, sizeof(struct sockaddr_in6));
    if (chattyv2g) fprintf(stderr, "======SEND\n");
    sentSz = sendto(sock, buf,
                    SDP_HEADER_LEN+SDP_RESP_PAYLOAD_LEN, 0,
                    (struct sockaddr *)&raddr, sizeof(struct sockaddr_in6));
    if (sentSz < SDP_HEADER_LEN+SDP_RESP_PAYLOAD_LEN) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n",  "sendto");
    }
    close(sock);
}

void sdp_listen(const char *if_name, int tls_port, int tcp_port)
{
    struct sockaddr_in6 laddr = {
        .sin6_family = AF_INET6,
        .sin6_addr = in6addr_any,
        .sin6_port = htons(SDP_SRV_PORT),
    };
    int sock, err, len;
    struct ipv6_mreq mreq;
    struct sockaddr_in6 raddr;
    size_t raddr_len = sizeof(raddr);
    if (chattyv2g) fprintf(stderr, "start listen %s fjhjh\n", if_name);
    // === Get interface index ===
    unsigned int if_index = if_nametoindex(if_name);
    if (if_index == 0) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "interface_index");
        exit(-1);
    }
    //sock = announce("udp![::1]:15118");
    sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "socket");
        exit(-1);
    }
    // === Bind socket to SDP_SRV_PORT ===
    err = bind(sock, (struct sockaddr *) &laddr, sizeof(laddr));
    if (err != 0) {
        close(sock);
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "bind");
        exit(-1);
    }
    // === Join Multicast Group ===
    memset(&mreq, 0, sizeof(mreq));
    memcpy(&mreq.ipv6mr_multiaddr,
           SDP_MULTICAST_ADDR,
           sizeof(mreq.ipv6mr_multiaddr));
    mreq.ipv6mr_interface = if_index;
    err = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
    if (err != 0) {
        close(sock);
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "IPV6_JOIN_GROUP");
        exit(-1);
    }
    if (chattyv2g) fprintf(stderr, "SDP set to using TLS port = %d, TCP port = %d\n", tls_port, tcp_port);
    // === Keep receiving SDP requests ===
    if (chattyv2g) fprintf(stderr, "Receive SDP requests\n");
    for (;;) {
        byte buf[1024];
        byte *payload = buf + SDP_HEADER_LEN;
        byte evcc_security;
        len = recvfrom(sock, buf, 1024, 0,
                       (struct sockaddr *)&raddr,
                       (socklen_t *)&raddr_len);
        if (len != SDP_HEADER_LEN + SDP_REQ_PAYLOAD_LEN) {
            if (len == -1) {
                if (chattyv2g) fprintf(stderr, "%s: %m\n",  "recvfrom");
                exit(-1);
            }
            if (chattyv2g) fprintf(stderr, "evse_sdp_listen_discovery_msg: invalid length\n");
            continue;
        }
        err = validate_header(buf, SDP_REQ_TYPE, SDP_REQ_PAYLOAD_LEN);
        if (err != 0) {
            if (chattyv2g) fprintf(stderr, "evse_sdp_listen_discovery_msg: invalid header\n");
            continue;
        }
        evcc_security = payload[0];
        if (chattyv2g) fprintf(stderr, "SECC security = 0x%0x\n", evcc_security);
        if (evcc_security == SDP_SECURITY_TLS && tls_port > 0) {
            if (chattyv2g) fprintf(stderr, "Respond SDP with security field = TLS\n");
            evse_sdp_respond(if_name, raddr, tls_port, SDP_SECURITY_TLS);
        } else if (tcp_port > 0) {
            if (chattyv2g) fprintf(stderr, "Respond SDP with security field = no security\n");
            evse_sdp_respond(if_name, raddr, tcp_port, SDP_SECURITY_NONE);
        }
    }
    close(sock);
}
