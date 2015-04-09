#include <nikolav2g.h>
#include "plc_eth.h"

void print_byte_arr(void *varr, size_t n)
{
    uint8_t *arr = (uint8_t*)varr;
    int i;
    if (chattyv2g) fprintf(stderr, "[");
    // Highly ineffictive but whatever it's TESTING!! :D
    for (i = 0; i < n; i++) {
        if (chattyv2g) fprintf(stderr,  " %02x", arr[i]);
    }
    if (chattyv2g) fprintf(stderr, " ]\n");
}

static int lookup_mac(const char *if_name, uint8_t *mac)
{
    char buf[64 + IFNAMSIZ];
    FILE *f;
    if (strlen(if_name) > IFNAMSIZ) { return -1; }

    sprintf(buf, "/sys/class/net/%s/address", if_name);
    if ((f = fopen(buf, "r")) == NULL) { return -1; }
    if (fscanf(f, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               mac,mac+1,mac+2,mac+3,mac+4,mac+5) != 6) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

int ethdial(ethconn_t *ethconn, const char *if_name, uint16_t protocol)
{
    uint8_t src_mac[6];
    unsigned idx;

    if ((idx = if_nametoindex(if_name)) == 0) { return -1; }
    if (lookup_mac(if_name, src_mac) != 0) {
        errno = ENXIO;
        return -1;
    }
    memcpy(ethconn->src_mac, src_mac, sizeof(src_mac));
    ethconn->protocol = protocol;
    ethconn->if_index = idx;
    ethconn->sockfd = socket(AF_PACKET, SOCK_RAW, htons(protocol));
    if (ethconn->sockfd < 0) { return -1; }
	return 0;
}

int ethclose(ethconn_t *ethconn)
{
    return close(ethconn->sockfd);
}

ssize_t ethrecvfrom(ethconn_t *ethconn, void *buffer, const uint8_t remote_mac[ETH_ALEN])
{
    struct sockaddr_ll rsa = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex  = ethconn->if_index,
        .sll_hatype   = ARPHRD_ETHER,
        .sll_pkttype  = PACKET_OTHERHOST,
        .sll_halen    = ETH_ALEN
    };
    socklen_t sockaddr_len = sizeof(rsa);
    memcpy(rsa.sll_addr, remote_mac, ETH_ALEN);
    return recvfrom(ethconn->sockfd, buffer, ETH_FRAME_LEN, 0,
                    (struct sockaddr *)&rsa, &sockaddr_len);
}

ssize_t ethrecv(ethconn_t *ethconn, void *buffer)
{
    return recvfrom(ethconn->sockfd, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
 }

void ethwritehdr(void *vbuf, ethconn_t *ethconn, const uint8_t destmac[6])
{
    uint8_t *buf = vbuf;
	memcpy(buf, destmac, ETH_ALEN);
    memcpy(buf + ETH_ALEN, ethconn->src_mac, ETH_ALEN);
    //eh->h_proto = 0xcafe;
    buf[12] = ethconn->protocol >> 8;
    buf[13] = ethconn->protocol & 0xff;
}

int ethsend(ethconn_t *ethconn, const void *data, size_t len)
 {
    struct sockaddr_ll rsa = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex  = ethconn->if_index,
        .sll_hatype   = ARPHRD_ETHER,
        .sll_pkttype  = PACKET_OTHERHOST,
        .sll_halen    = ETH_ALEN
    };
    uint8_t mindata[ETH_FRAME_MIN_SIZE];

    if (len > ETH_FRAME_LEN) {
         errno = EMSGSIZE;
         return -1;
    }
    if (len < ETH_FRAME_MIN_SIZE) {
        memset(mindata, 0, sizeof(mindata));
        memcpy(mindata, data, len);
        data = mindata;
        len = ETH_FRAME_MIN_SIZE;
    }
    memcpy(rsa.sll_addr, data, ETH_ALEN); /* XXX does this matter? */
    if (sendto(ethconn->sockfd, data, len, 0,
               (struct sockaddr *)&rsa, sizeof(rsa)) < 0) {
         return -1;
     }
     return 0;
}



//==================================
//     Higher Level Functions
//==================================

int toggle_listen_slac_assn(ethconn_t *ethconn, const uint8_t dest_mac[6], bool listen)
 {
    static const uint8_t listen_payload[3] = { 0x00, 0x0b, 0x01 };
    static const uint8_t stoplisten_payload[4] = { 0x00, 0x0b, 0x03, 0x00 };
    uint8_t ethframe[ETH_FRAME_LEN];
    uint8_t *payload = ethframe + ETH_FRAME_HDR_SIZE;
    size_t payload_len;
    memset(ethframe, 0, sizeof(ethframe));
    ethwritehdr(ethframe, ethconn, dest_mac);
    if (listen) {
        memcpy(payload, listen_payload, sizeof(listen_payload));
        payload_len = 61;
    } else {
        memcpy(payload, stoplisten_payload, sizeof(stoplisten_payload));
        payload_len = 4;
    }
    return ethsend(ethconn, ethframe, ETH_FRAME_HDR_SIZE + payload_len);
}

//int terminate_dlink(ethconn_t *ethconn, byte dest_mac[6], bool resetup)
//{
//    byte ethframe[ETH_FRAME_LEN];
//    byte *payload = ethframe + ETH_FRAME_HDR_SIZE;
//    size_t payload_len;
//    byte payload[62];
//    int err;
//    payload[0] = 0x0b;
//    payload[1] = 0x07;
//    payload[2] = !resetup;
//    memset(payload+3, 0, 58);
//    err = ethsend(ethconn, dest_mac, payload, 61);
//    if (err == -1) {
//        if (chattyv2g) fprintf(stderr, "%s: %m\n", "plc_eth_send");
//    }
//    return err;
//}

int switch_power_line(const char *if_name, const uint8_t dest_mac[6], bool toggle_powerline)
{
    static const uint8_t powerline_payload[3] = { 0x00, 0x0f, 0x10 };
    static const uint8_t pilotline_payload[3] = { 0x00, 0x0f, 0x0e };
    uint8_t ethframe[ETH_FRAME_LEN];
    uint8_t *payload = ethframe + ETH_FRAME_HDR_SIZE;
    size_t payload_len;
    ethconn_t ethconn;
    int r, e;

    if (ethdial(&ethconn, if_name, 0xcafe) != 0) { return -1; }

    memset(ethframe, 0, sizeof(ethframe));
    ethwritehdr(ethframe, &ethconn, dest_mac);
    if (toggle_powerline) {
        memcpy(payload, powerline_payload, 3);
        payload_len = 61;
    } else {
        memcpy(payload, pilotline_payload, 3);
        payload_len = 61;
    }
    r = ethsend(&ethconn, ethframe, ETH_FRAME_HDR_SIZE + payload_len);

    e = errno;
    ethclose(&ethconn);
    errno = e;

    return r;
}

uint16_t get_slac_type(const void *buf)
{
    const uint8_t *_buf = buf;
    return ((uint16_t)_buf[ETH_FRAME_HDR_SIZE + 1] << 8) |
            (uint16_t)_buf[ETH_FRAME_HDR_SIZE + 2];
}
