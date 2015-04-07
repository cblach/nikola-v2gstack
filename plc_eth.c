#include "nikolav2g.h"
#include "plc_eth.h"



// EVSE: sudo ./test -i eth1
// EV: sudo ./test -t ev -i eth0

void print_byte_arr( void* varr, size_t n )
{
    uint8_t* arr = (uint8_t*)varr;
    int i;
    if (chattyv2g) fprintf(stderr, "[");
    // Highly ineffictive but whatever it's TESTING!! :D
    for( i = 0; i < n; i++) {
        if (chattyv2g) fprintf(stderr,  " %02x", arr[i] );
    }
    if (chattyv2g) fprintf(stderr, " ]\n");
}

int lookup_mac(char* if_name, uint8_t* mac){
    int matches, err;
    FILE* f;
    char fnamebuf[256];
    int n = sprintf( fnamebuf,"/sys/class/net/%s/address", if_name);
    if( n > 256 ) {
        errno = EFAULT;
        return -1;
    }
    f = fopen( fnamebuf, "r");
    if ( f == NULL ) {
        return -1;
    }
    matches = fscanf( f, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      mac,mac+1,mac+2,mac+3,mac+4,mac+5);
    if ( matches < 6 ) {
        return -1;
    }
    err = fclose(f);
    if( err != 0){
        return -1;
    }
    return 0;
}

int ethdial(ethconn_t* ethconn,
              char* if_name,

              uint16_t protocol)
{
    uint8_t src_mac[6];
    int err = lookup_mac(if_name, src_mac);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "lookup mac err\n");
        return -1;
    }
    ethconn->protocol = protocol;
    ethconn->sockfd = socket( AF_PACKET, SOCK_RAW, htons( protocol ) );
    if( ethconn->sockfd < 1 ) {
        return -1;
    }
    int if_index = if_nametoindex( if_name );
    if (if_index == 0) {
        if (chattyv2g) fprintf(stderr, "if index lookup err\n");
        return -1;
    }
    ethconn->if_index = if_index;
    /*struct sockaddr_ll* rsa = &ethconn->rsaddr;
        rsa->sll_family   = AF_PACKET,
        rsa->sll_protocol = htons(ETH_P_IP),
        rsa->sll_ifindex  = if_index,
        rsa->sll_hatype   = ARPHRD_ETHER,
        rsa->sll_pkttype  = PACKET_OTHERHOST,
        rsa->sll_halen    = ETH_ALEN,
    memcpy( rsa->sll_addr,
            dest_mac,
            ETH_ALEN );
    memcpy( ethconn->dest_mac, dest_mac, ETH_ALEN);*/
    memcpy( ethconn->src_mac, src_mac, ETH_ALEN);
	return 0;
}

int ethclose(ethconn_t* ethconn ){
    int r;
    r = close( ethconn->sockfd );
    if( r == -1){
        return -1;
    }
    return 0;
}

ssize_t ethrecvfrom(ethconn_t* ethconn ,
					void* buffer,
					uint8_t remote_mac[ETH_ALEN])
{
    struct sockaddr_ll rsa = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex  = ethconn->if_index,
        .sll_hatype   = ARPHRD_ETHER,
        .sll_pkttype  = PACKET_OTHERHOST,
        .sll_halen    = ETH_ALEN
    };
    socklen_t sockaddr_len = sizeof( rsa );
    memcpy( rsa.sll_addr, remote_mac, ETH_ALEN );
    int n = recvfrom(ethconn->sockfd, buffer, (size_t)ETH_FRAME_LEN, 0,
                      (struct sockaddr*)&rsa,
                      &sockaddr_len);

    if( n == -1 ){
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "recvfrom");
        return -1;
    }
    return n;
}

ssize_t ethrecv(ethconn_t* ethconn ,
					void* buffer)
{
    //socklen_t sockaddr_len = sizeof( ethconn->rsaddr );
    int n = recvfrom(ethconn->sockfd, buffer, (size_t)ETH_FRAME_LEN, 0,
                     (struct sockaddr *) (0), (socklen_t *)(0));
                      //(struct sockaddr*)&ethconn->rsaddr,
                      //&sockaddr_len);

    if( n == -1 ){
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "recvfrom");
        return -1;
    }
    return n;
}

void ethwritehdr(void* vbuf, ethconn_t *ethconn, uint8_t destmac[6])
{
    uint8_t* buf = vbuf;
	memcpy(buf, destmac, ETH_ALEN);
    memcpy(buf + ETH_ALEN, ethconn->src_mac, ETH_ALEN);
    //eh->h_proto = 0xcafe;
    buf[12] = ethconn->protocol >> 8;
    buf[13] = ethconn->protocol & 0xff;
}

int ethsend(ethconn_t* ethconn,
             void* data,
             size_t data_len )
{
    int send_result;
    struct sockaddr_ll rsa = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex  = ethconn->if_index,
        .sll_hatype   = ARPHRD_ETHER,
        .sll_pkttype  = PACKET_OTHERHOST,
        .sll_halen    = ETH_ALEN
    };
    memcpy( rsa.sll_addr, data, ETH_ALEN );     // does this matter??
    if( data_len > ETH_FRAME_LEN ){
        if (chattyv2g) fprintf(stderr,  "Payload is %zu bytes, but must be less than %d\n",
                data_len, ETH_FRAME_LEN );
        errno = EMSGSIZE;
        return -1;
    }
    if( data_len < ETH_FRAME_MIN_SIZE) {
        data_len = ETH_FRAME_MIN_SIZE;
        memset( (uint8_t*)data + data_len, 0, ETH_FRAME_MIN_SIZE - data_len );
    }
    send_result = sendto( ethconn->sockfd,
                          data, data_len+ETH_FRAME_HDR_SIZE,
                          0,
                          //(struct sockaddr *) (0), (socklen_t)(0));
	                      (struct sockaddr*)&rsa,
	                      sizeof( rsa));
    if (send_result == -1) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "sendto");
        return -1;
    }
    return 0;
}



//==================================
//     Higher Level Functions
//==================================

int
toggle_listen_slac_assn(ethconn_t* ethconn, uint8_t dest_mac[6], bool listen )
{
    uint8_t ethframe[ETH_FRAME_LEN];
    uint8_t* payload = ethframe + ETH_FRAME_HDR_SIZE;
    size_t payload_len;
    const uint8_t listen_payload[3] = { 0x00, 0x0b, 0x01 };
    const uint8_t stoplisten_payload[4] = { 0x00, 0x0b, 0x03, 0x00 };
    ethwritehdr(ethframe, ethconn, dest_mac);
    if( listen ){
        memcpy(payload, listen_payload, 3);
        memset(payload + 3, 0, 58);
        payload_len = 61;
    } else {
        memcpy(payload, stoplisten_payload, 4);
        payload_len = 4;
    }
    int err = ethsend( ethconn, ethframe, ETH_FRAME_HDR_SIZE + payload_len );
    if( err == -1 ) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "plc_eth_send");
    }
    return err;
}
/*
int terminate_dlink(ethconn_t* ethconn, byte dest_mac[6], bool resetup)
{
    byte ethframe[ETH_FRAME_LEN];
    byte* payload = ethframe + ETH_FRAME_HDR_SIZE;
    size_t payload_len;
    byte payload[62];
    int err;
    payload[0] = 0x0b;
    payload[1] = 0x07;
    payload[2] = !resetup;
    memset(payload+3, 0, 58);
    err = ethsend(ethconn, dest_mac, payload, 61);
    if( err == -1 ) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "plc_eth_send");
    }
    return err;
}*/

int switch_power_line(char* if_name, uint8_t dest_mac[6], bool toggle_powerline)
{
    ethconn_t ethconn;
    ethdial(&ethconn, if_name, 0xcafe);

    uint8_t ethframe[ETH_FRAME_LEN];
    uint8_t* payload = ethframe + ETH_FRAME_HDR_SIZE;
    size_t payload_len;
    const uint8_t powerline_payload[3] = { 0x00, 0x0f, 0x10 };
    const uint8_t pilotline_payload[3] = { 0x00, 0x0f, 0x0e };
    ethwritehdr(ethframe, &ethconn, dest_mac);
    if( toggle_powerline ){
        memcpy(payload, powerline_payload, 3);
        memset(payload + 3, 0, 58);
        payload_len = 61;
    } else {
        memcpy(payload, pilotline_payload, 3);
        memset(payload + 3, 0, 58);
        payload_len = 61;
    }
    int err = ethsend( &ethconn, ethframe, ETH_FRAME_HDR_SIZE + payload_len );
    if( err == -1 ) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "plc_eth_send");
    }
    ethclose(&ethconn);
    return err;
}

uint16_t get_slac_type(uint8_t* buf)
{
    size_t i = ETH_FRAME_HDR_SIZE + 1;
    return (buf[i] << 8) + buf[i+1];
}

/*void tcp_comm(){
    int tcp_socket = socket( AF_INET, SOCK_STREAM, 0);

}*/
