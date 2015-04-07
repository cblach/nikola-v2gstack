#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if_packet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
// Arm tasks
//  zhasha: http://sprunge.us/NbFA task-arm.s
//  http://sprunge.us/aahI task-386.s

// Powerline GP Reference:
//http://www.insys-icom.com/bausteine.net/f/10637/HB_en_INSYS_Powerline_GP_1401.pdf?fd=0#page=36

#ifndef PLC_ETH_H
#define PLC_ETH_H 1
static const size_t ETH_FRAME_HDR_SIZE = 14;
static const size_t ETH_FRAME_MIN_PAYLOAD_SIZE = 46;
static const size_t ETH_FRAME_MIN_SIZE = ETH_FRAME_HDR_SIZE + ETH_FRAME_MIN_PAYLOAD_SIZE;

static uint8_t ETH_BROADCAST_ADDR[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t ETH_LOCAL_ATHEROS_DEVICE[ETH_ALEN] = {0x00, 0xb0, 0x52, 0x00, 0x00, 0x01};

#define ETH_P_HPAV 0x88E1
#define ETH_P_TOGGLE_PILOT 0xcafe
#define ETH_P_SLAC 0xabba

#define SLAC_RES_DLINK_READY 0x0b06

typedef struct {
	int sockfd;
	int if_index;
	uint8_t src_mac[6];
//	byte dest_mac[6];
	uint16_t protocol;
//	struct sockaddr_ll rsaddr;
} ethconn_t;

//=======================================0
// Note that ALL receiving buffers must
// be at least ETH_FRAME_LEN bytes long
int ethdial(ethconn_t *eth_conn,
            const char *if_name,
              //byte dest_mac[6],
            uint16_t protocol);
int ethclose(ethconn_t *eth_conn);

ssize_t ethrecv(ethconn_t *eth_conn ,
			void *buffer);
ssize_t ethrecvfrom(ethconn_t *eth_conn ,
				void *buffer,
				uint8_t remote_mac[ETH_ALEN]);

int ethsend(ethconn_t *ethconn,
            void *payload,
            size_t payload_len);
void ethwritehdr(void *vbuf, ethconn_t *ethconn, uint8_t destmac[6]);

//===== HIGHER LEVEL STUFF ======

void recv_eth_package(void *arg);

int switch_power_line(const char *if_name, uint8_t dest_mac[6], bool powerline);

int
toggle_listen_slac_assn(ethconn_t *ethconn,uint8_t dest_mac[6], bool listen);
//int terminate_dlink(struct ethconn_t *ethconn,byte dest_mac[6], bool resetup);

uint16_t get_slac_type(uint8_t *buf);

void print_byte_arr(void *arr, size_t n);
#endif
