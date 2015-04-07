#include "plc_eth.h"
#include <stdio.h>
#include "multitask.h"

typedef uint8_t byte;
struct plgp_slac_args{
    char* if_name;
    byte* evse_mac;
};
void plgp_slac_listen_blocking(void* vargs)
{
    struct plgp_slac_args* args = (struct plgp_slac_args*)vargs;
    ethconn_t ethconn;
    byte buffer[ETH_FRAME_LEN];
    int err;
    ssize_t n;
    char if_name[IFNAMSIZ];
    byte dest_mac_evse[6];
    //Chan c1;
    strcpy(if_name, args->if_name);
    memcpy(dest_mac_evse, args->evse_mac, 6);
    rendez(vargs, NULL);
   // memcpy(dest_mac_evse, ETH_LOCAL_ATHEROS_DEVICE, 6);
    err = ethdial( &ethconn, if_name, ETH_P_SLAC);
    if( err != 0 ) {
        perror("dial");
        exit(1);
    }
    toggle_listen_slac_assn(&ethconn, dest_mac_evse, false);
    toggle_listen_slac_assn(&ethconn, dest_mac_evse, true);
    printf("start SlAC listen!\n");
    /*chaninit(&c1, sizeof(int), 32);
    recv_eth_chan(&ethconn, &c1);
    while(1){
        int i;
        chanrecv(&c1, &i);
        printf( "\nyup\n, sz = %d\n", i);
    }*/
    while(1){
        n = ethrecv( &ethconn, buffer );
        uint16_t slac_type = get_slac_type(buffer);
        //if (slac_type  == SLAC_RES_DLINK_READY && buffer[17] == 0x01) {
        if (slac_type  == 0xb09 && buffer[17] != 0x01) {
            toggle_listen_slac_assn(&ethconn, dest_mac_evse, false);
            toggle_listen_slac_assn(&ethconn, dest_mac_evse, true);
            //terminate_dlink(&ethconn, true);
        } else {
            switch (slac_type) {
            case 0x0b02:
                if (buffer[17] != 0x01){
                    print_byte_arr(buffer, n);
                } else {
                    printf(".");
                    fflush(stdout);
                }
                break;
            case 0x0b04:
                if (buffer[17] != 0x01){
                    print_byte_arr(buffer, n);
                }
                break;
            case 0x0b06:
                if (buffer[17] != 0x01){
                    printf("YAY, link established %u\n", buffer[17]);

                }
                break;
            case 0x0b05:
                printf("Attenuation profile received\n");
                print_byte_arr(buffer, n);
                break;
            default:
                printf("unexpected slac type %0x\n", slac_type);
                print_byte_arr(buffer, n);
                break;
            }
        }
    }
}
void plgp_slac_listen(char* if_name, byte dest_mac_evse[6])
{
    struct plgp_slac_args args = {.if_name = if_name,
                                  .evse_mac = dest_mac_evse};
    threadcreate(plgp_slac_listen_blocking, &args, 1024 * 1024);
    rendez(&args, NULL);
}
