#include <stdio.h>
#include <multitask.h>
#include <nikolav2g.h>
#include "plc_eth.h"

typedef uint8_t byte;

typedef struct plgp_slac_args plgp_slac_args_t;
struct plgp_slac_args{
    const char *if_name;
    byte *evse_mac;
};

static void dumpbytes(const void *data, size_t len)
{
    const byte *d = data;
    size_t i, j;

    if (!chattyv2g) { return; }

    for (i = 0; i < len; i += 16) {
        fprintf(stderr, " ");
        for (j = 0; j < 16 && i + j < len; ++j) {
            fprintf(stderr, " %02X", d[i + j]);
        }
        fprintf(stderr, "\n");
    }
}

void plgp_slac_listen_blocking(void *vargs)
{
    plgp_slac_args_t *args = (plgp_slac_args_t*)vargs;
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
    err = ethdial(&ethconn, if_name, ETH_P_SLAC);
    if (err != 0) {
        perror("dial");
        exit(1);
    }
    toggle_listen_slac_assn(&ethconn, dest_mac_evse, false);
    toggle_listen_slac_assn(&ethconn, dest_mac_evse, true);
    printf("Starting SLAC listener!\n");
    while (1) {
        n = ethrecv(&ethconn, buffer);
        uint16_t slac_type = get_slac_type(buffer);
        //if (slac_type  == SLAC_RES_DLINK_READY && buffer[17] == 0x01) {
        if (slac_type  == 0xb09 && buffer[17] != 0x01) {
            toggle_listen_slac_assn(&ethconn, dest_mac_evse, false);
            toggle_listen_slac_assn(&ethconn, dest_mac_evse, true);
            //terminate_dlink(&ethconn, true);
        } else {
            switch (slac_type) {
            case 0x0b02:
                if (buffer[17] != 0x01) {
                    dumpbytes(buffer, n);
                } else {
                    printf(".");
                    fflush(stdout);
                }
                break;
            case 0x0b04:
                if (buffer[17] != 0x01) {
                    dumpbytes(buffer, n);
                }
                break;
            case 0x0b06:
                if (buffer[17] != 0x01) {
                    printf("Data Link Established!\n");

                }
                break;
            case 0x0b05:
                printf("Attenuation profile received\n");
                //dumpbytes(buffer, n);
                break;
            default:
                printf("unexpected slac type %0x\n", slac_type);
                dumpbytes(buffer, n);
                break;
            }
        }
    }
}
int plgp_slac_listen(const char *if_name, byte dest_mac_evse[6])
 {
    plgp_slac_args_t args = {
        .if_name = if_name,
        .evse_mac = dest_mac_evse
    };
    if (threadcreate(plgp_slac_listen_blocking, &args, 1024 * 1024) < 0) {
        return -1;
    }
    rendez(&args, NULL);
    return 0;
}
