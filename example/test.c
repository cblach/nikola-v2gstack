#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "nikolav2g.h"
//#include <net/if.h>
#include "plc_eth.h"
void ev_example(char *if_name);
void evse_example(char *if_name);
int slac_associate(char *if_name);
void plgp_slac_listen(char *if_name, uint8_t dest_mac_evse[6]);
typedef enum { EVSE_NODE, EV_NODE } node_type_t;

int Node_Type = EVSE_NODE;
bool Slac_Enable = false;
char V2G_Network_Interface[IFNAMSIZ] = "eth0";

void parseFlags(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "i:t:v")) != -1) {
        switch (opt) {
        case 'i':
            if (optarg) {
                printf("Interface %s used for PLC modem connection\n", optarg);
                strcpy(V2G_Network_Interface, optarg);
            } else {
                printf("Error: Empty interface name\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 't':
            if (strcasecmp(optarg, "EVSE") == 0) {
                Node_Type = EVSE_NODE;
                printf("Starting service in EVSE mode\n");
            } else if (strcasecmp(optarg, "EV") == 0) {
                Node_Type = EV_NODE;
                printf("Starting service in EV mode\n");
            } else {
                printf("Error: unknown node type %s\n, defaulting to EVSE\n", optarg);
            }
            break;
        case 'v': // Verbose
            chattyv2g = 1;
            break;
        case ':':
            fprintf(stderr, "Option -%c requires an operand\n", optopt);
            exit(EXIT_FAILURE);
        case '?':
            fprintf(stderr, "Unrecognized option: -%c\n", optopt);
            exit(EXIT_FAILURE);
        default:
            fprintf(stderr, "Usage: %s [-i interface] [-t node type]\n",
                   argv[0]);
            exit(EXIT_FAILURE);
        }
    }
}

static uint8_t EVMAC[6] = {0x00, 0x05, 0xB6, 0x01, 0x86, 0xBD};
static uint8_t EVSEMAC[6] = {0x00, 0x05, 0xB6, 0x01, 0x88, 0xA3};


int chattyv2g = 0; // == 0 means no error messages
void
threadmain(int argc,
       char *argv[])
{
    parseFlags(argc, argv);
    //testEth();
    if (Node_Type == EV_NODE) {
        if (Slac_Enable) {
            switch_power_line(V2G_Network_Interface, EVMAC, false);
            printf("=== STARTING SLAC ASSOCIATION ===\n");
            while(slac_associate(V2G_Network_Interface) != 0) {
                printf("something went wrong, trying again\n");
            }
            printf("Slac is done. Waiting 8 seconds for networks to form.\n");
            sleep(8);
        }
        ev_example(V2G_Network_Interface);
        //struct ev_request_t req;
    } else if (Node_Type == EVSE_NODE) {
        switch_power_line(V2G_Network_Interface, EVSEMAC, false);
        if (Slac_Enable) {
            printf("SLAC enabled\n");
            plgp_slac_listen(V2G_Network_Interface, EVSEMAC);
        }
        evse_example(V2G_Network_Interface);
    }
    printf("Exiting\n");
    exit(0);
}
