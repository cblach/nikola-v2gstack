#include <stdio.h>
#include <stdlib.h>
//#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "v2gstack.h"
//#include <net/if.h>
#include "plc_eth.h"

void ev_example(char* if_name);
void evse_example(char* if_name);
int slac_associate(char* if_name);
void plgp_slac_listen(char* if_name, byte dest_mac_evse[6]);
typedef enum { EVSE_NODE, EV_NODE } node_type_t;

int Node_Type = EVSE_NODE;
bool Slac_Enable = true;
char V2G_Network_Interface[IFNAMSIZ] = "eth0";

void parseFlags( int argc, char **argv ){
    int i;
    for (i = 1; i < argc;  i++) {
        if( strcmp(argv[i], "-t" ) == 0) {
            i++;
            if (i < argc) {
                if( strcasecmp(argv[i], "EVSE") == 0 ){
                    Node_Type = EVSE_NODE;
                    printf("Starting service in EVSE mode\n");
                } else if (strcasecmp(argv[i], "EV") == 0) {
                    Node_Type = EV_NODE;
                    printf("Starting service in EV mode\n");
                } else {
                    printf("Error: unknown node type %s\n, defaulting to EVSE\n",argv[i+1]);
                }
            }
        } else if (strcmp(argv[i], "-i" ) == 0) {
            i++;
            if (i < argc) {
                printf( "Interface %s used for PLC modem connection\n", argv[i]);
                strcpy(V2G_Network_Interface, argv[i]);
            }
        } else {
            printf("Error: unknown flag %s\n",argv[i]);
        }
    }
}


static byte EVMAC[6] = {0x00, 0x05, 0xB6, 0x01, 0x86, 0xBD};
static byte EVSEMAC[6] = {0x00, 0x05, 0xB6, 0x01, 0x88, 0xA3};
void
threadmain( int argc,
       char *argv[] )
{
    parseFlags( argc, argv );
    //testEth();
    if( Node_Type == EV_NODE ) {
        if (Slac_Enable) {
            switch_power_line(V2G_Network_Interface, EVMAC, false);
            printf("=== STARTING SLAC ASSOCIATION ===\n");
            while(slac_associate(V2G_Network_Interface) != 0){
                printf("something went wrong, trying again\n");
            }
            printf("Slac is done. Waiting 8 seconds for networks to form.\n");
            sleep(8);
        }
        ev_example(V2G_Network_Interface);
        //struct ev_request_t req;
    } else if( Node_Type == EVSE_NODE ) {
        switch_power_line(V2G_Network_Interface, EVSEMAC, false);
        if (Slac_Enable) {
            printf("SLAC enabled\n");
            plgp_slac_listen(V2G_Network_Interface, EVSEMAC);
        }
        evse_example(V2G_Network_Interface);
    }

    //sleep( 10 );
    //eth_close(&ethconn);
    printf("Exiting\n");
    exit(0);
}

/*int
main( int argc,
      char *argv[] )
{
    thread_main(tmain, argc, argv);
    return 0;
}*/
