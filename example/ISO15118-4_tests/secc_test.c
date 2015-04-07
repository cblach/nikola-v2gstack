#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include "nikolav2g.h"
#include "example_client.c"




int testnumber = 0, succeses = 0;

bool USE_TLS = true;
const char V2G_Network_Interface[IFNAMSIZ] = "eth0";

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
        case 'v': // Verbose
            chattyv2g = 1;
            break;
        case ':':
            fprintf(stderr, "Option -%c requires an operand\n", optopt);
            exit(EXIT_FAILURE);
        case '?':
            fprintf(stderr, "Unrecognized option: -%c\n", optopt);
            exit(EXIT_FAILURE);
        default: /* '?' */
            fprintf(stderr, "Usage: %s [-i interface] [-t node type]\n",
                   argv[0]);
            exit(EXIT_FAILURE);
        }
    }
}

void test_validate_port(struct sockaddr_in6 *addr)
{
    if (addr->sin6_port == 0) {
        printf("Test Failed\n");
    } else {
        printf("Success: SDP found TCP on port %u\n", addr->sin6_port);
        succeses++;
    }
}


int chattyv2g = 0;
void threadmain(int argc,
       char *argv[])
{
    struct ev_tls_conn_t conn;
    ev_session_t ev_session;
    struct sockaddr_in6 secc_tlsaddr, secc_tcpaddr;
    int err, tls_port, tcp_port, n = 0;
    parseFlags(argc, argv);
    printf("Test %d: SDP with TLS enabled (Security = 0x00)... ", ++n);
    tls_port = ev_sdp_discover_evse(V2G_Network_Interface, &secc_tlsaddr, true);
    if (secc_tlsaddr.sin6_port == 0) {
        printf("Test Failed\n");
    } else {
        printf("Success: SDP found TLS on port %u\n", secc_tlsaddr.sin6_port);
        succeses++;
    }
    printf("Test %d: SDP with TLS disabled (Security = 0x10... ", ++n);
    err = ev_sdp_discover_evse(V2G_Network_Interface, &secc_tcpaddr, false);
    if (err != 0) {
        printf("Test Failed\n");
    } else {
        test_validate_port(&secc_tcpaddr);
    }
    memset(&conn, 0, sizeof(struct ev_tls_conn_t));
    printf("Test %d: TLS serving & 15118 Protocol Handshake\n", ++n);
    if (USE_TLS && secc_tlsaddr.sin6_port != 0) {
        memcpy(&conn.addr, &secc_tlsaddr, sizeof(conn.addr));
        err = evcc_connect_tls(&conn, "../certs/ev.pem", "../certs/ev.key");
    } else if (!USE_TLS && secc_tlsaddr.sin6_port != 0) {
        memcpy(&conn.addr, &secc_tcpaddr, sizeof(conn.addr));
        err = evcc_connect_tcp(&conn);
    } else {
        printf("Unable to proceed as SDP found no viable port for chosen security\n");
        goto exit;
    }
    if (err != 0) {
        printf("Connect failed, unable to proceed\n");
        goto exit;
    }
    succeses++;
    printf("Test %d: Session Response\n", ++n);
    memset(&ev_session, 0, sizeof(ev_session_t));
    err = session_request(&conn, &ev_session);
    if (err != 0) {
        printf("Test Failed: Session Setup. Unable to proceed.\n");
        goto exit;
    }
    succeses++;
    if (ev_session.id == 0) {
        printf("Test Failed: Session Setup. Unable to proceed.\n");
        goto exit;
    }
    succeses++;
    printf("Test %d: Service Discovery Response\n", ++n);
    err = service_discovery_request(&conn, &ev_session);
    if (err != 0) {
        printf("Test Failed: Service Discovery to proceed.\n");
        goto exit;
    }
    exit:
    printf("Done testing, %d of %d tests were succesful\n", succeses, n);
    exit(0);
}
