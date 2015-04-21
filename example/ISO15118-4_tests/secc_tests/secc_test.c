#include <nikolav2g.h>
#include <unistd.h>
#include "client.h"
#include <net/if.h>
#include "powerdeliveryres_test.c"
int session_request(evcc_conn_t *conn, ev_session_t *s);
int service_discovery_request(evcc_conn_t *conn, ev_session_t *s);


static const char *argv0;
int succeses = 0, n = 0;

bool USE_TLS = true;

void usage(void)
{
    fprintf(stderr, "Usage: %s [-sv] [--] interface node-type\n", argv0);
    exit(1);
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


void secc_tester(const char* iface) {
    evcc_conn_t conn;
    ev_session_t s;
    struct sockaddr_in6 secc_tlsaddr, secc_tcpaddr;
    int err;
    memset(&conn, 0, sizeof(conn));
    memset(&s, 0, sizeof(s));

    err = load_contract("../../certs/contractchain.pem", "../../certs/contract.key", &s);
    if (err != 0) {
        printf("ev_example: load_contract error\n");
        return;
    }
    printf("Test %d: SDP with TLS enabled (Security = 0x00)... ", ++n);
    err = ev_sdp_discover_evse(iface, &secc_tlsaddr, true);
    if (err != 0) {
        printf("Test Failed\n");
    } else {
        printf("Success: SDP found TLS on port %u\n", secc_tlsaddr.sin6_port);
        succeses++;
    }
    printf("Test %d: SDP with TLS disabled (Security = 0x10... ", ++n);
    err = ev_sdp_discover_evse(iface, &secc_tcpaddr, false);
    if (err != 0) {
        printf("Test Failed\n");
    } else {
        test_validate_port(&secc_tcpaddr);
    }
    printf("Test %d: TLS serving & 15118 Protocol Handshake\n", ++n);
    if (USE_TLS && secc_tlsaddr.sin6_port != 0) {
        memcpy(&conn.addr, &secc_tlsaddr, sizeof(conn.addr));
        err = evcc_connect_tls(&conn, "../../certs/ev.pem", "../../certs/ev.key");
    } else if (!USE_TLS && secc_tlsaddr.sin6_port != 0) {
        memcpy(&conn.addr, &secc_tcpaddr, sizeof(conn.addr));
        err = evcc_connect_tcp(&conn);
    } else {
        printf("Unable to proceed as SDP found no viable port for chosen security\n");
        return;
    }
    if (err != 0) {
        printf("Connect failed, unable to proceed\n");
        return;
    }
    succeses++;
    printf("Test %d: Session Response\n", ++n);
    err = session_request(&conn, &s);
    if (err != 0 || s.id == 0) {
        printf("Test Failed: Session Setup. Unable to proceed.\n");
        return;
    }
    succeses++;
    printf("Test %d: Service Discovery Response\n", ++n);
    err = service_discovery_request(&conn, &s);
    if (err != 0) {
        printf("Test Failed: Service Discovery to proceed.\n");
        return;
    }
    succeses++;
   err = payment_selection_request(&conn, &s);
    if (err != 0) {
        printf("ev_example: payment_selection_request err\n");
        return;
    }
    err = payment_details_request(&conn, &s);
    if (err != 0) {
        printf("ev_example: payment_details_request err\n");
        return;
    }
    err = authorization_request(&conn, &s);
    if (err != 0) {
        printf("ev_example: authorization_request err\n");
        return;
    }
    err = charge_parameter_request(&conn, &s);
    if (err != 0) {
        printf("ev_example: charge_parameter_request err\n");
        return;
    }
    printf("Test %d: Power Delivery Response\n", ++n);
    err = test_power_delivery_request1(&conn, &s);
    if (err != 0) {
        printf("Test Failed: test_power_delivery_request1.\n");
        return;
    }
    succeses++;
    printf("Test %d: Power Delivery Response\n", ++n);
    err = test_power_delivery_request2(&conn, &s);
    if (err != 0) {
        printf("Test Failed: test_power_delivery_request2.\n");
        return;
    }
    succeses++;
    printf("Test %d: Power Delivery Response\n", ++n);
    err = test_power_delivery_request3(&conn, &s);
    if (err != 0) {
        printf("Test Failed: test_power_delivery_request3.\n");
        return;
    }
    succeses++;
    printf("Test %d: Power Delivery Response\n", ++n);
    err = test_power_delivery_request4(&conn, &s);
    if (err != 0) {
        printf("Test Failed: test_power_delivery_request4.\n");
        return;
    }
    succeses++;
    printf("Test %d: Power Delivery Response\n", ++n);
    err = test_power_delivery_request5(&conn, &s);
    if (err != 0) {
        printf("Test Failed: test_power_delivery_request5.\n");
        return;
    }
    succeses++;
}


void threadmain(int argc,
       char *argv[])
{
    const char *iface;
    int opt, notls = 0;

    argv0 = argv[0];
    while ((opt = getopt(argc, argv, "vn")) != -1) {
        switch (opt) {
        /*case 's':
            slac++;
            break;*/
        case 'v':
            chattyv2g++;
            break;
        case 'n': // no tls
            notls++;
            break;
        default:
            usage();
        }
    }
    if (optind >= argc) { usage(); }
    iface = argv[optind];
    printf("LLOLOLLOOOLLOLOLOOLOLOLOLOL %s\n", iface);
    secc_tester(iface);
    printf("Done testing, %d of %d tests were succesful\n", succeses, n);
    exit(0);
}
