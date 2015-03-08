#include "v2gEXIDatatypes.h"
#include "multitask.h"
#include <netinet/in.h>
#include "polarssl/ctr_drbg.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#ifndef SECC_H
#define SECC_H 1

//=============
//    SDP
//=============
int ev_sdp_discover_evse( char* if_name, struct sockaddr_in6* evse_addr );
//void evse_sdp_listen_discovery_msg( void* args );
void sdp_listen(char* if_name, int tls_port);
//==============
//    TLS
//==============
typedef uint8_t byte;
int secc_listen_tls(int, int ( *handle_func )( struct v2gEXIDocument*,
                                                struct v2gEXIDocument* ));
int bind_tls();
struct ev_blocking_request_t;
struct ev_tls_conn_t{
	bool alive;
    struct sockaddr_in6 addr;
    ssl_context ssl;
    QLock mutex;
    Chan kill_chan;
    // The connection keeps a queue of waiting requests to respond in correct order.
    struct ev_blocking_request_t* first_req;
    struct ev_blocking_request_t* last_req;

    // Stored here due to cleanup:
    int serverfd;
    x509_crt cacert;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
};

int new_request( struct ev_tls_conn_t* conn, byte* buffer,
                 size_t request_len, size_t buffer_len );

int evcc_connect_tls( struct ev_tls_conn_t* conn );

int v2g_request( struct ev_tls_conn_t* conn, struct v2gEXIDocument* exiIn, struct v2gEXIDocument* exiOut);


//==================
//      Session
//==================
enum session_status { SESSION_ACTIVE, SESSION_PAUSED, SESSION_TERMINATED };

typedef struct{
    uint8_t evcc_id[6]; // EV mac address
    struct v2gSelectedServiceType services[v2gSelectedServiceListType_SelectedService_ARRAY_SIZE];
    v2gEnergyTransferModeType energy_transfer_mode;
    v2gpaymentOptionType payment_type;
    byte challenge[16];
    struct{
        bool valid_crt; // Before a contract can be valid, it must have a valid crt
        bool valid;
        byte cert[v2gCertificateChainType_Certificate_BYTES_SIZE];
        size_t cert_len;
        x509_crt crt;
        ecdsa_context pubkey;
    } contract;
    // === DO NOT MANIPULATE THE FOLLOWING FIELDS ===
    uint64_t id;
    QLock mutex;
    int refcount;
    enum session_status status;
}session_t;

int gen_random_data(void* dest, size_t dest_len);
int init_sessions();
session_t* session_new();
session_t* session_lookup( uint64_t sessionid );
session_t* session_lookup_exi(struct v2gEXIDocument* exiIn);
void session_lock(session_t* session);
void session_unlock(session_t* session);
void session_terminate( session_t* session );
void session_remove_ref(session_t* session);


#define ERROR_UNEXPECTED_REQUEST_MESSAGE -601
#define ERROR_UNEXPECTED_SESSION_SETUP_RESP_MESSAGE -602
#define ERROR_UNEXPECTED_SERVICE_DISCOVERY_RESP_MESSAGE -602
#define ERROR_UNEXPECTED_SERVICE_DETAILS_RESP_MESSAGE -603
#define ERROR_UNEXPECTED_PAYMENT_SERVICE_SELECTION_RESP_MESSAGE -604
#define ERROR_UNEXPECTED_PAYMENT_DETAILS_RESP_MESSAGE -605
#define ERROR_UNEXPECTED_AUTHORIZATION_RESP_MESSAGE -606
#define ERROR_UNEXPECTED_CHARGE_PARAMETER_DISCOVERY_RESP_MESSAGE -607
#define ERROR_UNEXPECTED_POWER_DELIVERY_RESP_MESSAGE -608
#define ERROR_UNEXPECTED_CHARGING_STATUS_RESP_MESSAGE -609
#define ERROR_UNEXPECTED_METERING_RECEIPT_RESP_MESSAGE -610
#define ERROR_UNEXPECTED_SESSION_STOP_RESP_MESSAGE -611
#define ERROR_UNEXPECTED_CABLE_CHECK_RESP_MESSAGE -612
#define ERROR_UNEXPECTED_PRE_CHARGE_RESP_MESSAGE -612
#define ERROR_UNEXPECTED_CURRENT_DEMAND_RESP_MESSAGE -613
#define ERROR_UNEXPECTED_WELDING_DETECTION_RESP_MESSAGE -614

#endif
