#include "OpenV2G/v2gEXIDatatypes.h"
#include "multitask.h"
#include <netinet/in.h>
#include "polarssl/ctr_drbg.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#ifndef SECC_H
#define SECC_H 1

// Verbose flag (set before running anything in this library):
extern int chattyv2g;

//=============
//    SDP
//=============
int ev_sdp_discover_evse(const char *if_name,
                         struct sockaddr_in6 *evse_addr,
                         bool tls_enabled);
void sdp_listen(const char *if_name, int tls_port, int tcp_port);
//==============
//    TLS
//==============
typedef int (*handle_func_t)(struct v2gEXIDocument*,
                             struct v2gEXIDocument*);
void secc_listen_tls(int, handle_func_t, const char *crt_path, const char *key_path);
void secc_listen_tcp(int, handle_func_t);
int bind_v2gport();
struct ev_blocking_request_t;

// SECC connection Context that allows either for an fd or an ssl context
typedef struct{
    bool tls_enabled;
    int sockfd;
    ssl_context ssl;
} comboconn_t;
struct ev_tls_conn_t{
	bool alive;
    struct sockaddr_in6 addr;
    bool tls_enabled;
    comboconn_t cconn; // Makes it possible for either TCP or TLS
    QLock mutex;
    Chan kill_chan;
    // The connection keeps a queue of waiting requests to respond in correct order.
    struct ev_blocking_request_t *first_req;
    struct ev_blocking_request_t *last_req;

    // TLS Only stuff Stored here due to cleanup:
    int serverfd;
    x509_crt cacert;
    pk_context pkey;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
};

int evcc_connect_tls(struct ev_tls_conn_t *conn, const char *crt_path, const char *key_path);
int evcc_connect_tcp(struct ev_tls_conn_t *conn);

int v2g_request(struct ev_tls_conn_t *conn, struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);


//==================
//      Session
//==================
enum session_status { SESSION_ACTIVE, SESSION_PAUSED, SESSION_TERMINATED };

typedef struct{
    uint8_t evcc_id[6]; // EV mac address
    struct v2gSelectedServiceType services[v2gSelectedServiceListType_SelectedService_ARRAY_SIZE];
    v2gEnergyTransferModeType energy_transfer_mode;
    v2gpaymentOptionType payment_type;
    struct v2gSAScheduleListType SAScheduleList;
    bool SAScheduleList_isUsed;
    uint8_t challenge[16];
    bool verified;
    struct{
        bool valid_crt; // Before a contract can be valid, it must have a valid crt
        //byte cert[v2gCertificateChainType_Certificate_BYTES_SIZE];
        //size_t cert_len;
        x509_crt crt;
        ecdsa_context pubkey;
    } contract;
    // === DO NOT MANIPULATE THE FOLLOWING FIELDS ===
    bool tls_enabled;
    uint64_t id;
    QLock mutex;
    int refcount;
    enum session_status status;
}session_t;

int gen_random_data(void *dest, size_t dest_len);
int init_sessions();
session_t *session_new();
session_t *session_lookup(uint64_t sessionid);
session_t *session_lookup_exi(struct v2gEXIDocument *exiIn);
void session_lock(session_t *session);
void session_unlock(session_t *session);
void session_terminate(session_t *session);
void session_remove_ref(session_t *session);

#endif
