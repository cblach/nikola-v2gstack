#ifndef EXAMPLE_CLIENT_H
#define EXAMPLE_CLIENT_H

typedef struct ev_session ev_session_t;
struct ev_session{
    uint64_t id;
    uint16_t charge_service_id;
    uint8_t challenge[16];
    struct{
        bool is_used;
        uint8_t tupleid;
    } pmax_schedule;
    struct{
        uint8_t cert[v2gCertificateChainType_Certificate_BYTES_SIZE];
        size_t cert_len;
        uint8_t  sub_certs[v2gSubCertificatesType_Certificate_ARRAY_SIZE][v2gCertificateChainType_Certificate_BYTES_SIZE];
        size_t subcert_len[v2gSubCertificatesType_Certificate_ARRAY_SIZE];
        ecdsa_context key;
        entropy_context entropy;
        ctr_drbg_context ctr_drbg;
    } contract;
};
void evcc_session_cleanup(ev_session_t* s);
int load_contract(const char *pemchain_path, const char *keyfile_path, ev_session_t *s);
int sign_auth_request(struct v2gAuthorizationReqType *req,
                      ecdsa_context *key,
                      ctr_drbg_context *ctr_drbg,
                      struct v2gSignatureType *sig);
int session_request(evcc_conn_t *conn, ev_session_t *s);
int service_discovery_request(evcc_conn_t *conn, ev_session_t *s);
int payment_selection_request(evcc_conn_t *conn, ev_session_t *s);
int payment_details_request(evcc_conn_t *conn, ev_session_t *s);
int authorization_request(evcc_conn_t *conn, ev_session_t *s);
int charge_parameter_request(evcc_conn_t *conn, ev_session_t *s);int power_delivery_request(evcc_conn_t *conn, ev_session_t *s);
int charging_status_request(evcc_conn_t *conn, ev_session_t *s);
int session_stop_request(evcc_conn_t *conn, ev_session_t *s);

#endif
