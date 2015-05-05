#ifndef SERVER_H
#define SERVER_H
extern int secc_free_charge;
#include <OpenV2G/v2gEXIDatatypes.h>
#include <polarssl/x509.h>

typedef struct session_data session_data_t;
struct session_data {
    uint8_t evcc_id[6]; // EV mac address
    struct v2gSelectedServiceType services[v2gSelectedServiceListType_SelectedService_ARRAY_SIZE];
    v2gEnergyTransferModeType energy_transfer_mode;
    v2gpaymentOptionType payment_type;
    struct v2gSAScheduleListType SAScheduleList;
    bool SAScheduleList_isUsed;
    uint8_t challenge[16];
    bool verified;
    bool charging;
    bool tls_enabled;
    bool renegotiation_required;
    struct{
        bool valid_crt; // Before a contract can be valid, it must have a valid crt
        //byte cert[v2gCertificateChainType_Certificate_BYTES_SIZE];
        //size_t cert_len;
        x509_crt crt;
        ecdsa_context pubkey;
    } contract;
};
void session_data_cleanup(session_t *s);
void init_v2g_response(struct v2gEXIDocument *exiOut, session_t *s);
int verify_charging_profile(session_data_t *sd, uint8_t tupleid, struct v2gChargingProfileType *profile);

extern x509_crt Trusted_contract_rootcert_chain;

int create_response_message(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut, bool tls_enabled);


int handle_session_setup(struct v2gEXIDocument *exiIn,
                         struct v2gEXIDocument *exiOut,
                         session_t *s, session_data_t *sd);
int handle_service_discovery(struct v2gEXIDocument *exiIn,
                             struct v2gEXIDocument *exiOut,
                             session_t *s, session_data_t *sd);
int payment_service_selection(struct v2gEXIDocument *exiIn,
                              struct v2gEXIDocument *exiOut,
                              session_t *s, session_data_t *sd);
int handle_service_detail(struct v2gEXIDocument *exiIn,
                          struct v2gEXIDocument *exiOut,
                          session_t *s, session_data_t *sd);
int handle_payment_detail(struct v2gEXIDocument *exiIn,
                          struct v2gEXIDocument *exiOut,
                          session_t *s, session_data_t *sd);
int handle_authorization(struct v2gEXIDocument *exiIn,
                         struct v2gEXIDocument *exiOut,
                         session_t *s, session_data_t *sd);
int handle_charge_parameters(struct v2gEXIDocument *exiIn,
                             struct v2gEXIDocument *exiOut,
                             session_t *s, session_data_t *sd);
int handle_power_delivery(struct v2gEXIDocument *exiIn,
                          struct v2gEXIDocument *exiOut,
                          session_t *s, session_data_t *sd);
int handle_charging_status(struct v2gEXIDocument *exiIn,
                           struct v2gEXIDocument *exiOut,
                           session_t *s, session_data_t *sd);
int handle_session_stop(struct v2gEXIDocument *exiIn,
                        struct v2gEXIDocument *exiOut,
                        session_t *s, session_data_t *sd);

#endif
