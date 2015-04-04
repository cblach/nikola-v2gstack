#include <stdio.h>
#include "v2gstack.h"
#include "EXITypes.h"
#include "v2gEXIDatatypes.h"
#include "v2gEXIDatatypesEncoder.h"
#include "xmldsigEXIDatatypes.h"
#include "xmldsigEXIDatatypesEncoder.h"
#include "v2gtp.h"
#include <string.h>
#include <unistd.h>
#include "polarssl/pk.h"
#include "polarssl/ecdsa.h"
#include <fcntl.h>
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"


typedef struct ev_session{
    uint64_t id;
    uint16_t charge_service_id;
    byte challenge[16];
    struct{
        bool is_used;
        uint8_t tupleid;
    } pmax_schedule;
    struct{
        byte cert[v2gCertificateChainType_Certificate_BYTES_SIZE];
        size_t cert_len;
        byte sub_certs[v2gSubCertificatesType_Certificate_ARRAY_SIZE][v2gCertificateChainType_Certificate_BYTES_SIZE];
        size_t subcert_len[v2gSubCertificatesType_Certificate_ARRAY_SIZE];
        ecdsa_context key;
        entropy_context entropy;
        ctr_drbg_context ctr_drbg;
    } contract;
}ev_session_t;

//=========================================
//            Utility Functions
//=========================================

ssize_t read_file( char* path, void* buf, size_t buf_len)
{
    int fd;
    ssize_t len;
    ssize_t n = 0;
    fd = open(path, O_RDONLY);
    if (fd < 0){
        return -1;
    }
    while (buf_len - n > 0) {
        len = read(fd, (char*)buf + n, buf_len - n);
        switch (len) {
        case -1:
            perror("readfile: read");
            close(fd);
            return -1;
        case 0: // EOF
            close(fd);
            return n;
        }
        n += len;
    }
    printf("File too long for buffer. Must be smaller than %zd bytes\n", buf_len);
    close(fd);
    return -1;
}

int load_contract(char* keyfile_path, ev_session_t* ev_session) {
    int err;
    ssize_t n;
    pk_context pk;
    pk_init(&pk);
    const char *pers = "ecdsa";

    err = pk_parse_keyfile(&pk, keyfile_path, NULL);
    if (err != 0) {
        printf("could not parse keyfile at %s\n",keyfile_path);
        return -1;
    }
    ecp_keypair *kp = pk_ec(pk);
    err = ecdsa_from_keypair(&ev_session->contract.key, kp);
    if (err != 0) {
        printf("could not retrieve ecdsa from keypair at %s\n",keyfile_path);
        return -1;
    }
    n = read_file("certs/contract.pem", &ev_session->contract.cert, v2gCertificateChainType_Certificate_BYTES_SIZE);
    if (n <= 0) {
        printf("load_contract read file error\n");
        return -1;
    }
    ev_session->contract.cert_len = n;
    n = read_file("certs/root/mobilityop/certs/mobilityop.pem", &ev_session->contract.sub_certs[0], v2gCertificateChainType_Certificate_BYTES_SIZE);
    if (n <= 0) {
        printf("load_contract read file error\n");
        return -1;
    }
    ev_session->contract.subcert_len[0] = n;
    entropy_init( &ev_session->contract.entropy );
    if( ( err = ctr_drbg_init( &ev_session->contract.ctr_drbg, entropy_func, &ev_session->contract.entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 ) {
        printf( "load_contract:  failed\n  ! ctr_drbg_init returned %d\n", err );
        return -1;
    }
    return 0;
}

int sign_auth_request(struct v2gAuthorizationReqType* req,
                      ecdsa_context* key,
                      ctr_drbg_context* ctr_drbg,
                      struct v2gSignatureType* sig) {
    int err;
    unsigned char buf[256];
    byte digest[32];
    uint16_t buffer_pos = 0;
    bitstream_t stream = {
        .size = 256,
        .data = buf,
        .pos  = &buffer_pos,
        .buffer = 0,
        .capacity = 8, // Set to 8 for send and 0 for recv
    };
   //struct v2gEXIDocument exiIn;
    struct v2gEXIFragment auth_fragment;
    init_v2gEXIFragment(&auth_fragment);
    auth_fragment.AuthorizationReq_isUsed = 1u;
    memcpy(&auth_fragment.AuthorizationReq, req, sizeof(struct v2gAuthorizationReqType));
    err = encode_v2gExiFragment(&stream, &auth_fragment);
    if (err != 0) {
        printf("error 1: error code = %d\n", err);
        return -1;
    }
    sha256(buf, (size_t)buffer_pos, digest, 0);
    //=======================================
    //      Create signature
    //=======================================
    struct xmldsigEXIFragment sig_fragment;
    struct xmldsigReferenceType* ref = &sig_fragment.SignedInfo.Reference.array[0];
    char uri[4] = {"#ID1"};
	char arrayCanonicalEXI[35] = {"http://www.w3.org/TR/canonical-exi/"};
	char arrayxmldsigSHA256[51] = {"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"};
	char arrayxmlencSHA256[39] = {"http://www.w3.org/2001/04/xmlenc#sha256"};
	init_xmldsigEXIFragment(&sig_fragment);
	sig_fragment.SignedInfo_isUsed = 1;
	init_xmldsigSignedInfoType(&sig_fragment.SignedInfo);
	init_xmldsigCanonicalizationMethodType(&sig_fragment.SignedInfo.CanonicalizationMethod);
	sig_fragment.SignedInfo.CanonicalizationMethod.Algorithm.charactersLen = 35;
	memcpy(sig_fragment.SignedInfo.CanonicalizationMethod.Algorithm.characters, arrayCanonicalEXI, 35);
	sig_fragment.SignedInfo.SignatureMethod.HMACOutputLength_isUsed = 0;
	sig_fragment.SignedInfo.SignatureMethod.Algorithm.charactersLen = 51;
	strncpy(sig_fragment.SignedInfo.SignatureMethod.Algorithm.characters, arrayxmldsigSHA256, 51);
	sig_fragment.SignedInfo.Reference.arrayLen = 1;
	 /* "#ID1" */
	ref->URI_isUsed = 1;
	ref->URI.charactersLen = 4;
	memcpy(ref->URI.characters, uri, 4);
	/* "http://www.w3.org/TR/canonical-exi/" */
	ref->Transforms_isUsed = 1;
	ref->Transforms.Transform.arrayLen = 1;
	ref->Transforms.Transform.array[0].Algorithm.charactersLen = 35;
	strncpy(ref->Transforms.Transform.array[0].Algorithm.characters, arrayCanonicalEXI, 35); /* Will copy 35 characters from arrayCanonicalEXI to characters */
	ref->Transforms.Transform.array[0].XPath.arrayLen = 0;
	ref->DigestMethod.Algorithm.charactersLen = 39;
	strncpy(ref->DigestMethod.Algorithm.characters, arrayxmlencSHA256, 39);
	ref->DigestValue.bytesLen = 32;
	memcpy(ref->DigestValue.bytes, digest, 32);
    buffer_pos = 0;
	err = encode_xmldsigExiFragment(&stream, &sig_fragment);
    if (err != 0) {
        printf("error 2: error code = %d\n", err);
        return -1;
    }
    memcpy(&sig->SignedInfo, &sig_fragment.SignedInfo, sizeof(struct v2gSignedInfoType));
    sha256(buf, buffer_pos, digest, 0);
    err = ecdsa_write_signature( key,
                                 digest, 32,
                                 sig->SignatureValue.CONTENT.bytes,
                                 (size_t*)&sig->SignatureValue.CONTENT.bytesLen,
                                 ctr_drbg_random,
                                 ctr_drbg );
    if (err != 0) {
        printf("ecdsa write sig err\n");
        return -1;
    }
    sig->KeyInfo_isUsed = 0;
	sig->Id_isUsed = 0;
	sig->Object.arrayLen = 1;
	sig->Object.array[0].Id_isUsed = 0;
	sig->Object.array[0].MimeType_isUsed = 0;
	sig->Object.array[0].Encoding_isUsed = 0;
	sig->SignatureValue.Id_isUsed = 0;
    return 0;
}


static void printACEVSEStatus(struct v2gAC_EVSEStatusType* status)
{
	printf("\tEVSEStatus:\n");
	printf("\t\tRCD=%d\n", status->RCD);
	printf("\t\tEVSENotification=%d\n", status->EVSENotification);
	printf("\t\tNotificationMaxDelay=%d\n", status->NotificationMaxDelay);
}

static int verify_response_code(v2gresponseCodeType code)
{
    switch (code) {
    case v2gresponseCodeType_OK:
        return 0;
	case v2gresponseCodeType_OK_NewSessionEstablished:
	    return 0;
	case v2gresponseCodeType_OK_OldSessionJoined:
	    return 0;
	case v2gresponseCodeType_OK_CertificateExpiresSoon:
	    return 0;
    case v2gresponseCodeType_FAILED:
	case v2gresponseCodeType_FAILED_SequenceError:
	case v2gresponseCodeType_FAILED_ServiceIDInvalid:
	case v2gresponseCodeType_FAILED_UnknownSession:
	case v2gresponseCodeType_FAILED_ServiceSelectionInvalid:
	case v2gresponseCodeType_FAILED_PaymentSelectionInvalid:
	case v2gresponseCodeType_FAILED_CertificateExpired:
	case v2gresponseCodeType_FAILED_SignatureError:
	case v2gresponseCodeType_FAILED_NoCertificateAvailable:
	case v2gresponseCodeType_FAILED_CertChainError:
	case v2gresponseCodeType_FAILED_ChallengeInvalid:
	case v2gresponseCodeType_FAILED_ContractCanceled:
	case v2gresponseCodeType_FAILED_WrongChargeParameter:
	case v2gresponseCodeType_FAILED_PowerDeliveryNotApplied:
	case v2gresponseCodeType_FAILED_TariffSelectionInvalid:
	case v2gresponseCodeType_FAILED_ChargingProfileInvalid:
	case v2gresponseCodeType_FAILED_MeteringSignatureNotValid:
	case v2gresponseCodeType_FAILED_NoChargeServiceSelected:
	case v2gresponseCodeType_FAILED_WrongEnergyTransferMode:
	case v2gresponseCodeType_FAILED_ContactorError:
	case v2gresponseCodeType__FAILED_CertificateNotAllowedAtThisEVSE:
	case v2gresponseCodeType_FAILED_CertificateRevoked:
	default:
	    return -1;
    }
}


void init_v2g_request(struct v2gEXIDocument* exiIn, ev_session_t* ev_session)
{
    //memset(exiIn, 0, sizeof(*exiIn));
    init_v2gEXIDocument(exiIn);
	exiIn->V2G_Message_isUsed = 1u;
	init_v2gMessageHeaderType(&exiIn->V2G_Message.Header);
	// Set session id to 0
	if (ev_session == NULL) {
	    memset(exiIn->V2G_Message.Header.SessionID.bytes, 0, 8);
	} else {
	    memcpy(exiIn->V2G_Message.Header.SessionID.bytes, &ev_session->id, 8);
	}
	exiIn->V2G_Message.Header.SessionID.bytesLen = 8;
	exiIn->V2G_Message.Header.Notification_isUsed = 0u; /* no notification */
	exiIn->V2G_Message.Header.Signature_isUsed = 0u;
    init_v2gBodyType(&exiIn->V2G_Message.Body);
}

//=======================
//  Request Definitions
//=======================
int session_request(struct ev_tls_conn_t* conn, ev_session_t* ev_session)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    init_v2g_request(&exiIn, NULL);
	exiIn.V2G_Message.Body.SessionSetupReq_isUsed = 1u;

	init_v2gSessionSetupReqType(&exiIn.V2G_Message.Body.SessionSetupReq);

	exiIn.V2G_Message.Body.SessionSetupReq.EVCCID.bytesLen = 1;
	exiIn.V2G_Message.Body.SessionSetupReq.EVCCID.bytes[0] = 20;

	printf("VAR = %u\n", exiIn.V2G_Message_isUsed);
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("unable to do v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.SessionSetupRes_isUsed != 1u) {
        printf("session_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(exiOut.V2G_Message.Body.SessionSetupRes.ResponseCode) != 0) {
        printf("session_request: session setup response NOT ok, code = %d\n", exiOut.V2G_Message.Body.SessionSetupRes.ResponseCode);
        return -1;
    }
    // === Save session id ===
    memcpy( &ev_session->id, exiOut.V2G_Message.Header.SessionID.bytes, 8);

    return 0;
}

int service_discovery_request(struct ev_tls_conn_t* conn, ev_session_t* ev_session)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    // === Init ===
    init_v2g_request(&exiIn, ev_session);
	exiIn.V2G_Message.Body.ServiceDiscoveryReq_isUsed = 1u;
	init_v2gServiceDiscoveryReqType(&exiIn.V2G_Message.Body.ServiceDiscoveryReq);

    exiIn.V2G_Message.Body.ServiceDiscoveryReq.ServiceCategory_isUsed = 1u;
	exiIn.V2G_Message.Body.ServiceDiscoveryReq.ServiceCategory = v2gserviceCategoryType_EVCharging;
	exiIn.V2G_Message.Body.ServiceDiscoveryReq.ServiceScope_isUsed = 0u;
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("unable to do v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.ServiceDiscoveryRes_isUsed != 1u) {
        printf("service_discovery_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(exiOut.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode) != 0) {
        printf("service_discovery_request: response NOT ok, code = %d\n", exiOut.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode);
        return -1;
    }
    ev_session->charge_service_id = exiOut.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceID;
    return 0;
}

int payment_selection_request(struct ev_tls_conn_t* conn, ev_session_t* ev_session)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    init_v2g_request(&exiIn, ev_session);
	init_v2gPaymentServiceSelectionReqType(&exiIn.V2G_Message.Body.PaymentServiceSelectionReq);
    exiIn.V2G_Message.Body.PaymentServiceSelectionReq_isUsed = 1u;


	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedPaymentOption = v2gpaymentOptionType_Contract;
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.arrayLen = 1; /* only one service was selected */
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.array[0].ServiceID = ev_session->charge_service_id; /* charge server ID */
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.array[0].ParameterSetID_isUsed = 0u; /* is not used */


	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("unable to do payment_selection_request v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.PaymentServiceSelectionRes_isUsed != 1u) {
        printf("payment_selection_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(exiOut.V2G_Message.Body.PaymentServiceSelectionRes.ResponseCode) != 0) {
        printf("payment_selection_request: session setup response NOT ok, code = %d\n", exiOut.V2G_Message.Body.PaymentServiceSelectionRes.ResponseCode);
        return -1;
    }
    return 0;
}

int payment_details_request(struct ev_tls_conn_t* conn, ev_session_t* ev_session)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    struct v2gPaymentDetailsReqType* req = &exiIn.V2G_Message.Body.PaymentDetailsReq;
    struct v2gPaymentDetailsResType* res = &exiOut.V2G_Message.Body.PaymentDetailsRes;
    init_v2g_request(&exiIn, ev_session);
	init_v2gPaymentDetailsReqType(req);
    exiIn.V2G_Message.Body.PaymentDetailsReq_isUsed = 1u;
	req->eMAID.characters[0] = 1;
	req->eMAID.characters[1] = 123;
	req->eMAID.charactersLen = 2;
    memcpy(req->ContractSignatureCertChain.Certificate.bytes, ev_session->contract.cert, ev_session->contract.cert_len);
	req->ContractSignatureCertChain.Certificate.bytesLen = ev_session->contract.cert_len;


	req->ContractSignatureCertChain.SubCertificates_isUsed = 1u;
	memcpy(req->ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytes, ev_session->contract.sub_certs[0], ev_session->contract.subcert_len[0]);
    req->ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytesLen = ev_session->contract.subcert_len[0];
    req->ContractSignatureCertChain.SubCertificates.Certificate.arrayLen = 1;
    exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Id_isUsed = 0;
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("unable to do payment_details_request v2g_request, exiting\n");
        return -1;
    }
    printf("v2g request\n");
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.PaymentDetailsRes_isUsed != 1u) {
        printf("payment_details_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(res->ResponseCode) != 0) {
        printf("payment_details_request: session setup response NOT ok, code = %d\n", res->ResponseCode);
        return -1;
    }
    if (res->GenChallenge.bytesLen != 16) {
        printf("payment_details: Invalid genchallenge length %u, length must me 16\n", res->GenChallenge.bytesLen);
        return -1;
    }
    memcpy(ev_session->challenge, res->GenChallenge.bytes, 16);
    return 0;
}

int authorization_request(struct ev_tls_conn_t* conn, ev_session_t* ev_session)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    struct v2gAuthorizationReqType* req = &exiIn.V2G_Message.Body.AuthorizationReq;
    struct v2gAuthorizationResType* res = &exiOut.V2G_Message.Body.AuthorizationRes;
    init_v2g_request(&exiIn, ev_session);
	init_v2gAuthorizationReqType(req);
	exiIn.V2G_Message.Body.AuthorizationReq_isUsed = 1u;
	req->Id_isUsed = 1u;
    req->Id.characters[0] = 'I';
    req->Id.characters[1] = 'D';
    req->Id.characters[2] = '1';
    req->Id.charactersLen = 3;
	req->GenChallenge_isUsed = 1;
    memcpy(req->GenChallenge.bytes, ev_session->challenge, 16);
	req->GenChallenge.bytesLen = 16;

	exiIn.V2G_Message.Header.Signature_isUsed = 1u;
	sign_auth_request(req, &ev_session->contract.key,
	                   &ev_session->contract.ctr_drbg,
	                   &exiIn.V2G_Message.Header.Signature);

	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("unable to do authorization v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.AuthorizationRes_isUsed != 1u) {
        printf("authorization_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(res->ResponseCode) != 0) {
        printf("authorization_request: authorization response NOT ok, code = %d\n", res->ResponseCode);
        return -1;
    }
	if(res->EVSEProcessing != v2gEVSEProcessingType_Finished) {
        printf("\t EVSEProcessing=Not Finished\n");
        return -1;
	}
    printf("\t EVSEProcessing=Finished\n");
    return 0;
}

int charge_parameter_request(struct ev_tls_conn_t* conn, ev_session_t* ev_session)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    struct v2gChargeParameterDiscoveryReqType* req = &exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq;
    struct v2gChargeParameterDiscoveryResType* res = &exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes;
    struct v2gAC_EVChargeParameterType* charge_params = &req->AC_EVChargeParameter;
    init_v2g_request(&exiIn, ev_session);
    exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed = 1u;
	init_v2gChargeParameterDiscoveryReqType(req);

	/* we use here AC based charging parameters */
	req->RequestedEnergyTransferMode = v2gEnergyTransferModeType_AC_single_phase_core;
	req->MaxEntriesSAScheduleTuple = 1234;

	req->AC_EVChargeParameter_isUsed = 1u;

	*charge_params = (struct v2gAC_EVChargeParameterType) {
	    .DepartureTime = 12345,
	    .EAmount = (struct v2gPhysicalValueType) {
	        .Value = 20,
	        .Multiplier = 3,
	        .Unit = v2gunitSymbolType_Wh,
	    },
	    .EVMaxCurrent = (struct v2gPhysicalValueType) {
	        .Value = 500,
	        .Multiplier = 0,
	        .Unit = v2gunitSymbolType_A,
	    },
	    .EVMinCurrent = (struct v2gPhysicalValueType) {
	        .Value = 200,
	        .Multiplier = 0,
	        .Unit = v2gunitSymbolType_A,
	    },
	    .EVMaxVoltage = (struct v2gPhysicalValueType) {
	        .Value = 400,
	        .Multiplier = 0,
	        .Unit = v2gunitSymbolType_A,
	    },
	};

	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("unable to do charge_parameter v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed != 1u) {
        printf("charge_parameter_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(res->ResponseCode) != 0) {
        printf("charge_parameter_request: authorization response NOT ok, code = %d\n", res->ResponseCode);
        return -1;
    }
    // === Decide which tuple to use ===
    if (res->SAScheduleList_isUsed && res->SAScheduleList.SAScheduleTuple.arrayLen > 0) {
        // === One can implement advanced logic to decide which tuple should be used here ===
        ev_session->pmax_schedule.is_used = true;
        ev_session->pmax_schedule.tupleid = res->SAScheduleList.SAScheduleTuple.array[0].SAScheduleTupleID;
    }
    // === Print digest ===
	printACEVSEStatus(&(res->AC_EVSEChargeParameter.AC_EVSEStatus));
	printf("\t EVSEProcessing=%d\n", res->EVSEProcessing);
	printf("\t EVSEMaxCurrent=%d\n", res->AC_EVSEChargeParameter.EVSEMaxCurrent.Value);
	printf("\t EVSENominalVoltage=%d\n", res->AC_EVSEChargeParameter.EVSENominalVoltage.Value);
    return 0;
}

int power_delivery_request(struct ev_tls_conn_t* conn, ev_session_t* ev_session)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    struct v2gChargingProfileType* profile = &exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile;

    init_v2g_request(&exiIn, ev_session);
    exiIn.V2G_Message.Body.PowerDeliveryReq_isUsed = 1u;
	init_v2gPowerDeliveryReqType(&exiIn.V2G_Message.Body.PowerDeliveryReq);

	exiIn.V2G_Message.Body.PowerDeliveryReq.DC_EVPowerDeliveryParameter_isUsed = 0; /* DC parameters are send */
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargeProgress = v2gchargeProgressType_Start;

	// === A charging profile is used for this request===
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed = 1u;
	exiIn.V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID  = ev_session->pmax_schedule.tupleid;
    // Max 5 charging profile entries (3 being used)

	profile->ProfileEntry.arrayLen = 4;

    // === Charging Profile Entry 1 ===
	profile->ProfileEntry.array[0] = (struct v2gProfileEntryType) {
	    .ChargingProfileEntryMaxPower = (struct v2gPhysicalValueType) {
	        .Value = 15,
	        .Multiplier = 3, // * 10^3 (e.g. kW)
	        .Unit = v2gunitSymbolType_W,
	    },
	    .ChargingProfileEntryStart = 0,
	    .ChargingProfileEntryMaxNumberOfPhasesInUse = 3,
	    .ChargingProfileEntryMaxNumberOfPhasesInUse_isUsed = 1,
	};
    // === Charging Profile Entry 2 ===
	profile->ProfileEntry.array[1] = (struct v2gProfileEntryType) {
	    .ChargingProfileEntryMaxPower = (struct v2gPhysicalValueType) {
	        .Value = 20,
	        .Multiplier = 3, // * 10^3 (e.g. kW)
	        .Unit = v2gunitSymbolType_W,
	    },
	    .ChargingProfileEntryStart = 100,
	    .ChargingProfileEntryMaxNumberOfPhasesInUse = 3,
	    .ChargingProfileEntryMaxNumberOfPhasesInUse_isUsed = 1,
	};
    // === Charging Profile Entry 3 ===
	profile->ProfileEntry.array[2] = (struct v2gProfileEntryType) {
	    .ChargingProfileEntryMaxPower = (struct v2gPhysicalValueType) {
	        .Value = 10,
	        .Multiplier = 3, // * 10^3 (e.g. kW)
	        .Unit = v2gunitSymbolType_W,
	    },
	    .ChargingProfileEntryStart = 200,
	    .ChargingProfileEntryMaxNumberOfPhasesInUse = 3,
	    .ChargingProfileEntryMaxNumberOfPhasesInUse_isUsed = 1,
	};
    // === Charging Profile Entry 4 ===
	profile->ProfileEntry.array[3] = (struct v2gProfileEntryType) {
	    .ChargingProfileEntryMaxPower = (struct v2gPhysicalValueType) {
	        .Value = 0,
	        .Multiplier = 3, // * 10^3 (e.g. kW)
	        .Unit = v2gunitSymbolType_W,
	    },
	    .ChargingProfileEntryStart = 400,
	    .ChargingProfileEntryMaxNumberOfPhasesInUse = 3,
	    .ChargingProfileEntryMaxNumberOfPhasesInUse_isUsed = 1,
	};
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("power_delivery_request v2g_request error, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.PowerDeliveryRes_isUsed != 1u) {
        printf("power_delivery_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(exiOut.V2G_Message.Body.PowerDeliveryRes.ResponseCode) != 0) {
        printf("power_delivery_request: response NOT ok, code = %d\n", exiOut.V2G_Message.Body.PowerDeliveryRes.ResponseCode);
        return -1;
    }
	printACEVSEStatus(&(exiOut.V2G_Message.Body.PowerDeliveryRes.AC_EVSEStatus));
    return 0;
}

int charging_status_request(struct ev_tls_conn_t* conn, ev_session_t* ev_session)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    init_v2g_request(&exiIn, ev_session);
	exiIn.V2G_Message.Body.ChargingStatusReq_isUsed = 1u;
	init_v2gChargingStatusReqType(&exiIn.V2G_Message.Body.ChargingStatusReq);
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("harging_status_request: unable to do v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.ChargingStatusRes_isUsed != 1u) {
        printf("charging_status_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(exiOut.V2G_Message.Body.ChargingStatusRes.ResponseCode) != 0) {
        printf("charging_status_request: authorization response NOT ok, code = %d\n", exiOut.V2G_Message.Body.ChargingStatusRes.ResponseCode);
        return -1;
    }
    return 0;
}

int session_stop_request(struct ev_tls_conn_t* conn, ev_session_t* ev_session)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    init_v2g_request(&exiIn, ev_session);
	exiIn.V2G_Message.Body.SessionStopReq_isUsed = 1u;
	init_v2gSessionStopReqType(&exiIn.V2G_Message.Body.SessionStopReq);
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("harging_status_request: unable to do v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.SessionStopRes_isUsed != 1u) {
        printf("charging_status_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(exiOut.V2G_Message.Body.SessionStopRes.ResponseCode) != 0) {
        printf("charging_status_request: authorization response NOT ok, code = %d\n", exiOut.V2G_Message.Body.SessionStopRes.ResponseCode);
        return -1;
    }
    return 0;
}

void ev_example(char* if_name)
{
    struct ev_tls_conn_t conn;
    ev_session_t ev_session;
    memset(&conn, 0, sizeof(struct ev_tls_conn_t));
    memset(&ev_session, 0, sizeof(ev_session_t));
    int err;
    err = load_contract("certs/contract.key", &ev_session);
    if( err != 0 ){
        printf("ev_example: load_contract error\n");
        return;
    }
    if( ev_sdp_discover_evse( if_name, &conn.addr, true ) < 0 ){
        printf("ev_example: ev_sdp_discover_evse error\n");
        return;
    }
    printf("connecting to secc\n");
    err = evcc_connect_tls(&conn, "certs/ev.pem", "certs/ev.key");
   //err = evcc_connect_tcp(&conn);
    if( err != 0 ){
        printf("main: evcc_connect_tls error\n");
        return;
    }
    printf("session setup request\n");
    err = session_request(&conn, &ev_session);
    if (err != 0) {
        printf("RIP session_request\n");
        return;
    }
    printf("service discovery request\n");
    err = service_discovery_request(&conn, &ev_session);
    if (err != 0) {
        printf("ev_example: service discovery request err\n");
        return;
    }
    printf("payment selection request\n");
    err = payment_selection_request(&conn, &ev_session);
    if (err != 0) {
        printf("ev_example: payment_selection_request err\n");
        return;
    }
    printf("payment details request\n");
    err = payment_details_request(&conn, &ev_session);
    if (err != 0) {
        printf("ev_example: payment_selection_request err\n");
        return;
    }
    printf("authorization request\n");
    err = authorization_request(&conn, &ev_session);
    if (err != 0) {
        printf("ev_example: authorization_request err\n");
        return;
    }
    printf("charge parameter request\n");
    err = charge_parameter_request(&conn, &ev_session);
    if (err != 0) {
        printf("ev_example: charge_parameter_request err\n");
        return;
    }
    printf("power delivery request\n");
    err = power_delivery_request(&conn, &ev_session);
    if (err != 0) {
        printf("ev_example: power_delivery_request err\n");
        return;
    }
    printf("Charging (repeating charging status requests)\n");
    for (int i = 0;i < 10; i++) {
        err = charging_status_request(&conn, &ev_session);
        if (err != 0) {
            printf("ev_example: charging_status_request err\n");
            return;
        }
        printf("=");
        fflush(stdout);
        sleep(1);
    }
    session_stop_request(&conn, &ev_session);
    printf("Finished charging, ending session\n");
    /*printf("service and payment selection request\n");
    // for PnC: Payment details req (opt: cert update)
    printf("authorization request\n");
    printf("charge parameter discovery request\n");
        printf("session request\n");*/
}
