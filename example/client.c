#include <stdio.h>
#include <nikolav2g.h>
#include <OpenV2G/EXITypes.h>
#include <OpenV2G/v2gEXIDatatypes.h>
#include <OpenV2G/v2gEXIDatatypesEncoder.h>
#include <OpenV2G/xmldsigEXIDatatypes.h>
#include <OpenV2G/xmldsigEXIDatatypesEncoder.h>
#include <OpenV2G/v2gtp.h>
#include <string.h>
#include <unistd.h>
#include <polarssl/pk.h>
#include <polarssl/ecdsa.h>
#include <fcntl.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include "client.h"

//=========================================
//            Utility Functions
//=========================================

void evcc_session_cleanup(ev_session_t* s) {
    ctr_drbg_free(&s->contract.ctr_drbg);
    ecdsa_free(&s->contract.key);
    entropy_free(&s->contract.entropy);
}

int load_contract(const char *pemchain_path,
                  const char *keyfile_path,
                  ev_session_t *s) {
    int err, i = 0;
    x509_crt crtchain;
    x509_crt* crt;
    pk_context pk;
    pk_init(&pk);
    const char *pers = "ecdsa";
    x509_crt_init(&crtchain);
    err = x509_crt_parse_file(&crtchain, pemchain_path);
    if (err != 0) {
        printf("load_contract: x509_crl_parse_file error\n");
        return -1;
    }
    if (crtchain.raw.len > v2gCertificateChainType_Certificate_BYTES_SIZE) {
        printf("load_contract: certificate too big\n");
        return -1;
    }
    memcpy(&s->contract.cert, crtchain.raw.p, crtchain.raw.len);
    s->contract.cert_len = crtchain.raw.len;
    crt = &crtchain;
    while (crt->next != NULL) {
        if (i > v2gSubCertificatesType_Certificate_ARRAY_SIZE) {
            printf("load_contract: certificate chain too long (max 4 subcerts)\n");
            return -1;
        }
        crt = crt->next;
        if (crt->raw.len > v2gSubCertificatesType_Certificate_BYTES_SIZE) {
            printf("load_contract: subcertificate too big\n");
            return -1;
        }
        memcpy(&s->contract.sub_certs[i], crt->raw.p, crt->raw.len);
        s->contract.subcert_len[i] = crt->raw.len;
        i++;
    }
    x509_crt_free(&crtchain);
    err = pk_parse_keyfile(&pk, keyfile_path, NULL);
    if (err != 0) {
        printf("could not parse keyfile at %s\n",keyfile_path);
        return -1;
    }
    ecp_keypair *kp = pk_ec(pk);
    ecdsa_free(&s->contract.key); // Free, if existing already
    err = ecdsa_from_keypair(&s->contract.key, kp);
    pk_free(&pk);
    if (err != 0) {
        printf("could not retrieve ecdsa from keypair at %s\n",keyfile_path);
        return -1;
    }

    entropy_init(&s->contract.entropy);
    if ((err = ctr_drbg_init(&s->contract.ctr_drbg, entropy_func,
                             &s->contract.entropy,
                             (const unsigned char*)pers,
                             strlen(pers))) != 0) {
        printf("load_contract:  failed\n  ! ctr_drbg_init returned %d\n", err);
        return -1;
    }
    return 0;
}

int sign_auth_request(struct v2gAuthorizationReqType *req,
                      ecdsa_context *key,
                      ctr_drbg_context *ctr_drbg,
                      struct v2gSignatureType *sig) {
    int err;
    unsigned char buf[256];
    uint8_t digest[32];
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
    memset(&sig_fragment, 0, sizeof(sig_fragment));
    struct xmldsigReferenceType *ref = &sig_fragment.SignedInfo.Reference.array[0];
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
	ref->URI_isUsed = 1;
	ref->URI.charactersLen = 4;
	memcpy(ref->URI.characters, uri, 4);
	// "http://www.w3.org/TR/canonical-exi/"
	ref->Transforms_isUsed = 1;
	ref->Transforms.Transform.arrayLen = 1;
	ref->Transforms.Transform.array[0].Algorithm.charactersLen = 35;
	strncpy(ref->Transforms.Transform.array[0].Algorithm.characters, arrayCanonicalEXI, 35); // Will copy 35 characters from arrayCanonicalEXI to characters
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
    err = ecdsa_write_signature(key,
                                digest, 32,
                                sig->SignatureValue.CONTENT.bytes,
                                (size_t*)&sig->SignatureValue.CONTENT.bytesLen,
                                ctr_drbg_random,
                                ctr_drbg);
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

void SetProfileEntry(struct v2gChargingProfileType* prof,
                     uint32_t start, int32_t value,
                     uint32_t nphases)
{
    uint16_t* counter = &prof->ProfileEntry.arrayLen;
    const int max_value = (2 << 16) - 1;
    const int max_power = (2 << 8) - 1;
    int power = 0;
    while(abs(value) > max_value &&
          power < max_power) {
        value /= 10;
        power ++;
    }

    prof->ProfileEntry.array[*counter] =  (struct v2gProfileEntryType) {
        .ChargingProfileEntryStart = start,
        .ChargingProfileEntryMaxNumberOfPhasesInUse = nphases,
        .ChargingProfileEntryMaxNumberOfPhasesInUse_isUsed = 1u,
        .ChargingProfileEntryMaxPower = (struct v2gPhysicalValueType) {
	        .Value = value,
	        .Multiplier = power,
	        .Unit = v2gunitSymbolType_W,
	    },
	};
    (*counter)++;
}


/*static void printACEVSEStatus(struct v2gAC_EVSEStatusType *status)
{
	printf("\tEVSEStatus:\n");
	printf("\t\tRCD=%d\n", status->RCD);
	printf("\t\tEVSENotification=%d\n", status->EVSENotification);
	printf("\t\tNotificationMaxDelay=%d\n", status->NotificationMaxDelay);
}*/

int verify_response_code(v2gresponseCodeType code)
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


void init_v2g_request(struct v2gEXIDocument *exiIn, ev_session_t *s)
{
    memset(exiIn, 0, sizeof(*exiIn));
    init_v2gEXIDocument(exiIn);
	exiIn->V2G_Message_isUsed = 1u;
	init_v2gMessageHeaderType(&exiIn->V2G_Message.Header);
	// Set session id to 0
	if (s == NULL) {
	    memset(exiIn->V2G_Message.Header.SessionID.bytes, 0, 8);
	} else {
	    memcpy(exiIn->V2G_Message.Header.SessionID.bytes, &s->id, 8);
	}
	exiIn->V2G_Message.Header.SessionID.bytesLen = 8;
	exiIn->V2G_Message.Header.Notification_isUsed = 0u; // no notification
	exiIn->V2G_Message.Header.Signature_isUsed = 0u;
    init_v2gBodyType(&exiIn->V2G_Message.Body);
}

//=======================
//  Request Definitions
//=======================
int session_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    init_v2g_request(&exiIn, NULL);
	exiIn.V2G_Message.Body.SessionSetupReq_isUsed = 1u;

	init_v2gSessionSetupReqType(&exiIn.V2G_Message.Body.SessionSetupReq);

	exiIn.V2G_Message.Body.SessionSetupReq.EVCCID.bytesLen = 1;
	exiIn.V2G_Message.Body.SessionSetupReq.EVCCID.bytes[0] = 20;
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
    memcpy(&s->id, exiOut.V2G_Message.Header.SessionID.bytes, 8);

    return 0;
}

int service_discovery_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    // === Init ===
    init_v2g_request(&exiIn, s);
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
    s->charge_service_id = exiOut.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceID;
    s->charging_is_free = exiOut.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.FreeService && 1;
    return 0;
}

int payment_selection_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    init_v2g_request(&exiIn, s);
	init_v2gPaymentServiceSelectionReqType(&exiIn.V2G_Message.Body.PaymentServiceSelectionReq);
    exiIn.V2G_Message.Body.PaymentServiceSelectionReq_isUsed = 1u;

    if (!s->charging_is_free) {
	    exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedPaymentOption = v2gpaymentOptionType_Contract;
	}
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.arrayLen = 1; // === only one service was selected ===
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.array[0].ServiceID = s->charge_service_id; // charge server ID
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.array[0].ParameterSetID_isUsed = 0u; // is not used


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
        printf("payment_selection_request: response NOT ok, code = %d\n", exiOut.V2G_Message.Body.PaymentServiceSelectionRes.ResponseCode);
        return -1;
    }
    return 0;
}

int payment_details_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    struct v2gPaymentDetailsReqType *req = &exiIn.V2G_Message.Body.PaymentDetailsReq;
    struct v2gPaymentDetailsResType *res = &exiOut.V2G_Message.Body.PaymentDetailsRes;
    init_v2g_request(&exiIn, s);
	init_v2gPaymentDetailsReqType(req);
    exiIn.V2G_Message.Body.PaymentDetailsReq_isUsed = 1u;
	req->eMAID.characters[0] = 1;
	req->eMAID.characters[1] = 123;
	req->eMAID.charactersLen = 2;
	if (s->contract.cert_len == 0) {
	    printf("payment_details_request: contract certificate not loaded\n");
	    return -1;
	}
    memcpy(req->ContractSignatureCertChain.Certificate.bytes, s->contract.cert, s->contract.cert_len);
	req->ContractSignatureCertChain.Certificate.bytesLen = s->contract.cert_len;
	req->ContractSignatureCertChain.SubCertificates_isUsed = 1u;
	memcpy(req->ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytes, s->contract.sub_certs[0], s->contract.subcert_len[0]);
    req->ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytesLen = s->contract.subcert_len[0];
    req->ContractSignatureCertChain.SubCertificates.Certificate.arrayLen = 1;
    req->ContractSignatureCertChain.Id_isUsed = 0;
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
    memcpy(s->challenge, res->GenChallenge.bytes, 16);
    return 0;
}

int authorization_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    struct v2gAuthorizationReqType *req = &exiIn.V2G_Message.Body.AuthorizationReq;
    struct v2gAuthorizationResType *res = &exiOut.V2G_Message.Body.AuthorizationRes;
    init_v2g_request(&exiIn, s);
	init_v2gAuthorizationReqType(req);
	exiIn.V2G_Message.Body.AuthorizationReq_isUsed = 1u;
	req->Id_isUsed = 1u;
    req->Id.characters[0] = 'I';
    req->Id.characters[1] = 'D';
    req->Id.characters[2] = '1';
    req->Id.charactersLen = 3;
    if (!s->charging_is_free) {
	    req->GenChallenge_isUsed = 1;
        memcpy(req->GenChallenge.bytes, s->challenge, 16);
	    req->GenChallenge.bytesLen = 16;

	    exiIn.V2G_Message.Header.Signature_isUsed = 1u;
	    sign_auth_request(req, &s->contract.key,
	                       &s->contract.ctr_drbg,
	                       &exiIn.V2G_Message.Header.Signature);
	}

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
	if (res->EVSEProcessing != v2gEVSEProcessingType_Finished) {
        printf("\t EVSEProcessing=Not Finished\n");
        return -1;
	}
    printf("\t EVSEProcessing=Finished\n");
    return 0;
}

int charge_parameter_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    struct v2gChargeParameterDiscoveryReqType *req = &exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq;
    struct v2gChargeParameterDiscoveryResType *res = &exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes;
    struct v2gAC_EVChargeParameterType *charge_params = &req->AC_EVChargeParameter;
    init_v2g_request(&exiIn, s);
    exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed = 1u;
	init_v2gChargeParameterDiscoveryReqType(req);

	//=== we use here AC based charging parameters ===
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
        s->pmax_schedule.is_used = true;
        s->pmax_schedule.tupleid = res->SAScheduleList.SAScheduleTuple.array[0].SAScheduleTupleID;
    }
    // === Print digest ===
	/*printACEVSEStatus(&(res->AC_EVSEChargeParameter.AC_EVSEStatus));
	printf("\t EVSEProcessing=%d\n", res->EVSEProcessing);
	printf("\t EVSEMaxCurrent=%d\n", res->AC_EVSEChargeParameter.EVSEMaxCurrent.Value);
	printf("\t EVSENominalVoltage=%d\n", res->AC_EVSEChargeParameter.EVSENominalVoltage.Value);*/
    return 0;
}

int power_delivery_request(evcc_conn_t *conn, ev_session_t *s,
                            v2gchargeProgressType progress)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    struct v2gChargingProfileType *profile = &exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile;

    init_v2g_request(&exiIn, s);
    exiIn.V2G_Message.Body.PowerDeliveryReq_isUsed = 1u;
	init_v2gPowerDeliveryReqType(&exiIn.V2G_Message.Body.PowerDeliveryReq);

	exiIn.V2G_Message.Body.PowerDeliveryReq.DC_EVPowerDeliveryParameter_isUsed = 0;
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargeProgress = progress;

	// === A charging profile is used for this request===

	exiIn.V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID  = s->pmax_schedule.tupleid;

    if (progress == v2gchargeProgressType_Start) {
	    exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed = 1u;
	     // Must be initialized to 0
	    // == Charging Entries ==
	    //SetProfileEntry(profile, relative time, power, max phases)
        profile->ProfileEntry.arrayLen = 0; // must be 0
        SetProfileEntry(profile,   0, 15000, 3);
        SetProfileEntry(profile, 100, 20000, 3);
        SetProfileEntry(profile, 200, 10000, 3);
        SetProfileEntry(profile, 400,     0, 3);
	} else {
	    exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed = 0;
	}
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
	//printACEVSEStatus(&(exiOut.V2G_Message.Body.PowerDeliveryRes.AC_EVSEStatus));
    return 0;
}

int charging_status_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    struct v2gChargingStatusResType *res = &exiOut.V2G_Message.Body.ChargingStatusRes;
    init_v2g_request(&exiIn, s);
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
    if (verify_response_code(res->ResponseCode) != 0) {
        printf("charging_status_request: authorization response NOT ok, code = %d\n", exiOut.V2G_Message.Body.ChargingStatusRes.ResponseCode);
        return -1;
    }
    if (res->AC_EVSEStatus.EVSENotification <= v2gEVSENotificationType_ReNegotiation) {
        s->evse_notification = res->AC_EVSEStatus.EVSENotification;
    }
    return 0;
}

int session_stop_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    init_v2g_request(&exiIn, s);
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
