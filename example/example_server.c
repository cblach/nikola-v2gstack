#include "v2gstack.h"
#include "EXITypes.h"
#include "v2gEXIDatatypes.h"
#include "v2gEXIDatatypesEncoder.h"
#include "xmldsigEXIDatatypes.h"
#include "xmldsigEXIDatatypesEncoder.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "polarssl/error.h"

const v2gEnergyTransferModeType ENERGY_TRANSFER_MODES[] =
{ 	v2gEnergyTransferModeType_AC_single_phase_core,
	v2gEnergyTransferModeType_AC_three_phase_core,
};

void init_v2g_response(struct v2gEXIDocument* exiIn, session_t* session)
{
    init_v2gEXIDocument(exiIn);
	exiIn->V2G_Message_isUsed = 1u;
	init_v2gMessageHeaderType(&exiIn->V2G_Message.Header);
	// Set session id to 0
	if (session == NULL) {
	    memset(exiIn->V2G_Message.Header.SessionID.bytes, 0, 8);
	} else {
	    memcpy(exiIn->V2G_Message.Header.SessionID.bytes, &session->id, 8);
	}
	exiIn->V2G_Message.Header.SessionID.bytesLen = 8;
//	exiIn->V2G_Message.Header.Notification_isUsed = 0u; /* no notification */
//	exiIn->V2G_Message.Header.Signature_isUsed = 0u;
    init_v2gBodyType(&exiIn->V2G_Message.Body);
}




static int handle_session_setup(struct v2gEXIDocument* exiIn, struct v2gEXIDocument* exiOut, session_t* session)
{
    struct v2gSessionSetupResType* res = &exiOut->V2G_Message.Body.SessionSetupRes;
/* generate an unique sessionID */
    session =  session_new();
    if (session == NULL) {
        printf("session creation error\n");
        return -1;
    }
    printf("New Session id = %lu", session->id);
    init_v2g_response(exiOut, session);
    init_v2gSessionSetupResType(res);
    exiOut->V2G_Message.Body.SessionSetupRes_isUsed = 1u;
    res->ResponseCode = v2gresponseCodeType_OK;
    res->EVSEID.characters[0] = 0;
    res->EVSEID.characters[1] = 20;
    res->EVSEID.charactersLen = 2;
    //exiOut->V2G_Message.Body.SessionSetupRes.EVSETimeStamp_isUsed = 1u;
    //exiOut->V2G_Message.Body.SessionSetupRes.EVSETimeStamp = 123456789;
    return 0;
}

static int handle_service_discovery(struct v2gEXIDocument* exiIn,
                                    struct v2gEXIDocument* exiOut,
                                    session_t* session)
{
    struct v2gServiceDiscoveryResType* res = &exiOut->V2G_Message.Body.ServiceDiscoveryRes;
    // === Lookup session ===
    init_v2g_response(exiOut, session);
	exiOut->V2G_Message.Body.ServiceDiscoveryRes_isUsed = 1u;
	init_v2gServiceDiscoveryResType(res);
	res->ServiceList_isUsed = 0u;
	printf("\t\t ServiceCategory=%d\n", exiIn->V2G_Message.Body.ServiceDiscoveryReq.ServiceCategory);

	/* Prepare data for EV */
	 /* we do not provide VAS */
	res->ResponseCode = v2gresponseCodeType_OK;

	res->ChargeService.ServiceID = 1; /* ID of the charge service */
	res->ChargeService.ServiceName_isUsed = 1u;
	// Up to 32
	res->ChargeService.ServiceName.characters[0] = 'N';
	res->ChargeService.ServiceName.characters[1] = 'i';
	res->ChargeService.ServiceName.characters[2] = 'k';
	res->ChargeService.ServiceName.characters[3] = 'o';
	res->ChargeService.ServiceName.characters[4] = 'l';
	res->ChargeService.ServiceName.characters[5] = 'a';
	res->ChargeService.ServiceName.characters[6] = '\0';
	res->ChargeService.ServiceName.charactersLen = 6;
	res->ChargeService.ServiceScope_isUsed = 1u;
	res->ChargeService.FreeService = 1;
	res->ChargeService.ServiceCategory = v2gserviceCategoryType_EVCharging;
	res->ChargeService.ServiceScope_isUsed = 1u;
	res->ChargeService.ServiceScope.characters[0] = 100;
	res->ChargeService.ServiceScope.characters[1] = '\0';
	res->ChargeService.ServiceScope.charactersLen = 1;
	res->ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.array[0] =
	    v2gEnergyTransferModeType_AC_single_phase_core;
	res->ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.array[1] =
	    v2gEnergyTransferModeType_AC_three_phase_core;
	res->ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.arrayLen = 2;

	res->PaymentOptionList.PaymentOption.array[0] = v2gpaymentOptionType_ExternalPayment; /* EVSE handles the payment */
	res->PaymentOptionList.PaymentOption.array[1] = v2gpaymentOptionType_Contract;
	res->PaymentOptionList.PaymentOption.arrayLen = 2;
	if (session == NULL) {
        printf("unknown session\n");
        res->ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
        return 0;
    }
    return 0;
}

static int payment_service_selection(struct v2gEXIDocument* exiIn,
                                     struct v2gEXIDocument* exiOut,
                                     session_t* session)
{
    struct v2gPaymentServiceSelectionReqType* req = &exiIn->V2G_Message.Body.PaymentServiceSelectionReq;
    struct v2gPaymentServiceSelectionResType* res = &exiOut->V2G_Message.Body.PaymentServiceSelectionRes;
	init_v2g_response(exiOut, session);
	exiOut->V2G_Message.Body.PaymentServiceSelectionRes_isUsed= 1u;
	init_v2gPaymentServiceSelectionResType(res);
    if (session == NULL) {
        printf("create_response_message error: session_lookup_exi\n");
	    memset(res, 0, sizeof(*res));
        res->ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
        return 0;
    }
    switch (req->SelectedPaymentOption) {
    case v2gpaymentOptionType_ExternalPayment:
        printf("\t\t SelectedPaymentOption=ExternalPayment\n");
        break;
    case v2gpaymentOptionType_Contract:
        break;
    default:
        res->ResponseCode = v2gresponseCodeType_FAILED_PaymentSelectionInvalid;
        return 0;
    }
    res->ResponseCode = v2gresponseCodeType_OK;
    session->payment_type = req->SelectedPaymentOption;
    return 0;
}

static int handle_payment_detail(struct v2gEXIDocument* exiIn,
                                 struct v2gEXIDocument* exiOut,
                                 session_t* session)
{
    struct v2gPaymentDetailsReqType* req = &exiIn->V2G_Message.Body.PaymentDetailsReq;
    struct v2gPaymentDetailsResType* res = &exiOut->V2G_Message.Body.PaymentDetailsRes;
    int err;
    init_v2g_response(exiOut, session);
	exiOut->V2G_Message_isUsed = 1u;
	exiOut->V2G_Message.Body.PaymentDetailsRes_isUsed = 1u;
    if (session == NULL) {
    	memset(res, 0, sizeof(*res));
        res->ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
        printf("handle_payment_detail: unknown session\n");
        return 0;
    }
    if (session->payment_type == v2gpaymentOptionType_Contract) {
        session->contract.valid_crt = false;
        err = x509_crt_parse(&session->contract.crt,
                             req->ContractSignatureCertChain.Certificate.bytes,
                             req->ContractSignatureCertChain.Certificate.bytesLen);
        if (err != 0) {
            memset(res, 0, sizeof(*res));
            res->ResponseCode = v2gresponseCodeType_FAILED_CertChainError;
            printf("handle_payment_detail: invalid certififcate received in req\n");
            return 0;
        }
        err = ecdsa_from_keypair(&session->contract.pubkey, pk_ec(session->contract.crt.pk));
        if (err != 0) {
            memset(res, 0, sizeof(*res));
            res->ResponseCode = v2gresponseCodeType_FAILED_CertChainError;
            char strerr[256];
            error_strerror( err, strerr, 256 );
            printf("handle_payment_detail: could not retrieve ecdsa from keypair: %s\n", strerr);
            return 0;
        }
        gen_random_data(session->challenge, 16);
        memcpy(res->GenChallenge.bytes, session->challenge, 16);
      	res->GenChallenge.bytesLen = 16;
      	session->contract.valid_crt = true;
    }
    res->ResponseCode = v2gresponseCodeType_OK;
	res->EVSETimeStamp = time(NULL);
    return 0;
}

static int handle_authorization(struct v2gEXIDocument* exiIn,
                                struct v2gEXIDocument* exiOut,
                                session_t* session)
{
    struct v2gAuthorizationReqType* req = &exiIn->V2G_Message.Body.AuthorizationReq;
    struct v2gAuthorizationResType* res = &exiOut->V2G_Message.Body.AuthorizationRes;
    int err;
    init_v2g_response(exiOut, session);
	exiOut->V2G_Message.Body.AuthorizationRes_isUsed = 1u;
    init_v2gAuthorizationResType(res);
    res->EVSEProcessing = v2gEVSEProcessingType_Finished;
    if (session == NULL) {
    	memset(res, 0, sizeof(*res));
        res->ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
        printf("handle_authorization: unknown session\n");
        return 0;
    }
    if (session->payment_type == v2gpaymentOptionType_Contract &&
        session->contract.valid_crt == true) {
        if (req->GenChallenge_isUsed == 0 || req->GenChallenge.bytesLen != 16
            || memcmp(req->GenChallenge.bytes,session->challenge, 16) != 0) {
            printf("handle_authorization: challenge invalid or not present\n");
            res->ResponseCode = v2gresponseCodeType_FAILED_ChallengeInvalid;
            return 0;
        }
        if (exiIn->V2G_Message.Header.Signature_isUsed == 0) {
            printf("handle_authorization: missing signture\n");
            res->ResponseCode = v2gresponseCodeType_FAILED_SignatureError;
            return 0;
        }
        //===================================
        //    Validate signature -  PART 1/2
        //===================================
        struct v2gSignatureType* sig = &exiIn->V2G_Message.Header.Signature;
        unsigned char buf[256];
        uint16_t buffer_pos = 0;
        struct v2gReferenceType* req_ref = &sig->SignedInfo.Reference.array[0];
        bitstream_t stream = {
            .size = 256,
            .data = buf,
            .pos  = &buffer_pos,
            .buffer = 0,
            .capacity = 8, // Set to 8 for send and 0 for recv
        };
        struct v2gEXIFragment auth_fragment;
        byte digest[32];
        init_v2gEXIFragment(&auth_fragment);
        auth_fragment.AuthorizationReq_isUsed = 1u;
        memcpy(&auth_fragment.AuthorizationReq, req, sizeof(*req));
        err = encode_v2gExiFragment(&stream, &auth_fragment);
        if (err != 0) {
            printf("handle_authorization: unable to encode auth fragment\n");
            return -1;
        }
        sha256(buf, (size_t)buffer_pos, digest, 0);
        if (req_ref->DigestValue.bytesLen != 32
            || memcmp(req_ref->DigestValue.bytes, digest, 32) != 0) {
            printf("handle_authorization: invalid digest\n");
            res->ResponseCode = v2gresponseCodeType_FAILED_SignatureError;
            return 0;
        }
        //===================================
        //    Validate signature -  PART 2/2
        //===================================
        struct xmldsigEXIFragment sig_fragment;
        init_xmldsigEXIFragment(&sig_fragment);
	    sig_fragment.SignedInfo_isUsed = 1;
	    memcpy(&sig_fragment.SignedInfo, &sig->SignedInfo,
	           sizeof(struct v2gSignedInfoType));
        buffer_pos = 0;
	    err = encode_xmldsigExiFragment(&stream, &sig_fragment);
        if (err != 0) {
            printf("error 2: error code = %d\n", err);
            return -1;
        }
        // === Hash the signature ===
        sha256(buf, buffer_pos, digest, 0);
        // === Validate the ecdsa signature using the public key ===
        if (sig->SignatureValue.CONTENT.bytesLen > 350) {
            printf("handle_authorization: signature too long\n");
            res->ResponseCode = v2gresponseCodeType_FAILED_SignatureError;
            return 0;
        }
        err = ecdsa_read_signature(&session->contract.pubkey,
                                   digest, 32,
                                   sig->SignatureValue.CONTENT.bytes,
                                   sig->SignatureValue.CONTENT.bytesLen );
        if (err != 0) {
            res->ResponseCode = v2gresponseCodeType_FAILED_SignatureError;
            printf("invalid signature\n");
            return 0;
        }
        printf("Succesful verification of signature!!!\n");
    }
	res->ResponseCode = v2gresponseCodeType_OK;
	return 0;
}

static int handle_charge_parameters(struct v2gEXIDocument* exiIn,
                                    struct v2gEXIDocument* exiOut,
                                    session_t* session)
{
    struct v2gChargeParameterDiscoveryReqType* req = &exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq;
    struct v2gChargeParameterDiscoveryResType* res = &exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes;
    bool valid_mode = false;
    // === Lookup session ===
    init_v2g_response(exiOut, session);
	exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed = 1u;
    init_v2gChargeParameterDiscoveryResType(res);
	res->EVSEProcessing = v2gEVSEProcessingType_Finished;
	res->AC_EVSEChargeParameter_isUsed = 1u;
	res->DC_EVSEChargeParameter_isUsed = 0u;
	res->AC_EVSEChargeParameter.AC_EVSEStatus.RCD = 1;
	res->AC_EVSEChargeParameter.AC_EVSEStatus.EVSENotification = v2gEVSENotificationType_None;
	res->AC_EVSEChargeParameter.AC_EVSEStatus.NotificationMaxDelay=123;
	res->AC_EVSEChargeParameter.EVSEMaxCurrent.Multiplier = 0;
	res->AC_EVSEChargeParameter.EVSEMaxCurrent.Unit = v2gunitSymbolType_A;
	res->AC_EVSEChargeParameter.EVSEMaxCurrent.Value = 100;
	res->AC_EVSEChargeParameter.EVSENominalVoltage.Multiplier = 0;
	res->AC_EVSEChargeParameter.EVSENominalVoltage.Unit = v2gunitSymbolType_V;
	res->AC_EVSEChargeParameter.EVSENominalVoltage.Value = 300;
    if (session == NULL) {
        printf("create_response_message error: session_new\n");
        res->ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
        return 0;
    }
    for (int i = 0; i < sizeof(ENERGY_TRANSFER_MODES)/sizeof(ENERGY_TRANSFER_MODES[0]); i++) {
        if (req->RequestedEnergyTransferMode == ENERGY_TRANSFER_MODES[i]) {
            valid_mode = true;
            break;
        }
    }
    if (!valid_mode) {
        res->ResponseCode = v2gresponseCodeType_FAILED_WrongEnergyTransferMode;
    } else {
        session->energy_transfer_mode = req->RequestedEnergyTransferMode;
        res->ResponseCode = v2gresponseCodeType_OK;
    }
    return 0;
}

int handle_power_delivery(struct v2gEXIDocument* exiIn,
                          struct v2gEXIDocument* exiOut,
                          session_t* session)
{
    struct v2gPowerDeliveryReqType* req = &exiIn->V2G_Message.Body.PowerDeliveryReq;
    struct v2gPowerDeliveryResType* res = &exiOut->V2G_Message.Body.PowerDeliveryRes;
    init_v2g_response(exiOut, session);
	exiOut->V2G_Message_isUsed = 1u;
	exiOut->V2G_Message.Body.PowerDeliveryRes_isUsed = 1u;
	res->AC_EVSEStatus.RCD=0;
	res->AC_EVSEStatus.EVSENotification=3;
	res->AC_EVSEStatus.NotificationMaxDelay=12;
	res->AC_EVSEStatus_isUsed = 1;
	res->DC_EVSEStatus_isUsed = 0;
    if (session == NULL) {
        printf("handle_power_delivery: unknown session\n");
        res->ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
        return 0;
    }
    if (req->DC_EVPowerDeliveryParameter_isUsed) {
        printf("invalid charging mode: DC not available\n");
        return -1;
    }
	res->ResponseCode = v2gresponseCodeType_OK;

	return 0;
}

int handle_charging_status(struct v2gEXIDocument* exiIn,
                           struct v2gEXIDocument* exiOut,
                           session_t* session)
{
   // struct v2gChargingStatusReqType* req = &exiIn->V2G_Message.Body.ChargingStatusReq;
    struct v2gChargingStatusResType* res = &exiOut->V2G_Message.Body.ChargingStatusRes;
    init_v2g_response(exiOut, session);
	exiOut->V2G_Message_isUsed = 1u;
	exiOut->V2G_Message.Body.ChargingStatusRes_isUsed = 1u;
    if (session == NULL) {
        printf("handle_charging_status: unknown sessio \n");
        memset(res, 0, sizeof(*res));
        res->ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
        return 0;
    }
	res->ResponseCode = v2gresponseCodeType_OK;
	res->EVSEID.characters[0]=12;
	res->EVSEID.charactersLen =1;
	res->AC_EVSEStatus.RCD=1;
	res->AC_EVSEStatus.EVSENotification = v2gEVSENotificationType_None;
	res->AC_EVSEStatus.NotificationMaxDelay=123;
	res->ReceiptRequired=1;
	res->ReceiptRequired_isUsed =1;
	res->EVSEMaxCurrent.Multiplier = 2;
	res->EVSEMaxCurrent.Unit = v2gunitSymbolType_A;
	res->EVSEMaxCurrent.Value = 400;
	res->EVSEMaxCurrent_isUsed =1;
	res->SAScheduleTupleID=10;
	res->MeterInfo_isUsed =1;
	res->MeterInfo.MeterID.charactersLen =1;
	res->MeterInfo.MeterID.characters[0]=2;
	res->MeterInfo.MeterReading = 5000;
	res->MeterInfo.MeterStatus = 4321;
	res->MeterInfo.TMeter =123456789;
	res->MeterInfo.SigMeterReading.bytes[0]=123;
	res->MeterInfo.SigMeterReading.bytesLen=1;
	res->MeterInfo.MeterReading_isUsed = 1;
	res->MeterInfo.MeterStatus_isUsed =1;
	res->MeterInfo.TMeter_isUsed=1;
	res->MeterInfo.SigMeterReading_isUsed =1;
	return 0;
}

static int handle_session_stop(struct v2gEXIDocument* exiIn,
                               struct v2gEXIDocument* exiOut,
                               session_t* session)
{
    struct v2gSessionStopReqType* req = &exiIn->V2G_Message.Body.SessionStopReq;
    struct v2gSessionStopResType* res = &exiOut->V2G_Message.Body.SessionStopRes;
	exiOut->V2G_Message_isUsed = 1u;
	init_v2gBodyType(&exiOut->V2G_Message.Body);
	exiOut->V2G_Message.Body.SessionStopRes_isUsed = 1u;
    if (session == NULL) {
        printf("handle_session_stop: unknown session\n");
        res->ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
        return -1;
    }
    if (req->ChargingSession == v2gchargingSessionType_Terminate){
        session_terminate(session);
    }
	/* Prepare data for EV */

	exiOut->V2G_Message.Body.SessionStopRes.ResponseCode = v2gresponseCodeType_OK;
	return 0;
}

static int create_response_message(struct v2gEXIDocument* exiIn, struct v2gEXIDocument* exiOut) {
	int err = -1;//ERROR_UNEXPECTED_REQUEST_MESSAGE;
    session_t* session;
	/* create response message as EXI document */
	if (exiIn->V2G_Message_isUsed) {
	    session = session_lookup_exi(exiIn);
	    session_lock(session);
		init_v2gEXIDocument(exiOut);
		if (exiIn->V2G_Message.Body.SessionSetupReq_isUsed) {
		    printf("Handling session setup request\n");
			err = handle_session_setup(exiIn, exiOut, session);
		} else if (exiIn->V2G_Message.Body.ServiceDiscoveryReq_isUsed) {
			//errn = serviceDiscovery(exiIn, exiOut);
			printf("Handling service discovery request\n");
			err = handle_service_discovery(exiIn, exiOut, session);
		} else if (exiIn->V2G_Message.Body.ServiceDetailReq_isUsed) {
		    printf("No service detail request\n");
		    err = -1;
			//errn = serviceDetail(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PaymentServiceSelectionReq_isUsed) {
		    printf("Handling payment service selection request\n");
		    err = payment_service_selection(exiIn, exiOut, session);
			//errn = paymentServiceSelection(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PaymentDetailsReq_isUsed) {
		    printf("Handling payment details request\n");
			err = handle_payment_detail(exiIn, exiOut, session);
		} else if (exiIn->V2G_Message.Body.AuthorizationReq_isUsed) {
		    printf("Handling authorization request\n");
		    err = handle_authorization(exiIn, exiOut, session);
			//errn = authorization(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed) {
		    printf("Handling charge parameter discv. request\n");
		    err = handle_charge_parameters(exiIn, exiOut, session);
			//errn = chargeParameterDiscovery(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PowerDeliveryReq_isUsed) {
		    printf("Handling power delivery request\n");
			err = handle_power_delivery(exiIn, exiOut, session);
		} else if (exiIn->V2G_Message.Body.ChargingStatusReq_isUsed) {
		    printf("Handling charging status request\n");
			err = handle_charging_status(exiIn, exiOut, session);
		} else if (exiIn->V2G_Message.Body.MeteringReceiptReq_isUsed) {
		    printf("No handling metering receipt request\n");
		    err =  -1;
			//errn = meteringReceipt(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.SessionStopReq_isUsed) {
		    printf("Handling session stop request\n");
		    err = handle_session_stop(exiIn, exiOut, session);
			//errn = sessionStop(exiIn, exiOut);
		/*} else if (exiIn->V2G_Message.Body.CableCheckReq_isUsed) {
		    printf("Handling cable check request\n");
			//errn = cableCheck(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PreChargeReq_isUsed) {
		    printf("Handling precharge request\n");
			//errn = preCharge(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.CurrentDemandReq_isUsed) {
		    printf("Handling current demand request\n");
			//errn = currentDemand(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.WeldingDetectionReq_isUsed) {
		    printf("Handling welding detection request\n");
			//errn = weldingDetection(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.CertificateInstallationReq_isUsed) {
		    printf("Handling cert installation request\n");
		} else if (exiIn->V2G_Message.Body.CertificateUpdateReq_isUsed) {
		    printf("Handling cert update request\n");*/
		} else {
		    printf("create_response_message: request type not found\n");
		}
		session_unlock(session);
		session_remove_ref(session);
	}
	if (err != 0) {
        printf("Handle request returning %d\n", err);
    }
	return err;
}

void evse_example(char* if_name)
{
    int tls_port, sockfd;
    init_sessions();
    // === Bind to dynamic port ===
    sockfd = bind_tls(&tls_port);
    if (sockfd < 0) {
        printf( " secc_bind_tls  returned %d\n", sockfd );
        return;
    }
    printf( "start sdp listen\n");/*
    struct evse_sdp_listen_args sdp_args = {
        .if_name = if_name,
        .tls_port = tls_port,
    };
    threadcreate( evse_sdp_listen_discovery_msg, &sdp_args, 1024 * 1024);*/
    sdp_listen(if_name, tls_port);
    secc_listen_tls( sockfd, &create_response_message );

}
