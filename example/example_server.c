#include "v2gstack.h"
#include "EXITypes.h"
#include "v2gEXIDatatypes.h"
#include <stdio.h>
#include <string.h>


const v2gEnergyTransferModeType ENERGY_TRANSFER_MODES[] =
{ 	v2gEnergyTransferModeType_AC_single_phase_core,
	v2gEnergyTransferModeType_AC_three_phase_core,
};

void init_v2g_response(struct v2gEXIDocument* exiOut, session_t* session)
{
    init_v2gEXIDocument(exiOut);
	exiOut->V2G_Message_isUsed = 1u;
	init_v2gMessageHeaderType(&exiOut->V2G_Message.Header);
	// Set session id to 0
	if (session == NULL) {
	    memset(exiOut->V2G_Message.Header.SessionID.bytes, 0, 8);
	} else {
	    memcpy(exiOut->V2G_Message.Header.SessionID.bytes, &session->id, 8);
	}
	exiOut->V2G_Message.Header.SessionID.bytesLen = 8;
//	exiIn->V2G_Message.Header.Notification_isUsed = 0u; /* no notification */
//	exiIn->V2G_Message.Header.Signature_isUsed = 0u;
    init_v2gBodyType(&exiOut->V2G_Message.Body);
}




static int handle_session_setup(struct v2gEXIDocument* exiIn, struct v2gEXIDocument* exiOut)
{
    struct v2gSessionSetupResType* res = &exiOut->V2G_Message.Body.SessionSetupRes;
/* generate an unique sessionID */
    session_t* session;
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
    session_remove_ref(session);
    return 0;
}

static int handle_service_discovery(struct v2gEXIDocument* exiIn, struct v2gEXIDocument* exiOut)
{
    session_t* session;
    struct v2gServiceDiscoveryResType* res = &exiOut->V2G_Message.Body.ServiceDiscoveryRes;
    // === Lookup session ===
    session = session_lookup_exi(exiIn);
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
    session_remove_ref(session); // Only remove ref if session != NULL
    return 0;
}

static int payment_service_selection(struct v2gEXIDocument* exiIn, struct v2gEXIDocument* exiOut)
{
    struct v2gPaymentServiceSelectionReqType* req = &exiIn->V2G_Message.Body.PaymentServiceSelectionReq;
    struct v2gPaymentServiceSelectionResType* res = &exiOut->V2G_Message.Body.PaymentServiceSelectionRes;
    session_t* session = session_lookup_exi(exiIn);
	init_v2g_response(exiOut, session);
	exiOut->V2G_Message.Body.PaymentServiceSelectionRes_isUsed= 1u;
	init_v2gPaymentServiceSelectionResType(res);
    if (session == NULL) {
        printf("create_response_message error: session_lookup_exi\n");
	    memset(res, 0, sizeof(*res));
        res->ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
        return 0;
    }
	if(req->SelectedPaymentOption == v2gpaymentOptionType_ExternalPayment)  {
		printf("\t\t SelectedPaymentOption=ExternalPayment\n");
	}
	/*for (int i=0; i < req->SelectedServiceList.SelectedService.arrayLen;i++) {

	}*/
    res->ResponseCode = v2gresponseCodeType_OK;
    session_remove_ref(session);
    return 0;
}

static int handle_authorization(struct v2gEXIDocument* exiIn, struct v2gEXIDocument* exiOut) {
    struct v2gAuthorizationReqType* req = &exiIn->V2G_Message.Body.AuthorizationReq;
    struct v2gAuthorizationResType* res = &exiOut->V2G_Message.Body.AuthorizationRes;
    session_t* session = session_lookup_exi(exiIn);
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
	res->ResponseCode = v2gresponseCodeType_OK;
	session_remove_ref(session);
	return 0;
}

static int handle_charge_parameters(struct v2gEXIDocument* exiIn, struct v2gEXIDocument* exiOut)
{
    struct v2gChargeParameterDiscoveryReqType* req = &exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq;
    struct v2gChargeParameterDiscoveryResType* res = &exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes;
    session_t* session = session_lookup_exi(exiIn);
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
        session_lock(session);
        session->energy_transfer_mode = req->RequestedEnergyTransferMode;
        session_unlock(session);
        res->ResponseCode = v2gresponseCodeType_OK;
    }
	session_remove_ref(session);
    return 0;
}

int handle_power_delivery(struct v2gEXIDocument* exiIn, struct v2gEXIDocument* exiOut)
{
    struct v2gPowerDeliveryReqType* req = &exiIn->V2G_Message.Body.PowerDeliveryReq;
    struct v2gPowerDeliveryResType* res = &exiOut->V2G_Message.Body.PowerDeliveryRes;
    session_t* session = session_lookup_exi(exiIn);
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
        session_remove_ref(session);
        return -1;
    }
	res->ResponseCode = v2gresponseCodeType_OK;
	session_remove_ref(session);
	return 0;
}

int handle_charging_status(struct v2gEXIDocument* exiIn, struct v2gEXIDocument* exiOut)
{
    struct v2gChargingStatusReqType* req = &exiIn->V2G_Message.Body.ChargingStatusReq;
    struct v2gChargingStatusResType* res = &exiOut->V2G_Message.Body.ChargingStatusRes;
    session_t* session = session_lookup_exi(exiIn);
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
	session_remove_ref(session);
	return 0;
}

static int handle_session_stop(struct v2gEXIDocument* exiIn, struct v2gEXIDocument* exiOut) {
    struct v2gSessionStopReqType* req = &exiIn->V2G_Message.Body.SessionStopReq;
    struct v2gSessionStopResType* res = &exiOut->V2G_Message.Body.SessionStopRes;
    session_t* session = session_lookup_exi(exiIn);
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
    session_remove_ref(session);
	return 0;
}

static int create_response_message(struct v2gEXIDocument* exiIn, struct v2gEXIDocument* exiOut) {
	int err = -1;//ERROR_UNEXPECTED_REQUEST_MESSAGE;

	/* create response message as EXI document */
	if (exiIn->V2G_Message_isUsed) {
		init_v2gEXIDocument(exiOut);
		if (exiIn->V2G_Message.Body.SessionSetupReq_isUsed) {
		    printf("Handling session setup request\n");
			err = handle_session_setup(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.ServiceDiscoveryReq_isUsed) {
			//errn = serviceDiscovery(exiIn, exiOut);
			printf("Handling service discovery request\n");
			err = handle_service_discovery(exiIn, exiOut);
			printf("service discovery res i used = %u\n", exiOut->V2G_Message.Body.ServiceDiscoveryRes_isUsed);
		} else if (exiIn->V2G_Message.Body.ServiceDetailReq_isUsed) {
		    printf("Handling service detail request\n");
			//errn = serviceDetail(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PaymentServiceSelectionReq_isUsed) {
		    printf("Handling payment service selection request\n");
		    err = payment_service_selection(exiIn, exiOut);
			//errn = paymentServiceSelection(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PaymentDetailsReq_isUsed) {
		    printf("Handling payment details request\n");
			//errn = paymentDetails(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.AuthorizationReq_isUsed) {
		    printf("Handling authorization request\n");
		    err = handle_authorization(exiIn, exiOut);
			//errn = authorization(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed) {
		    printf("Handling charge parameter discv. request\n");
		    err = handle_charge_parameters(exiIn, exiOut);
			//errn = chargeParameterDiscovery(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PowerDeliveryReq_isUsed) {
		    printf("Handling power delivery request\n");
			err = handle_power_delivery(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.ChargingStatusReq_isUsed) {
		    printf("Handling charging status request\n");
			err = handle_charging_status(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.MeteringReceiptReq_isUsed) {
		    printf("Handling metering receipt request\n");
			//errn = meteringReceipt(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.SessionStopReq_isUsed) {
		    printf("Handling session stop request\n");
		    err = handle_session_stop(exiIn, exiOut);
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
