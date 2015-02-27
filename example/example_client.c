#include <stdio.h>
#include "v2gstack.h"
#include "EXITypes.h"
#include "v2gEXIDatatypes.h"
#include "v2gtp.h"
#include <string.h>
#include <unistd.h>

typedef struct{
    uint64_t id;
    uint16_t charge_service_id;
    uint8_t SAScheduleTupleID;

} v2g_ev_session;

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


void init_v2g_request(struct v2gEXIDocument* exiIn, v2g_ev_session* ev_session)
{
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
int session_request(struct ev_tls_conn_t* conn, v2g_ev_session* ev_session)
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
    memcpy( &ev_session->id, exiOut.V2G_Message.Header.SessionID.bytes, 8);

    return 0;
}

int service_discovery_request(struct ev_tls_conn_t* conn, v2g_ev_session* ev_session)
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

int payment_selection_request(struct ev_tls_conn_t* conn, v2g_ev_session* ev_session)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    init_v2g_request(&exiIn, ev_session);
	init_v2gPaymentServiceSelectionReqType(&exiIn.V2G_Message.Body.PaymentServiceSelectionReq);
    exiIn.V2G_Message.Body.PaymentServiceSelectionReq_isUsed = 1u;


	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedPaymentOption = v2gpaymentOptionType_ExternalPayment;
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

int authorization_request(struct ev_tls_conn_t* conn, v2g_ev_session* ev_session)
{
    int err;
    struct v2gEXIDocument exiIn;
    struct v2gEXIDocument exiOut;
    init_v2g_request(&exiIn, ev_session);
    exiIn.V2G_Message.Body.AuthorizationReq_isUsed = 1u;
	init_v2gAuthorizationReqType(&exiIn.V2G_Message.Body.AuthorizationReq);

	exiIn.V2G_Message.Body.AuthorizationReq.GenChallenge_isUsed = 0; /* no challenge needed here*/
	exiIn.V2G_Message.Body.AuthorizationReq.Id_isUsed = 0; /* no signature needed here */

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
    if (verify_response_code(exiOut.V2G_Message.Body.AuthorizationRes.ResponseCode) != 0) {
        printf("authorization_request: authorization response NOT ok, code = %d\n", exiOut.V2G_Message.Body.AuthorizationRes.ResponseCode);
        return -1;
    }
	if(exiOut.V2G_Message.Body.AuthorizationRes.EVSEProcessing != v2gEVSEProcessingType_Finished) {
        printf("\t EVSEProcessing=Not Finished\n");
        return -1;
	}
    printf("\t EVSEProcessing=Finished\n");
    return 0;
}

int charge_parameter_request(struct ev_tls_conn_t* conn, v2g_ev_session* ev_session)
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
	charge_params->DepartureTime = 12345;

	charge_params->EAmount.Multiplier = 0;
	charge_params->EAmount.Unit = v2gunitSymbolType_W;
	charge_params->EAmount.Value = 100;

	charge_params->EVMaxCurrent.Multiplier = 0;
	charge_params->EVMaxCurrent.Unit = v2gunitSymbolType_A;
	charge_params->EVMaxCurrent.Value = 200;

	charge_params->EVMaxVoltage.Multiplier = 0;
	charge_params->EVMaxVoltage.Unit = v2gunitSymbolType_V;
	charge_params->EVMaxVoltage.Value = 400;

	charge_params->EVMinCurrent.Multiplier = 0;
	charge_params->EVMinCurrent.Unit = v2gunitSymbolType_A;
	charge_params->EVMinCurrent.Value = 500;

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
    ev_session->SAScheduleTupleID = res->SAScheduleList.SAScheduleTuple.array[0].SAScheduleTupleID;
    // === Print digest ===
	printACEVSEStatus(&(res->AC_EVSEChargeParameter.AC_EVSEStatus));
	printf("\t EVSEProcessing=%d\n", res->EVSEProcessing);
	printf("\t EVSEMaxCurrent=%d\n", res->AC_EVSEChargeParameter.EVSEMaxCurrent.Value);
	printf("\t EVSENominalVoltage=%d\n", res->AC_EVSEChargeParameter.EVSENominalVoltage.Value);
    return 0;
}

int power_delivery_request(struct ev_tls_conn_t* conn, v2g_ev_session* ev_session)
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

	/* we are using a charging profile */
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed = 1u;
	exiIn.V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID  = ev_session->SAScheduleTupleID;

    // Max 5 profile entries
	profile->ProfileEntry.arrayLen=3;
	profile->ProfileEntry.array[0].ChargingProfileEntryMaxPower.Value=0;
	profile->ProfileEntry.array[0].ChargingProfileEntryMaxPower.Unit = v2gunitSymbolType_W;
	profile->ProfileEntry.array[0].ChargingProfileEntryMaxPower.Multiplier=2;
	profile->ProfileEntry.array[0].ChargingProfileEntryStart=0;
	profile->ProfileEntry.array[0].ChargingProfileEntryMaxNumberOfPhasesInUse=1;
	profile->ProfileEntry.array[0].ChargingProfileEntryMaxNumberOfPhasesInUse_isUsed=1;
	profile->ProfileEntry.array[1].ChargingProfileEntryMaxPower.Value=20000;
	profile->ProfileEntry.array[1].ChargingProfileEntryMaxPower.Unit = v2gunitSymbolType_W;
	profile->ProfileEntry.array[1].ChargingProfileEntryMaxPower.Multiplier = 1;
	profile->ProfileEntry.array[1].ChargingProfileEntryMaxNumberOfPhasesInUse=3;
	profile->ProfileEntry.array[1].ChargingProfileEntryMaxNumberOfPhasesInUse_isUsed=1;
	profile->ProfileEntry.array[1].ChargingProfileEntryStart=300; /* 5min */
	profile->ProfileEntry.array[2].ChargingProfileEntryMaxPower.Value=0;
	profile->ProfileEntry.array[2].ChargingProfileEntryStart=1200; /* 20min */
	profile->ProfileEntry.array[2].ChargingProfileEntryMaxNumberOfPhasesInUse=3;
	profile->ProfileEntry.array[2].ChargingProfileEntryMaxNumberOfPhasesInUse_isUsed=1;
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

int charging_status_request(struct ev_tls_conn_t* conn, v2g_ev_session* ev_session)
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

int session_stop_request(struct ev_tls_conn_t* conn, v2g_ev_session* ev_session)
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
    v2g_ev_session ev_session;
    int err;
    if( ev_sdp_discover_evse( if_name, &conn.addr ) < 0 ){
        printf("main: ev_sdp_discover_evse error\n");
        return;
    }
    printf("threadcreate\n");
    err = evcc_connect_tls(&conn);
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
    err = payment_selection_request(&conn, &ev_session);
    if (err != 0) {
        printf("ev_example: payment_selection_request err\n");
        return;
    }
    err = authorization_request(&conn, &ev_session);
    if (err != 0) {
        printf("ev_example: authorization_request err\n");
        return;
    }
    err = charge_parameter_request(&conn, &ev_session);
    if (err != 0) {
        printf("ev_example: charge_parameter_request err\n");
        return;
    }
    err = power_delivery_request(&conn, &ev_session);
    if (err != 0) {
        printf("ev_example: power_delivery_request err\n");
        return;
    }
    printf("Charging\n");
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
