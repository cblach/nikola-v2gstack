#define BASE_POWER_DELIVERY \
    int err;\
    struct v2gEXIDocument exiIn;\
    struct v2gEXIDocument exiOut;\
    init_v2g_request(&exiIn, s);\
    exiIn.V2G_Message.Body.PowerDeliveryReq_isUsed = 1u;\
	init_v2gPowerDeliveryReqType(&exiIn.V2G_Message.Body.PowerDeliveryReq);\
exiIn.V2G_Message.Body.PowerDeliveryReq.DC_EVPowerDeliveryParameter_isUsed = 0;

#define POWER_DELIVERY_REQ\
	err = v2g_request(conn, &exiIn, &exiOut);\
    if (err != 0) {\
        printf("power_delivery_request v2g_request error, exiting\n");\
        return -1;\
    }

#define VALIDATE_POWER_DELIVERY \
    if (exiOut.V2G_Message.Body.PowerDeliveryRes_isUsed != 1u) {\
        printf("power_delivery_request: wrong response type\n");\
        return -1;\
    }\
    if (verify_response_code(exiOut.V2G_Message.Body.PowerDeliveryRes.ResponseCode) != 0) {\
        printf("power_delivery_request: response NOT ok, code = %d\n", exiOut.V2G_Message.Body.PowerDeliveryRes.ResponseCode);\
        return -1;\
    }

int test_power_delivery_request1(evcc_conn_t *conn, ev_session_t *s)
{
    BASE_POWER_DELIVERY
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargeProgress = v2gchargeProgressType_Start;
	// === A charging profile is used for this request===
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed = 0;
    POWER_DELIVERY_REQ
    VALIDATE_POWER_DELIVERY
    return 0;
}

int test_power_delivery_request2(evcc_conn_t *conn, ev_session_t *s)
{
    BASE_POWER_DELIVERY
	// === A charging profile is used for this request===
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed = 0;
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargeProgress = v2gchargeProgressType_Renegotiate;
    POWER_DELIVERY_REQ
    VALIDATE_POWER_DELIVERY
    return 0;
}

int test_power_delivery_request3(evcc_conn_t *conn, ev_session_t *s)
{
    BASE_POWER_DELIVERY
	// === A charging profile is used for this request===
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed = 0;
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargeProgress = v2gchargeProgressType_Stop;
    POWER_DELIVERY_REQ
    VALIDATE_POWER_DELIVERY
    return 0;
}

int test_power_delivery_request4(evcc_conn_t *conn, ev_session_t *s)
{
    BASE_POWER_DELIVERY
    struct v2gChargingProfileType *profile = &exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile;
    exiIn.V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID  = s->pmax_schedule.tupleid;
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargeProgress = v2gchargeProgressType_Start;
	// === A charging profile is used for this request===
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed = 1u;

    profile->ProfileEntry.arrayLen = 0;
    unsigned int power = 10000;
    unsigned int mpower = 2 * power;
    SetProfileEntry(profile, 1400, power, 1);
    SetProfileEntry(profile, 1410, power, 2);
    SetProfileEntry(profile, 1420, power, 3);
    SetProfileEntry(profile, 1430, mpower, 2);
    SetProfileEntry(profile, 1440, power, 1);
    SetProfileEntry(profile, 1450, power, 2);
    SetProfileEntry(profile, 1500, power, 3);
    POWER_DELIVERY_REQ
    if (exiOut.V2G_Message.Body.PowerDeliveryRes_isUsed != 1u) {
        printf("power_delivery_request: wrong response type\n");
        return -1;\
    }\
    if (exiOut.V2G_Message.Body.PowerDeliveryRes.ResponseCode
        != v2gresponseCodeType_FAILED_ChargingProfileInvalid) {
        printf("power_delivery_request: unexpected response code, code = %d, \
        expected v2gresponseCodeType_FAILED_ChargingProfileInvalid\n", exiOut.V2G_Message.Body.PowerDeliveryRes.ResponseCode);
        return -1;
    }
    return 0;
}

int test_power_delivery_request5(evcc_conn_t *conn, ev_session_t *s)
{
    BASE_POWER_DELIVERY
    struct v2gChargingProfileType *profile = &exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile;
    exiIn.V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID  = s->pmax_schedule.tupleid;
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargeProgress = v2gchargeProgressType_Start;
	// === A charging profile is used for this request===
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed = 1u;

    profile->ProfileEntry.arrayLen = 0;
    unsigned int power = 10000;
    unsigned int mpower = power / 2;
    SetProfileEntry(profile, 1400, mpower, 1);
    SetProfileEntry(profile, 1410, mpower, 2);
    SetProfileEntry(profile, 1420, mpower, 3);
    SetProfileEntry(profile, 1430, mpower, 2);
    SetProfileEntry(profile, 1440, mpower, 1);
    SetProfileEntry(profile, 1450, mpower, 2);
    SetProfileEntry(profile, 1500, mpower, 3);
    POWER_DELIVERY_REQ
    VALIDATE_POWER_DELIVERY
    return 0;
}
