#define BASE_POWER_DELIVERY \
    int err;\
    struct v2gEXIDocument exiIn;\
    struct v2gEXIDocument exiOut;\
    struct v2gChargingProfileType *profile = &exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile;\
    init_v2g_request(&exiIn, s);\
    exiIn.V2G_Message.Body.PowerDeliveryReq_isUsed = 1u;\
	init_v2gPowerDeliveryReqType(&exiIn.V2G_Message.Body.PowerDeliveryReq);\
exiIn.V2G_Message.Body.PowerDeliveryReq.DC_EVPowerDeliveryParameter_isUsed = 0;\
	exiIn.V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID  = s->pmax_schedule.tupleid;

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
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed = 1u;

    profile->ProfileEntry.arrayLen = 0;
    SetProfileEntry(profile,   0, 15000, 3);
    SetProfileEntry(profile, 100, 20000, 3);
    SetProfileEntry(profile, 200, 10000, 3);
    SetProfileEntry(profile, 400,     0, 3);
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("power_delivery_request v2g_request error, exiting\n");
        return -1;
    }
    VALIDATE_POWER_DELIVERY
    return 0;
}
