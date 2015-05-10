#include "evcctests.h"


int succeses = 0, ntest = 1;

static const char *argv0;
void usage(void)
{
    fprintf(stderr, "Usage: %s [-sv] [--] interface node-type\n", argv0);
    exit(1);
}



void session_setup_test(struct v2gEXIDocument *exiIn)
{
    uint64_t sessionid;
    if (!exiIn->V2G_Message.Body.SessionSetupReq_isUsed) {
        printf("Test %d failed, unexpected request type\n", ntest);
        return;
    }
    memcpy(&sessionid, exiIn->V2G_Message.Header.SessionID.bytes, 8);
    if (sessionid != 0) {
        printf("Test %d failed, initial session id non-zero\n", ntest);
        return;
    }
    printf("Test %d: Session setup, succesful\n", ntest);
    succeses++;
}


int tests(struct v2gEXIDocument *exiIn,
           struct v2gEXIDocument *exiOut,
           session_t *s, session_data_t *sd) {
    int ret = TEST_IGNORE;
    switch (ntest) {
    case TC_EVCC_CMN_VTB_SessionSetup_001:
        session_setup_test(exiIn);
        ret = TEST_CLOSE_CONNECTION;
        ntest++;
        break;
    case TC_EVCC_CMN_VTB_ServiceDiscovery_001:
        if (exiIn->V2G_Message.Body.ServiceDiscoveryReq_isUsed) {
            service_discovery_test1(exiIn, exiOut, s, sd);
            ret = TEST_CLOSE_CONNECTION;
            ntest++;
        }
        break;
    case TC_EVCC_CMN_VTB_ServiceDiscovery_002:
    case TC_EVCC_CMN_VTB_ServiceDiscovery_003:
    case TC_EVCC_CMN_VTB_ServiceDiscovery_004:
        ret = service_discovery_test_sequence(exiIn, exiOut, s, sd);
        break;
    case TC_EVCC_CMN_VTB_ServiceDetailAndPaymentSelection_001:
        ret = service_detail_and_payment_selection_testseq(exiIn, exiOut, s, sd);
        break;
    case TC_EVCC_CMN_VTB_ChargeParameterDiscovery_001:
        ret = charge_parameter_discovery_test(exiIn, exiOut, s, sd);
        break;
    case TC_EVCC_AC_VTB_PowerDelivery_001:
        ret = power_delivery_test(exiIn, exiOut, s, sd);
        break;
    case TC_EVCC_AC_VTB_ChargingStatus_001:
        ret = charging_status_test(exiIn, exiOut, s, sd);
        break;
    default:
        printf("Done testing, %d/%d tests succesful\n", succeses, ntest - 1);
        exit(0);
    }
    return ret;
}
int create_response_message_evcctest(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut, bool tls_enabled) {
	int err = -1, exit = 0;//ERROR_UNEXPECTED_REQUEST_MESSAGE;
    session_t *s;
    session_data_t *sd;
    // Test 1 completed if we have gotten this far (i.e. correct application handshake

	/* create response message as EXI document */
	if (!exiIn->V2G_Message_isUsed) {
	    printf("V2GMessage not used\n");
	    return -1;
	}

    // === Fetch the session ===
    if (exiIn->V2G_Message.Body.SessionSetupReq_isUsed) {
	    s = session_new(sizeof(session_data_t), &session_data_cleanup);
    } else {
        s = session_lookup_exi(exiIn);
    }
    // Note that the session can be NULL, thus this must be
    // check in the individual response functions
    sd = (session_data_t*)&s->data;
    // === Inititialize request handling ===
    session_lock(s);
	init_v2g_response(exiOut, s);
	// === Start request handling ===
    exit = tests(exiIn, exiOut, s, sd);
    if (exit == TEST_RESPOND) {
        session_unlock(s);
        session_remove_ref(s);
        return 0;
    } else if (exit == TEST_CLOSE_CONNECTION) {
        session_unlock(s);
        session_remove_ref(s);
        return -1;
    }
	if (exiIn->V2G_Message.Body.SessionSetupReq_isUsed) {
	    exiOut->V2G_Message.Body.SessionSetupRes_isUsed = 1u;
	    init_v2gSessionSetupResType(&exiOut->V2G_Message.Body.SessionSetupRes);
		err = handle_session_setup(exiIn, exiOut, s, sd);
	}
	else if (exiIn->V2G_Message.Body.ServiceDiscoveryReq_isUsed) {
		exiOut->V2G_Message.Body.ServiceDiscoveryRes_isUsed = 1u;
	    init_v2gServiceDiscoveryResType(&exiOut->V2G_Message.Body.ServiceDiscoveryRes);
		err = handle_service_discovery(exiIn, exiOut, s, sd);
	} else if (exiIn->V2G_Message.Body.ServiceDetailReq_isUsed) {
		exiOut->V2G_Message.Body.ServiceDetailRes_isUsed = 1u;
	    init_v2gServiceDetailResType(&exiOut->V2G_Message.Body.ServiceDetailRes);
	    err = handle_service_detail(exiIn, exiOut, s, sd);
	} else if (exiIn->V2G_Message.Body.PaymentServiceSelectionReq_isUsed) {
	    exiOut->V2G_Message.Body.PaymentServiceSelectionRes_isUsed= 1u;
	    init_v2gPaymentServiceSelectionResType(&exiOut->V2G_Message.Body.PaymentServiceSelectionRes);
	    err = payment_service_selection(exiIn, exiOut, s, sd);
	} else if (exiIn->V2G_Message.Body.PaymentDetailsReq_isUsed) {
	    exiOut->V2G_Message.Body.PaymentDetailsRes_isUsed = 1u;
	    init_v2gPaymentDetailsResType(&exiOut->V2G_Message.Body.PaymentDetailsRes);
		err = handle_payment_detail(exiIn, exiOut, s, sd);
	} else if (exiIn->V2G_Message.Body.AuthorizationReq_isUsed) {
		exiOut->V2G_Message.Body.AuthorizationRes_isUsed = 1u;
		init_v2gAuthorizationResType(&exiOut->V2G_Message.Body.AuthorizationRes);
	    err = handle_authorization(exiIn, exiOut, s, sd);
	} else if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed) {
	    exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed = 1u;
	    init_v2gChargeParameterDiscoveryResType(&exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes);
	    err = handle_charge_parameters(exiIn, exiOut, s, sd);
	} else if (exiIn->V2G_Message.Body.PowerDeliveryReq_isUsed) {
	    exiOut->V2G_Message.Body.PowerDeliveryRes_isUsed = 1u;
	    init_v2gPowerDeliveryResType(&exiOut->V2G_Message.Body.PowerDeliveryRes);
		err = handle_power_delivery(exiIn, exiOut, s, sd);
	} else if (exiIn->V2G_Message.Body.ChargingStatusReq_isUsed) {
	    exiOut->V2G_Message.Body.ChargingStatusRes_isUsed = 1u;
	    init_v2gChargingStatusResType(&exiOut->V2G_Message.Body.ChargingStatusRes);
		err = handle_charging_status(exiIn, exiOut, s, sd);
	} else if (exiIn->V2G_Message.Body.MeteringReceiptReq_isUsed) {
	    err =  -1;
		//errn = meteringReceipt(exiIn, exiOut);
	} else if (exiIn->V2G_Message.Body.SessionStopReq_isUsed) {
	    exiOut->V2G_Message.Body.SessionStopRes_isUsed = 1u;
	    init_v2gSessionStopResType(&exiOut->V2G_Message.Body.SessionStopRes);
	    err = handle_session_stop(exiIn, exiOut, s, sd);
	} else {
	    printf("create_response_message: request type not found\n");
	}
	session_unlock(s);
	session_remove_ref(s);
	if (err != 0) {
        printf("Handle request returning %d\n", err);
    }
	return err;
}


// === Note that this test only tests TCP since no tests are defined for TLS ===
void evcc_tester(const char* iface) {
    int tcp_port;
    // === Bind to dynamic port ===
    int tcp_sockfd = bind_v2gport(&tcp_port);
    if (tcp_sockfd < 0) {
        printf("secc_bind_tls  returned %d\n", tcp_sockfd);
        return;
    }
    init_sessions();
    secc_listen_tcp(tcp_sockfd, &create_response_message_evcctest);
    sdp_listen(iface, 0, tcp_port);
    printf("Test %d: SupportedAppProtocol Request\n", ++ntest);
}

void threadmain(int argc,
       char *argv[])
{
    const char *iface;
    int opt, notls = 0;
    argv0 = argv[0];
    while ((opt = getopt(argc, argv, "vn")) != -1) {
        switch (opt) {
        /*case 's':
            slac++;
            break;*/
        case 'v':
            chattyv2g++;
            break;
        case 'n': // no tls
            notls++;
            break;
        default:
            usage();
        }
    }
    if (optind >= argc) { usage(); }
    iface = argv[optind];
    secc_free_charge++;
    evcc_tester(iface);
    exit(0);
}
