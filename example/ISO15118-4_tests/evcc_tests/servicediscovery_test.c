#include "evcctests.h"

void service_discovery_test1(struct v2gEXIDocument *exiIn,
                                  struct v2gEXIDocument *exiOut,
                                  session_t *s, session_data_t *sd)
{
    struct v2gServiceDiscoveryResType *res = &exiOut->V2G_Message.Body.ServiceDiscoveryRes;
    if (s == NULL) {
        printf("Test %d failed, session not found\n", ntest);
        return;
    }
	res->ResponseCode = v2gresponseCodeType_OK;
	printf("Test %d: Service Discovery, succesful\n", ntest);
	succeses++;
}
void service_discovery_test2n3n4(struct v2gEXIDocument *exiIn,
                                  struct v2gEXIDocument *exiOut,
                                  session_t *s, session_data_t *sd)
{
    struct v2gServiceDiscoveryResType *res = &exiOut->V2G_Message.Body.ServiceDiscoveryRes;
    exiOut->V2G_Message.Body.ServiceDiscoveryRes_isUsed = 1u;
    init_v2gServiceDiscoveryResType(&exiOut->V2G_Message.Body.ServiceDiscoveryRes);
    if (s == NULL) {
        printf("Test %d failed, session not found\n", ntest);
        return;
    }
	res->ChargeService.FreeService = secc_free_charge && 1;
	res->ChargeService.ServiceCategory = v2gserviceCategoryType_EVCharging;
	res->ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.array[0] =
	    v2gEnergyTransferModeType_AC_single_phase_core;
	res->ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.array[1] =
	    v2gEnergyTransferModeType_AC_three_phase_core;
	res->ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.arrayLen = 2;

	res->PaymentOptionList.PaymentOption.array[0] = v2gpaymentOptionType_ExternalPayment; // EVSE handles the payment
	res->PaymentOptionList.PaymentOption.array[1] = v2gpaymentOptionType_Contract;
	res->PaymentOptionList.PaymentOption.arrayLen = 2;
	if (ntest == TC_EVCC_CMN_VTB_ServiceDiscovery_002) {
	    res->ResponseCode = v2gresponseCodeType_FAILED;
	} else if (ntest == TC_EVCC_CMN_VTB_ServiceDiscovery_003) {
	    res->ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	} else {//if(test == TC_EVCC_CMN_VTB_ServiceDiscovery_004){
        res->ResponseCode = v2gresponseCodeType_FAILED_SignatureError;
	}

}


int service_discovery_test_sequence(struct v2gEXIDocument *exiIn,
                                   struct v2gEXIDocument *exiOut,
                                   session_t *s, session_data_t *sd)
{
    static int step = 0;
    if (step == 1) {
        if (exiIn->V2G_Message.Body.SessionSetupReq_isUsed) {
            printf("Test %d Succesful: Service Discovery with Failed Code\n", ntest);
            succeses++;
        } else {
            printf("Test %d Failed: Service Discovery with Failed Code\n", ntest);
        }
        step = 0;
        ntest++;
        return TEST_IGNORE;
    }
    if (exiIn->V2G_Message.Body.ServiceDiscoveryReq_isUsed) {
        step = 1;
        service_discovery_test2n3n4(exiIn, exiOut, s, sd);
        return TEST_RESPOND;
    }
    return TEST_IGNORE;
}
