#include "evcctests.h"

int power_delivery_test(
    struct v2gEXIDocument *exiIn,
    struct v2gEXIDocument *exiOut,
    session_t *s, session_data_t *sd)

{
    static int step = 0;
    int ret = TEST_IGNORE;
    switch (step) {
    case 0:
        if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed) {
		    exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed = 1u;
		    init_v2gChargeParameterDiscoveryResType(&exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes);
	        if (handle_charge_parameters(exiIn, exiOut, s, sd) != 0) {
	            printf("Test %d Failed: Charge Param initial request required\n", ntest);
	            exit(-1);
	        }
	        step = 1;
        }
        break;
    case 1:
        if (exiIn->V2G_Message.Body.PowerDeliveryReq_isUsed) {
            if (s == NULL) {
                printf("Test %d Failed: NO session\n", ntest);
            }
        } else {
            printf("Test %d Failed: Unexpected Request\n", ntest);
            exit(-1);
        }
        printf("Test %d Succesful: Power Delivery Request Received\n", ntest);
        succeses++;
        ret = TEST_CLOSE_CONNECTION;
        step = 0;
        ntest++;
        break;
    }
    return ret;
}
