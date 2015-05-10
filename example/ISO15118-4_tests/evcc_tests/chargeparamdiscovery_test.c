#include "evcctests.h"

int charge_parameter_discovery_test(
    struct v2gEXIDocument *exiIn,
    struct v2gEXIDocument *exiOut,
    session_t *s, session_data_t *sd)

{
    static int step = 0;
    int ret = TEST_IGNORE;
    switch (step) {
    case 0:
        if (exiIn->V2G_Message.Body.AuthorizationReq_isUsed) {
		    exiOut->V2G_Message.Body.AuthorizationRes_isUsed = 1u;
		    init_v2gAuthorizationResType(&exiOut->V2G_Message.Body.AuthorizationRes);
	        if (handle_authorization(exiIn, exiOut, s, sd) != 0) {
	            printf("Test %d Failed: Auth request\n", ntest);
	            exit(-1);
	        }
	        step = 1;
        }
        break;
    case 1:
        if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed) {
            if (handle_charge_parameters(exiIn, exiOut, s, sd) != 0) {
                printf("Test %d Failed: Invalid request\n", ntest);
                exit(-1);
            }
        } else {
            printf("Test %d Failed: Unexpected Request\n", ntest);
            exit(-1);
        }
        printf("Test %d Succesful: Charge Parameter Request Received\n", ntest);
        succeses++;
        ret = TEST_CLOSE_CONNECTION;
        step = 0;
        ntest++;
        break;
    }
    return ret;
}
