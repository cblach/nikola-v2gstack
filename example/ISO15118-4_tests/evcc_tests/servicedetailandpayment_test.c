#include "evcctests.h"

int service_detail_and_payment_selection_testseq(
    struct v2gEXIDocument *exiIn,
    struct v2gEXIDocument *exiOut,
    session_t *s, session_data_t *sd)

{
    static int step = 0;
    int ret = TEST_IGNORE;
    switch (step) {
    case 0:
        if (exiIn->V2G_Message.Body.ServiceDiscoveryReq_isUsed) {
            step = 1;
        }
        break;
    case 1:
        if (exiIn->V2G_Message.Body.ServiceDetailReq_isUsed) {
            if (handle_service_detail(exiIn, exiOut, s, sd) != 0) {
                printf("Test %d Failed: Invalid request\n", ntest);
                exit(-1);
            }
        } else if (exiIn->V2G_Message.Body.PaymentServiceSelectionReq_isUsed) {
            if (payment_service_selection(exiIn, exiOut, s, sd) != 0) {
                printf("Test %d Failed: Invalid request\n", ntest);
                exit(-1);
            }
        } else {
            printf("Test %d Failed: Unexpected Request\n", ntest);
            exit(-1);
        }
        printf("Test %d Succesful: ServiceDetailAndPaymentSelection\n", ntest);
        succeses++;
        ret = TEST_CLOSE_CONNECTION;
        step = 0;
        ntest++;
        break;
    }
    return ret;
}
