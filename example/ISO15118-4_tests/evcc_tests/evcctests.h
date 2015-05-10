#include <nikolav2g.h>
#include <unistd.h>
#include "server.h"
#include <net/if.h>

enum {
    TEST_IGNORE = 0,
    TEST_RESPOND,
    TEST_CLOSE_CONNECTION,
};
enum{
    TC_EVCC_CMN_VTB_SessionSetup_001 = 1,
    TC_EVCC_CMN_VTB_ServiceDiscovery_001,
    TC_EVCC_CMN_VTB_ServiceDiscovery_002,
    TC_EVCC_CMN_VTB_ServiceDiscovery_003,
    TC_EVCC_CMN_VTB_ServiceDiscovery_004,
    TC_EVCC_CMN_VTB_ServiceDetailAndPaymentSelection_001,
    //TC_EVCC_CMN_VTB_Authorization_001,
    //TC_EVCC_CMN_VTB_Authorization_002,
    //TC_EVCC_CMN_VTB_Authorization_003,
    TC_EVCC_CMN_VTB_ChargeParameterDiscovery_001,
    TC_EVCC_AC_VTB_PowerDelivery_001,
    //TC_EVCC_AC_VTB_PowerDelivery_002,
    //TC_EVCC_AC_VTB_PowerDelivery_003,
    /*TC_EVCC_CMN_VTB_SessionStop_001,
    TC_EVCC_CMN_VTB_SessionStop_003,
    TC_EVCC_CMN_VTB_SessionStop_004,
    TC_EVCC_CMN_VTB_SessionStop_005,*/
    TC_EVCC_AC_VTB_ChargingStatus_001,
    /*TC_EVCC_AC_VTB_ChargingStatus_002,
    TC_EVCC_AC_VTB_ChargingStatus_003,
    TC_EVCC_AC_VTB_ChargingStatus_004,
    TC_EVCC_AC_VTB_ChargingStatus_005,*/
    TC_EVCC_LAST,
} test_t;

extern int succeses, ntest;

int service_detail_and_payment_selection_testseq(
    struct v2gEXIDocument *exiIn,
    struct v2gEXIDocument *exiOut,
    session_t *s, session_data_t *sd);

void service_discovery_test1(struct v2gEXIDocument *exiIn,
                                  struct v2gEXIDocument *exiOut,
                                  session_t *s, session_data_t *sd);

int service_discovery_test_sequence(struct v2gEXIDocument *exiIn,
                                   struct v2gEXIDocument *exiOut,
                                   session_t *s, session_data_t *sd);
int charge_parameter_discovery_test(
    struct v2gEXIDocument *exiIn,
    struct v2gEXIDocument *exiOut,
    session_t *s, session_data_t *sd);

int power_delivery_test(
    struct v2gEXIDocument *exiIn,
    struct v2gEXIDocument *exiOut,
    session_t *s, session_data_t *sd);
int charging_status_test(
    struct v2gEXIDocument *exiIn,
    struct v2gEXIDocument *exiOut,
    session_t *s, session_data_t *sd);
