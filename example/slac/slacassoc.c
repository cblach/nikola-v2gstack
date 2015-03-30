#include "homeplug.h"
#include "slac.h"
#include "plc_eth.h"
#include <time.h>
#include <assert.h>
#include <endian.h>
#include "multitask.h"
#include <limits.h>
/*#define HOMEPLUG_MMV 0x01
#define HOMEPLUG_MMTYPE 0x0000*/
#define HOMEPLUG_HDR_SIZE 5

#define TIME_MICROSECOND 1000ULL
#define TIME_MILLISECOND ( TIME_MICROSECOND * 1000 )
#define TIME_SECOND ( TIME_MILLISECOND * 1000 )
#define MSOUND_PAUSE (40 * TIME_MILLISECOND)
#define SLAC_ATTENUATION_THRESHOLD 32 // DB
#define SLAC_T_ASSOC_MNBC_TIMEOUT (1 * TIME_SECOND)
#define SLAC_T_ASSOC_RESPONSE (200 * TIME_MILLISECOND)
typedef unsigned long long uvlong;
static inline uvlong nsleep( uvlong ns )
{
    struct timespec left, ts = { .tv_sec = ns / TIME_SECOND, .tv_nsec = ns % TIME_SECOND };
    int r = nanosleep(&ts, &left);
    assert(r == 0 || (r < 0 && errno == EINTR));
    return (r == 0) ? 0 : ((uvlong)left.tv_sec * TIME_SECOND + (uvlong)ts.tv_nsec);
}

typedef struct {
    byte num_sounds;
    byte time_out;

}slac_session_t;


void ethhomeplughdr (void* vbuf, uint8_t mmv, uint16_t mmtype)
{
    byte* buf = vbuf;
    buf[0] = mmv; // MMV
    buf[1] = mmtype & 0xFF; // written in little endian
    buf[2] = mmtype >> 8;
    buf[3] = 0; // FMSN
    buf[4] = 0; // FMID
}

int slac_verify_response(byte* buf, uint8_t mmv, uint16_t mmtype)
{
    struct homeplug* homeplug = (struct homeplug *)(buf);
    if (ntohs (homeplug->ethernet.MTYPE) != ETH_P_HPAV) {
        printf("wrong eth type\n");
        return -1;
    }
    if (homeplug->homeplug.MMV != mmv) {
        printf("wrong mmv type %u\n", mmv);
        return -1;
    }
    if (le16toh(homeplug->homeplug.MMTYPE) != mmtype) {
        printf("wrong mmtype 0x%x, expected 0x%x\n", homeplug->homeplug.MMTYPE, mmtype);
        return -1;
    }
    return 0;
}

struct slac_iosendloop_args{
    ethconn_t* ethconn;
    byte* ethframe;
    size_t framelen;
    uvlong senddelay_ns;
    int max_tries;
};

// Cancellable send loop, initiated which must be initiated with an IO-channel
static ssize_t slac_iosendloop(void* vargs, atomic_int *cancel)
{
    int err;
    bool infloop = true;
    int i;
    struct slac_iosendloop_args* args = (struct slac_iosendloop_args*)vargs;
    if (args->max_tries > 0) {
        i = 0;
        infloop = false;
    }
    while (atomic_load(cancel) == 0) {
        err = ethsend(args->ethconn, args->ethframe, args->framelen);
        if (err != 0) {
            return -1;
        }
        if (!infloop && i++ >= args->max_tries) {
            break;
        }
        nsleep(args->senddelay_ns);
    }
    return 0;
}
struct slac_iorecvloop_args{
    ethconn_t* ethconn;
    byte* ethframe;
    byte mmv;
    uint16_t mmtype;
};
// Cancellable receive/read loop, initiated which must be initiated with an IO-channel
static ssize_t slac_iorecvloop(void* vargs, atomic_int *cancel)
{
    int err;
    ssize_t n = -1;
    struct slac_iorecvloop_args* args = (struct slac_iorecvloop_args*)vargs;
    while (atomic_load(cancel) == 0) {
        n = ethrecv(args->ethconn, args->ethframe);
        if ( n <= 0) {
            return -1;
        }
        err = slac_verify_response(args->ethframe, args->mmv, args->mmtype);
        if( err != 0) {
            continue;
        }
        break;
    }
    return n;
}

// Cancellable ethnernet receive/read (cancelled with a send on channel chnc)
ssize_t slac_recv_c( ethconn_t* ethconn, byte* ethframe, byte mmv, uint16_t mmtype, Chan* chnc)
{
    ssize_t ret;
    ssize_t err;
    Chan* iocr = iochan(1048576 - PTHREAD_STACK_MIN);
    Alt alts[] = {{ .c  = iocr, .v  = &ret, .op = CHANRECV },
                  { .c  = chnc, .v  = NULL, .op = CHANRECV },
                  { .op = CHANEND }};
    struct slac_iorecvloop_args rargs = {.ethconn = ethconn,
                                  .ethframe = ethframe,
                                  .mmv = mmv,
                                  .mmtype = mmtype};
    if (iocr == NULL) {
        printf("slac_recv_c: iochan err\n");
        return -1;
    }
    iocall(iocr, &slac_iorecvloop, &rargs, sizeof(rargs));
    switch (alt(alts)) {
        case 0: // Done reading response
            printf("received valid response\n");
            err = ret;
            break;
        case 1: // Done writing and no response -> error
            iocancel(iocr);
            err = -1;
            printf("timeout\n");
            break;
        default:
            printf("critical ev_sdp_discover_evse: alt error\n");
            abort();
    }
    chanfree(iocr);
    return err;
}

// Sends an ethframe over ethconn every send_delay nanoseconds up to
// max_send_tries times until a message with the mmv recv_mmv and the mmtype
// recv_mmtype is received.
// !! Note that while the framelen can vary, the underlying
// ethframe buffer must always be at least ETH_FRAME_LEN bytes. !!
ssize_t slac_sendrecvloop( ethconn_t* ethconn, byte* ethframe, size_t framelen,
                       byte recv_mmv, uint16_t recv_mmtype,
                       int max_send_tries, uvlong senddelay_ns )
{
    ssize_t ret;
    ssize_t err;
	Chan* iocr = iochan(1048576 - PTHREAD_STACK_MIN);
	Chan* iocs = iochan(1048576 - PTHREAD_STACK_MIN);
    Alt alts[] = {{ .c  = iocr, .v  = &ret, .op = CHANRECV },
                  { .c  = iocs, .v  = &ret, .op = CHANRECV },
                  { .op = CHANEND }};
    struct slac_iorecvloop_args rargs = {.ethconn = ethconn,
                                  .ethframe = ethframe,
                                  .mmv = recv_mmv,
                                  .mmtype = recv_mmtype};
    struct slac_iosendloop_args sargs = {.ethconn = ethconn,
                                  .ethframe = ethframe,
                                  .framelen = framelen,
                                  .senddelay_ns = senddelay_ns,
                                  .max_tries = max_send_tries};
	if (iocr == NULL || iocs == NULL) {
	    printf("slac_sendrecvloop: iochan error\n");
	    if (iocr != NULL) {
	        chanfree(iocr);
	    }
	    if (iocs != NULL) {
	        chanfree(iocs);
	    }
	    return -1;
	}
	iocall(iocr, &slac_iorecvloop, &rargs, sizeof(rargs));
	iocall(iocs, &slac_iosendloop, &sargs, sizeof(sargs));
    switch (alt(alts)) {
        case 0: // Done reading response
            iocancel(iocs);
            printf("received valid response\n");
            err = ret;
            break;
        case 1: // Done writing and no response -> error
            iocancel(iocr);
            err = -1;
            break;
        default:
            printf("critical ev_sdp_discover_evse: alt error\n");
            abort();
    }
    chanfree(iocr);
    chanfree(iocs);
    return err;
}

// === Slac parameter discovery ===
int slac_cm_param_req(ethconn_t* ethconn, struct slac_session* session)
{
    byte ethframe[ETH_FRAME_LEN];
    ssize_t n;
    struct cm_slac_param_request* req = (struct cm_slac_param_request*)ethframe;
    struct cm_slac_param_confirm * confirm = (struct cm_slac_param_confirm *) (ethframe);
    ethwritehdr(&req->ethernet, ethconn, ETH_BROADCAST_ADDR);
    ethhomeplughdr(&req->homeplug, HOMEPLUG_MMV, (CM_SLAC_PARAM | MMTYPE_REQ));
    req->APPLICATION_TYPE = SLAC_APPLICATION_TYPE;
	req->SECURITY_TYPE = SLAC_SECURITY_TYPE;
	memcpy(req->RunID, session->RunID, sizeof(session->RunID));
	req->CipherSuiteSetSize = 0;
	req->CipherSuite [0] = htole16(0);
	/*request->CipherSuite [0] = HTOLE16 ((uint16_t) (session->counter));*/

	n = slac_sendrecvloop(ethconn, ethframe, sizeof(*req),
                          HOMEPLUG_MMV, (CM_SLAC_PARAM | MMTYPE_CNF),
                          0, 250 * TIME_MILLISECOND );
    if (n <= 0) {
        printf("slac_cm_param_req error\n");
        return -1;
    }
    if (confirm->APPLICATION_TYPE != SLAC_APPLICATION_TYPE) {
        printf("slac_cm_param_req: invalid slac application type\n");
        return -1;
    }
    if (confirm->SECURITY_TYPE != SLAC_SECURITY_TYPE) {
        printf("slac_cm_param_req: invalid slac security type\n");
        return -1;
    }
    //memcpy(session->EVSE_MAC, confirm->ethernet.OSA, ETH_ALEN);
    memcpy(session->FORWARDING_STA, confirm->FORWARDING_STA, sizeof (session->FORWARDING_STA));
    session->NUM_SOUNDS = confirm->NUM_SOUNDS;
    session->TIME_OUT = confirm->TIME_OUT;
    session->RESP_TYPE = confirm->RESP_TYPE;
    printf("Received leh something\n");
    return 0;
}

// === Start Attenuation Characterization ===
int slac_cm_start_atten_char(ethconn_t* ethconn, struct slac_session* session)
{
    int err, i;
    byte ethframe[ETH_FRAME_LEN];
	struct cm_start_atten_char_indicate * indicate = (struct cm_start_atten_char_indicate *) (ethframe);
	ethwritehdr(&indicate->ethernet, ethconn, ETH_BROADCAST_ADDR);
    ethhomeplughdr(&indicate->homeplug, HOMEPLUG_MMV, (CM_START_ATTEN_CHAR | MMTYPE_IND));
	indicate->APPLICATION_TYPE = SLAC_APPLICATION_TYPE;
	indicate->SECURITY_TYPE = SLAC_SECURITY_TYPE;
	indicate->ACVarField.NUM_SOUNDS = session->NUM_SOUNDS;
	indicate->ACVarField.TIME_OUT = session->TIME_OUT;
	indicate->ACVarField.RESP_TYPE = session->RESP_TYPE;
	memcpy (indicate->ACVarField.FORWARDING_STA, session->FORWARDING_STA, sizeof (indicate->ACVarField.FORWARDING_STA));
	memcpy (indicate->ACVarField.RunID, session->RunID, sizeof (indicate->ACVarField.RunID));
	for (i = 0; i < 3; i++) {
	    err = ethsend(ethconn, ethframe, sizeof(*indicate));
        if (err != 0) {
            printf("slac_cm_start_atten_char: ethsend err\n");
            return -1;
        }
    }
    return 0;
}

int slac_cm_mnbc_sound(ethconn_t* ethconn, struct slac_session* session)
{
    int err;
    byte ethframe[ETH_FRAME_LEN];
    int sound = session->NUM_SOUNDS;
    struct cm_mnbc_sound_indicate * indicate = (struct cm_mnbc_sound_indicate *) (ethframe);
	while (sound--) {
	    ethwritehdr(&indicate->ethernet, ethconn, ETH_BROADCAST_ADDR);
        ethhomeplughdr(&indicate->homeplug, HOMEPLUG_MMV, (CM_MNBC_SOUND | MMTYPE_IND));
		indicate->APPLICATION_TYPE = SLAC_APPLICATION_TYPE;
		indicate->SECURITY_TYPE = SLAC_SECURITY_TYPE;
		memcpy(indicate->MSVarField.SenderID, session->PEV_ID, sizeof (indicate->MSVarField.SenderID));
		indicate->MSVarField.CNT = sound;
		memcpy(indicate->MSVarField.RunID, session->RunID, sizeof (indicate->MSVarField.RunID));
		memset (indicate->MSVarField.RND, 0, sizeof (indicate->MSVarField.RND));
		err = ethsend(ethconn, ethframe, sizeof(*indicate) );
		//err = 1;
        if (err != 0) {
            printf("ethsend err\n");
            return -1;
        }
        nsleep(MSOUND_PAUSE);
	}
	return 0;
}

int slac_check_attn(byte AAG[SLAC_GROUPS], byte numgroups, unsigned limit)
{
    unsigned int avg, i;
	unsigned int total = 0;
	if (numgroups == 0) {
	    printf("slac_check_attn: no atten groups\n");
	    return -1;
	}
	for (i = 0; i < numgroups; i++) {
		total += AAG[i];
	}
	avg = total / i;
	if (avg > limit) {
	    printf("slac_check_attn: Average attenuation %udB high\n", avg);
        return -1;
	}
	printf("Success: Average attenuation %udB, is less than %udB\n", avg, SLAC_ATTENUATION_THRESHOLD);
	return 0;
}

// Receive attenchar request from EVSE and respond
int slac_cm_atten_char(ethconn_t* ethconn, struct slac_session* session)
{
    int err;
    ssize_t n;
    Chan tc;
    byte ethframe[ETH_FRAME_LEN];
	struct cm_atten_char_indicate * indicate = (struct cm_atten_char_indicate *) (ethframe);
	struct cm_atten_char_response * response = (struct cm_atten_char_response *) (ethframe);
	err = tchaninit(&tc);
    if (err != 0) {
        return -1;
    }
    tchanset(&tc, SLAC_T_ASSOC_MNBC_TIMEOUT);
    for (;;) {
        n = slac_recv_c(ethconn, ethframe, HOMEPLUG_MMV, (CM_ATTEN_CHAR | MMTYPE_IND), &tc);
        if (n <= 0) {
            printf("slac_cm_atten_char: slac_recv_c err\n");
            chanfree(&tc);
            return -1;
        }
        err = slac_check_attn(indicate->ACVarField.ATTEN_PROFILE.AAG, indicate->ACVarField.ATTEN_PROFILE.NumGroups,session->limit);
        if (err != 0) {
            printf("slac_associate: slac_check_attn error\n");
            continue;
        }
        break;
    }
    memcpy (session->EVSE_MAC, indicate->ethernet.OSA, ETH_ALEN);
	session->NUM_SOUNDS = indicate->ACVarField.NUM_SOUNDS;
	// === Start writing response ===
    ethwritehdr(&response->ethernet, ethconn, session->EVSE_MAC);
    ethhomeplughdr(&response->homeplug, HOMEPLUG_MMV, (CM_ATTEN_CHAR | MMTYPE_RSP));
	response->APPLICATION_TYPE = SLAC_APPLICATION_TYPE;
	response->SECURITY_TYPE = SLAC_SECURITY_TYPE;
	memcpy (response->ACVarField.SOURCE_ADDRESS, ethconn->src_mac, ETH_ALEN);
	memcpy (response->ACVarField.RunID, session->RunID,
	        sizeof (response->ACVarField.RunID));
	memset (response->ACVarField.SOURCE_ID, 0,
	        sizeof (response->ACVarField.SOURCE_ID));
	memset (response->ACVarField.RESP_ID, 0,
	        sizeof (response->ACVarField.RESP_ID));
	response->ACVarField.Result = 0;
    err = ethsend(ethconn, ethframe, sizeof(*response) );
    if (err != 0) {
        printf("slac_cm_atten_char: ethsend err\n");
        chanfree(&tc);
        return -1;
    }
	printf("happeh tihmes\n");
	chanfree(&tc);
	return 0;
}

int slac_cm_match_request(ethconn_t* ethconn, struct slac_session* session)
{
    int err;
    ssize_t n;
    byte ethframe[ETH_FRAME_LEN];
    Chan tc;
	struct cm_slac_match_request * request = (struct cm_slac_match_request *) (ethframe);
	struct cm_slac_match_confirm * confirm = (struct cm_slac_match_confirm *) (ethframe);
    ethwritehdr(&request->ethernet, ethconn, session->EVSE_MAC);
    ethhomeplughdr(&request->homeplug, HOMEPLUG_MMV, (CM_SLAC_MATCH | MMTYPE_REQ));
	request->APPLICATION_TYPE = SLAC_APPLICATION_TYPE;
	request->SECURITY_TYPE = SLAC_SECURITY_TYPE;
	request->MVFLength = htole16 (sizeof (request->MatchVarField));
	memcpy (request->MatchVarField.PEV_ID, session->PEV_ID,
	        sizeof (request->MatchVarField.PEV_ID));
	memcpy(request->MatchVarField.PEV_MAC, ethconn->src_mac, ETH_ALEN);
	memcpy(request->MatchVarField.RunID, session->RunID,
	        sizeof (request->MatchVarField.RunID));
	memset(request->MatchVarField.RSVD, 0, sizeof(request->MatchVarField.RSVD));
    err = ethsend(ethconn, ethframe, sizeof(*request));
    if (err != 0) {
        printf("slac_cm_match_request: ethsend error\n");
        return -1;
    }
    err = tchaninit(&tc);
    if (err != 0) {
        printf("tchaninit err\n");
        return -1;
    }
    tchanset(&tc, SLAC_T_ASSOC_RESPONSE);
    for(;;) {
        n = slac_recv_c(ethconn, ethframe, HOMEPLUG_MMV, (CM_SLAC_MATCH | MMTYPE_CNF), &tc);
        if (n <= 0) {
            printf("slac_cm_match_request: slac_recv err\n");
            chanfree(&tc);
            return -1;
        }
        if (memcmp (session->RunID, confirm->MatchVarField.RunID,
                    sizeof (session->RunID)) != 0) {
            printf("slac_cm_match_request: invalid runid error, repeating recv\n");
            continue;
        }
        break;
    }
    memcpy (session->EVSE_ID, confirm->MatchVarField.EVSE_ID, sizeof (session->EVSE_ID));
	memcpy (session->EVSE_MAC, confirm->MatchVarField.EVSE_MAC, ETH_ALEN);
	memcpy (session->NMK, confirm->MatchVarField.NMK, sizeof (session->NMK));
	memcpy (session->NID, confirm->MatchVarField.NID, sizeof (session->NID));
	chanfree(&tc);
    return 0;
}

int slac_cm_set_key(ethconn_t* ethconn, struct slac_session* session)
{
    int err;
    ssize_t n;
    byte ethframe[ETH_FRAME_LEN];
    Chan tc;
    struct cm_set_key_request * request = (struct cm_set_key_request *) (ethframe);
	struct cm_set_key_confirm * confirm = (struct cm_set_key_confirm *) (ethframe);

	// === Configure "Set Network Key" request ===
    ethwritehdr(&request->ethernet, ethconn, ETH_LOCAL_ATHEROS_DEVICE);
    ethhomeplughdr(&request->homeplug, HOMEPLUG_MMV, (CM_SET_KEY | MMTYPE_REQ));
	request->KEYTYPE = SLAC_CM_SETKEY_KEYTYPE;
	memset(& request->MYNOUNCE, 0xAA, sizeof (request->MYNOUNCE));
	memset(& request->YOURNOUNCE, 0x00, sizeof (request->YOURNOUNCE));
	request->PID = SLAC_CM_SETKEY_PID;
	request->PRN = htole16 (SLAC_CM_SETKEY_PRN);
	request->PMN = SLAC_CM_SETKEY_PMN;
	request->CCOCAP = SLAC_CM_SETKEY_CCO;
	memcpy(request->NID, session->NID, sizeof (request->NID));
	request->NEWEKS = SLAC_CM_SETKEY_EKS;
	memcpy(request->NEWKEY, session->NMK, sizeof (request->NEWKEY));
	memset(request->RSVD, 0, sizeof(request->RSVD));
	err = ethsend(ethconn, ethframe, sizeof(*request) );
    if (err != 0) {
        printf("slac_cm_set_key_request: ethsend error\n");
        return -1;
    }
    err = tchaninit(&tc);
    if (err != 0) {
        printf("tchaninit err\n");
        return -1;
    }
    tchanset(&tc, SLAC_T_ASSOC_RESPONSE);
    printf("====####========== SET KEY ======####======\n");
    n = slac_recv_c(ethconn, ethframe, HOMEPLUG_MMV, (CM_SET_KEY | MMTYPE_CNF), &tc);
    if (n <= 0) {
        printf("slac_cm_set_key_request: slac_recv_c err\n");
        chanfree(&tc);
        return -1;
    }
    if (confirm->RESULT == 0) {
        printf("slac_cm_set_key_request: error result\n");
        chanfree(&tc);
        return -1;
    }
    chanfree(&tc);
    return 0;
}

int slac_associate(char* if_name)
{
    struct slac_session ses;
    ethconn_t ethconn;
    byte pev_id[17] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,
                       0x11,0x22,0x33,0x44,0x55,0x66,0x77};
    int err;
    static uint8_t runid_counter = 0;
    err = ethdial(&ethconn, if_name, ETH_P_HPAV);
    if (err != 0) {
        printf("ethdial err\n");
        return -1;
    }
    memset(&ses, 0, sizeof(ses));
    memcpy(ses.RunID, ethconn.src_mac, ETH_ALEN);
	ses.RunID[6] = 0x00;
	ses.RunID[7] = runid_counter++;
	memcpy(ses.PEV_ID, pev_id, 17);
	ses.limit = SLAC_ATTENUATION_THRESHOLD;
    err = slac_cm_param_req(&ethconn, &ses);
    if (err != 0) {
        printf("slac_associate: slac_cm_param_req error\n");
        return -1;
    }
    printf("Start atten char\n");
    err = slac_cm_start_atten_char(&ethconn, &ses);
    if (err != 0) {
        printf("slac_associate: slac_cm_mnbc_sound error\n");
        return -1;
    }
    printf("Send sounds\n");
    err = slac_cm_mnbc_sound(&ethconn, &ses);
    if (err != 0) {
        printf("slac_associate: slac_cm_mnbc_sound error\n");
        return -1;
    }
    printf("Receive atten char response\n");
    err = slac_cm_atten_char(&ethconn, &ses);
    if (err != 0) {
        printf("slac_associate: slac_cm_atten_char error\n");
        return -1;
    }
    printf("Slac match request\n");
    err = slac_cm_match_request(&ethconn, &ses);
        if (err != 0) {
        printf("slac_associate: slac_cm_match_request error\n");
        return -1;
    }
    printf("set key\n");
    err = slac_cm_set_key(&ethconn, &ses);
    if (err != 0) {
        printf("slac_associate: slac_cm_set_key error\n");
        return -1;
    }
    printf("done\n");
    return 0;
}
