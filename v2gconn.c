#include "nikolav2g.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <polarssl/ssl_cache.h>
#include <polarssl/error.h>
#include <OpenV2G/appHandEXIDatatypes.h>
#include <OpenV2G/appHandEXIDatatypesEncoder.h>
#include <OpenV2G/appHandEXIDatatypesDecoder.h>
#include <OpenV2G/v2gEXIDatatypesEncoder.h>
#include <OpenV2G/v2gEXIDatatypesDecoder.h>
#include <OpenV2G/v2gtp.h>
int chattyv2g = 0;
//===================================
//             Defines
//===================================



#define V2G_EVCC_Msg_Timeout_SupportedAppProtocolReq 2
#define V2G_EVCC_Msg_Timeout_SessionSetupReq 2
#define V2G_EVCC_Msg_Timeout_ServiceDiscoveryReq 2
#define V2G_EVCC_Msg_Timeout_ServiceDetailReq 5
#define V2G_EVCC_Msg_Timeout_PaymentServiceSelectionReq 2
#define V2G_EVCC_Msg_Timeout_PaymentDetailsReq 5
#define V2G_EVCC_Msg_Timeout_AuthorizationReq 2
#define V2G_EVCC_Msg_Timeout_ChargeParameterDiscoveryReq 2
#define V2G_EVCC_Msg_Timeout_ChargingStatusReq 2
#define V2G_EVCC_Msg_Timeout_MeteringReceiptReq 2
#define V2G_EVCC_Msg_Timeout_PowerDeliveryReq 5
#define V2G_EVCC_Msg_Timeout_CableCheckReq 2
#define V2G_EVCC_Msg_Timeout_PreChargeReq 2
#define V2G_EVCC_Msg_Timeout_CurrentDemandReq 0.25
#define V2G_EVCC_Msg_Timeout_WeldingDetectionReq 2
#define V2G_EVCC_Msg_Timeout_SessionStopReq 2
#define V2G_EVCC_Msg_Timeout_CertificateInstallationReq 5
#define V2G_EVCC_Msg_Timeout_CertificateUpdateReq 5
#define V2G_EVCC_Msg_Timeout_Default 2
#define V2G_SECC_Sequence_Timeout 60

#define IGNORE_SSL_CERTIFICATE_VALIDITY 1 // Set to 1 for testing
#define TIME_MICROSECOND 1000
#define TIME_MILLISECOND (TIME_MICROSECOND * 1000)
#define TIME_SECOND (TIME_MILLISECOND * 1000)

#define BUFFER_SIZE 4096
#define MAX_CLIENT_REQUEST_QUEUE_LEN 100
#define ISO_15118_MSG_DEF "urn:iso:15118:2:2010:MsgDef"
//===================================
//             Typdefs
//===================================
#ifndef byte
typedef uint8_t byte;
#endif
typedef unsigned long long uvlong;

// Defined in nicolav2g.h:
// typedef struct blocking_request blocking_request_t;
struct blocking_request {
    Chan wake_chan;
    byte *buffer; // Used both for request & response
    size_t buffer_len; // size of the underlying buffer
    blocking_request_t *next;
};

typedef struct ssln_arg ssln_arg_t;
struct ssln_arg {
    ssl_context *ssl;
    byte *buffer;
    unsigned int n;
};

typedef struct tcpn_arg tcpn_arg_t;
struct tcpn_arg{
    int sockfd;
    byte *buffer;
    unsigned int n;
};



//===================================
//             Globals
//===================================
static const uint8_t SECC_LOCALHOST_ADDR[16] = { 0, 0, 0, 0,
                                                0, 0, 0, 0,
                                                0, 0, 0, 0,
                                                0, 0, 0, 1 };
static const int V2G_CIPHER_SUITES[] = {
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    0
};

uint16_t SECC_Port;

//======================================
//            Error print
//======================================

void print_byte_array(byte *arr, size_t n)
{
    int i;
    if (chattyv2g) fprintf(stderr, "[");
    // Highly ineffictive but whatever it's TESTING!! :D
    for (i = 0; i < n; i++) {
        if (chattyv2g) fprintf(stderr,  " %02x", arr[i]);
    }
    if (chattyv2g) fprintf(stderr, " ]\n");
}

void print_ssl_read_err(int err)
{
    switch (err) {
        case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
            if (chattyv2g) fprintf(stderr,  "connection was closed gracefully\n");
            return;
        case POLARSSL_ERR_NET_CONN_RESET:
            if (chattyv2g) fprintf(stderr,  "connection was reset by peer\n");
            return;
        case POLARSSL_ERR_NET_WANT_READ:
        case POLARSSL_ERR_NET_WANT_WRITE:
            if (chattyv2g) fprintf(stderr, "ssl socket error; want read/want write\n");
            return;
        case 0:
            if (chattyv2g) fprintf(stderr, "EOF\n");
            return;
        default:
            if (chattyv2g) fprintf(stderr,  "ssl_read returned -0x%04x\n", -err);
            return;
    }
}

//======================================
//            Non-SSL IO functions
//======================================

static ssize_t iocall_readn(void *vargs, atomic_int *cancel)
{
    tcpn_arg_t *args = vargs;
    int bytes_read = 0;
    int tries = 0;
    int ret;
    while (bytes_read < args->n && atomic_load(cancel) == 0) {
        ret = read(args->sockfd, args->buffer + bytes_read,
                   args->n - bytes_read);
        if (ret == POLARSSL_ERR_NET_WANT_READ ||
            ret == POLARSSL_ERR_NET_WANT_WRITE) {
            if (tries > 30) {
                if (chattyv2g) fprintf(stderr, "sslreadn: Too many socket read errors\n");
                return -1;
            }
            continue;
        }
        if (ret < 1) {
            if (ret != 0) {
                if (chattyv2g) fprintf(stderr, "%s: %m\n", "iocall_readn: read err");
            }
            return -1;
        }
        bytes_read += ret;
    }
    return 0;
}

static ssize_t iocall_writen(void *vargs, atomic_int *cancel)
{
    tcpn_arg_t *args = vargs;
    int bytes_written = 0;
    int ret;
    while (bytes_written < args->n && atomic_load(cancel) == 0) {
        ret = write(args->sockfd, args->buffer + bytes_written,
                    args->n - bytes_written);
        if (ret < 1) {
            if (ret != 0) {
                if (chattyv2g) fprintf(stderr, "%s: %m\n", "iocall_writen: write err");
            }
            return -1;
        }
        bytes_written += ret;
    }
    return 0;
}

static int readn(int sockfd, byte *buffer,
                  unsigned int n, Chan *tc)
{
    Alt alts[3];
    tcpn_arg_t args = {
        .sockfd = sockfd,
        .buffer = buffer,
        .n = n,
    };
    ssize_t ret;
    int err;
    Chan *ioc = iochan(1048576 - PTHREAD_STACK_MIN);
    if (ioc == NULL) {
        if (chattyv2g) fprintf(stderr, "sslreadn error: iochan error\n");
        return -1;
    }
    iocall(ioc, &iocall_readn, &args, sizeof(args));
    alts[0].c = ioc;
    alts[0].v = &ret;
    alts[0].op = CHANRECV;
    alts[1].c = tc;
    alts[1].v = NULL;
    alts[1].op = CHANRECV;
    alts[2].op = CHANEND;
    switch (alt(alts)) {
        case 0:
            err = (int)ret;
            break;
        case 1:
            iocancel(ioc);
            if (chattyv2g) fprintf(stderr, "sslreadn error: timeout\n");
            err = -1;
            break;
        default:
            if (chattyv2g) fprintf(stderr, "critical sslreadn: alt error\n");
            abort();
    }
    chanfree(ioc);
    return err;
}

static int writen(int sockfd, byte *buffer,
                   unsigned int n, Chan *tc)
{
    Alt alts[3];
    tcpn_arg_t args = {
        .sockfd = sockfd,
        .buffer = buffer,
        .n = n,
    };
    ssize_t ret;
    int err;
    Chan *ioc = iochan(1048576 - PTHREAD_STACK_MIN);
    if (ioc == NULL) {
        if (chattyv2g) fprintf(stderr, "sslwriten error: iochan error\n");
        return -1;
    }
    iocall(ioc, &iocall_writen, &args, sizeof(args));
    alts[0].c = ioc;
    alts[0].v = &ret;
    alts[0].op = CHANRECV;
    alts[1].c = tc;
    alts[1].v = NULL;
    alts[1].op = CHANRECV;
    alts[2].op = CHANEND;
    switch (alt(alts)) {
        case 0:
            err = (int) ret;
            break;
        case 1:
            iocancel(ioc);
            if (chattyv2g) fprintf(stderr, "sslwriten error: timeout\n");
            err = -1;
            break;
        default:
            if (chattyv2g) fprintf(stderr, "critical sslwriten: alt error\n");
            abort();
    }
    chanfree(ioc);
    return err;
}
//======================================
//            SSL IO functions
//======================================
static ssize_t iocall_sslreadn(void *vargs, atomic_int *cancel)
{
    ssln_arg_t *args = vargs;
    int bytes_read = 0;
    int tries = 0;
    int ret;
    while (bytes_read < args->n && atomic_load(cancel) == 0) {
        ret = ssl_read(args->ssl, args->buffer + bytes_read,
                       args->n - bytes_read);
        if (ret == POLARSSL_ERR_NET_WANT_READ ||
            ret == POLARSSL_ERR_NET_WANT_WRITE) {
            if (tries > 30) {
                if (chattyv2g) fprintf(stderr, "sslreadn: Too many socket read errors\n");
                return -1;
            }
            continue;
        }
        if (ret < 1) {
            print_ssl_read_err(ret);
            return -1;
        }
        bytes_read += ret;
    }
    return 0;
}

static ssize_t iocall_sslwriten(void *vargs, atomic_int *cancel)
{
    ssln_arg_t *args = vargs;
    int bytes_written = 0;
    int ret;
    while (bytes_written < args->n && atomic_load(cancel) == 0) {
        ret = ssl_write(args->ssl, args->buffer + bytes_written,
                        args->n - bytes_written);
        if (ret < 1) {
            print_ssl_read_err(ret);
            return -1;
        }
        bytes_written += ret;
    }
    return 0;
}


static int sslreadn(ssl_context *ssl, byte *buffer,
                    unsigned int n, Chan *tc)
{
    Alt alts[3];
    ssln_arg_t args = {
        .ssl = ssl,
        .buffer = buffer,
        .n = n,
    };
    ssize_t ret;
    int err;
    Chan *ioc = iochan(1048576 - PTHREAD_STACK_MIN);
    if (ioc == NULL) {
        if (chattyv2g) fprintf(stderr, "sslreadn error: iochan error\n");
        return -1;
    }
    iocall(ioc, &iocall_sslreadn, &args, sizeof(args));
    alts[0].c = ioc;
    alts[0].v = &ret;
    alts[0].op = CHANRECV;
    alts[1].c = tc;
    alts[1].v = NULL;
    alts[1].op = CHANRECV;
    alts[2].op = CHANEND;
    switch (alt(alts)) {
        case 0:
            err = (int)ret;
            break;
        case 1:
            iocancel(ioc);
            if (chattyv2g) fprintf(stderr, "sslreadn error: timeout\n");
            err = -1;
            break;
        default:
            if (chattyv2g) fprintf(stderr, "critical sslreadn: alt error\n");
            abort();
    }
    chanfree(ioc);
    return err;
}

static int sslwriten(ssl_context *ssl, byte *buffer,
                     unsigned int n, Chan *tc)
{
    Alt alts[3];
    ssln_arg_t args = {
        .ssl = ssl,
        .buffer = buffer,
        .n = n,
    };
    ssize_t ret;
    int err;
    Chan *ioc = iochan(1048576 - PTHREAD_STACK_MIN);
    if (ioc == NULL) {
        if (chattyv2g) fprintf(stderr, "sslwriten error: iochan error\n");
        return -1;
    }
    iocall(ioc, &iocall_sslwriten, &args, sizeof(args));
    alts[0].c = ioc;
    alts[0].v = &ret;
    alts[0].op = CHANRECV;
    alts[1].c = tc;
    alts[1].v = NULL;
    alts[1].op = CHANRECV;
    alts[2].op = CHANEND;
    switch (alt(alts)) {
        case 0:
            err = (int) ret;
            break;
        case 1:
            iocancel(ioc);
            if (chattyv2g) fprintf(stderr, "sslwriten error: timeout\n");
            err = -1;
            break;
        default:
            if (chattyv2g) fprintf(stderr, "critical sslwriten: alt error\n");
            abort();
    }
    chanfree(ioc);
    return err;
}

// combiness both encrypted and unencrypted communication
int comboreadn(comboconn_t *cconn, byte *buffer,
               unsigned int n, Chan *t) {
    if (cconn->tls_enabled) {
        return sslreadn(&cconn->ssl, buffer, n, t);
    }
    return readn(cconn->sockfd, buffer, n, t);
}

int combowriten(comboconn_t *cconn, byte *buffer,
                unsigned int n, Chan *t) {
    if (cconn->tls_enabled) {
        return sslwriten(&cconn->ssl, buffer, n, t);
    }
    return writen(cconn->sockfd, buffer, n, t);
}

uint16_t get_secc_port()
{
    // No mutexes are used since it's assumed
    // secc_listen_tls is only started once:
    // i.e. in program init
    return SECC_Port;
}

void my_debug(void *ctx, int level, const char *str)
{
    ((void)level);
    ((void)ctx);
    if (chattyv2g) {
        fprintf(stderr, "%s", str);
        fflush(stderr);
    }

}

//======================================
//          EXI functions
//======================================

static int serializeEXI2Stream(struct v2gEXIDocument *exiIn, bitstream_t *stream)
{
	int errn;
	*stream->pos = V2GTP_HEADER_LENGTH;  // v2gtp header
	if ((errn = encode_v2gExiDocument(stream, exiIn)) == 0) {
		errn = write_v2gtpHeader(stream->data, (*stream->pos)-V2GTP_HEADER_LENGTH, V2GTP_EXI_TYPE);
	}
	return errn;
}


// deserializes V2G TP header and decodes right away EXI stream
static int deserializeStream2EXI(bitstream_t *streamIn, struct v2gEXIDocument *exi)
{
	int errn;
	uint16_t payloadLength;

	*streamIn->pos = 0;
	if ((errn = read_v2gtpHeader(streamIn->data, &payloadLength)) == 0) {
		*streamIn->pos += V2GTP_HEADER_LENGTH;

		errn = decode_v2gExiDocument(streamIn, exi);
	}
	return errn;
}

static int writeStringToEXIString(const char *string,
                                  exi_string_character_t *exiString)
{
	int pos = 0;
	while(string[pos]!='\0')
	{
		exiString[pos] = string[pos];
		pos++;
	}
	return pos;
}

// existrings are not null-terminated
static int compare_exi_string_to_string(exi_string_character_t *existring,
                                        const char *string, int n)
{
	int pos = 0;
	while (string[pos]!='\0' && pos < n) {
	    if ((exi_string_character_t)string[pos] != existring[pos]) {
            break;
	    }
	    if (pos == n - 1) {
	        return 0;
	    }
	    pos++;
	}
	return -1;
}

uvlong get_req_timeout(struct v2gEXIDocument *exiIn)
{
    if (exiIn->V2G_Message.Body.SessionSetupReq_isUsed) {
        return (uvlong)V2G_EVCC_Msg_Timeout_SessionSetupReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.ServiceDiscoveryReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_ServiceDiscoveryReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.ServiceDetailReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_ServiceDetailReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.PaymentServiceSelectionReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_PaymentServiceSelectionReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.PaymentDetailsReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_PaymentDetailsReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.AuthorizationReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_AuthorizationReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_ChargeParameterDiscoveryReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.PowerDeliveryReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_PowerDeliveryReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.ChargingStatusReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_ChargingStatusReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.MeteringReceiptReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_MeteringReceiptReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.SessionStopReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_SessionStopReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.CableCheckReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_CableCheckReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.PreChargeReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_PreChargeReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.CurrentDemandReq_isUsed) {
		return (uvlong)V2G_EVCC_Msg_Timeout_CurrentDemandReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.WeldingDetectionReq_isUsed) {
	    return (uvlong)V2G_EVCC_Msg_Timeout_WeldingDetectionReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.CertificateInstallationReq_isUsed) {
	    return (uvlong)V2G_EVCC_Msg_Timeout_CertificateInstallationReq * TIME_SECOND;
	} else if (exiIn->V2G_Message.Body.CertificateUpdateReq_isUsed) {
	    return (uvlong)V2G_EVCC_Msg_Timeout_CertificateUpdateReq * TIME_SECOND;
	} else {
	    if (chattyv2g) fprintf(stderr, "get_req_timeout: unknown request, using default timeout\n");
	    return (uvlong)V2G_EVCC_Msg_Timeout_Default * TIME_SECOND;
	}
}

//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
//======================================
//      Server (EVSE)
//======================================
//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

struct tls_global_params_t{
    x509_crt srvcert;
    pk_context pkey;
    entropy_context entropy;
    ssl_cache_context cache;
    handle_func_t handle_func;
};
struct handletls_args_t{
    int fd;
    struct tls_global_params_t *global;
};

// Bind the TLS listener to a dynamic port
int bind_v2gport(int *port)
{
    int err;
    struct sockaddr_in6 bound_laddr;
    unsigned int bound_laddr_len = sizeof(bound_laddr);
    struct sockaddr_in6 laddr = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(0), // dynamic port
    };
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "socket");
        return -1;
    }
    memcpy(laddr.sin6_addr.s6_addr, SECC_LOCALHOST_ADDR, 16);
    if (listen(sock, 127) < 0) {
        close(sock);
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "listen");
        return -1;
    }
    // === Set the dynamic port number if called with pointer ===
    if (port != NULL) {
        err = getsockname(sock, (struct sockaddr*) &bound_laddr, &bound_laddr_len);
        if (err < 0) {
            close(sock);
            if (chattyv2g) fprintf(stderr, "%s: %m\n", "getsockname");
            return -1;
        }
        *port = (int)ntohs(bound_laddr.sin6_port);
    }
    return sock;
}

// Handle v2g handshake (exchange of supported app protocols)
int handle_handshake (comboconn_t *cconn, Chan *tc)
{
    int err, i, strlen;
    exi_string_character_t *str;
    struct appHandEXIDocument handshake_req;
    struct appHandEXIDocument handshake_resp;
    uint16_t buffer_pos = 0;
    unsigned char buf[BUFFER_SIZE];
    bitstream_t stream = {
        .size = BUFFER_SIZE,
        .data = buf,
        .pos  = &buffer_pos,
        .buffer = 0,
        .capacity = 0, // Set to 8 for send and 0 for recv
    };
    uint16_t payload_len;
    // === Wait for request header ===
    err = comboreadn(cconn, buf, V2GTP_HEADER_LENGTH, tc);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "handle_handshake: sslreadn error\n");
        return -1;
    }
    err = read_v2gtpHeader(buf, &payload_len);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "handle_handshake: invalid v2gtp header\n");
        return -1;
    }
    if ((size_t)payload_len + V2GTP_HEADER_LENGTH > BUFFER_SIZE) {
        if (chattyv2g) fprintf(stderr, "Buffer too small for request\n");
        return -1;
    }
    // === Read handshake request ===
    err = comboreadn(cconn, buf + V2GTP_HEADER_LENGTH, payload_len, tc);
    if  (err != 0) {
        if (chattyv2g) fprintf(stderr, "handle_handshake: sslreadn error\n");
        return -1;
    }
    buffer_pos = V2GTP_HEADER_LENGTH;
    err = decode_appHandExiDocument(&stream, &handshake_req);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "handle_handshake error: decode_appHandExiDocument\n");
        return -1;
    }
    // === Validate handshake request ===
    err = -1;
    for (i = 0; i < handshake_req.supportedAppProtocolReq.AppProtocol.arrayLen ; i++) {
        str = handshake_req.supportedAppProtocolReq.AppProtocol.array[0].ProtocolNamespace.characters;
        strlen = handshake_req.supportedAppProtocolReq.AppProtocol.array[0].ProtocolNamespace.charactersLen;
        if (compare_exi_string_to_string(str, ISO_15118_MSG_DEF, strlen) == 0) {
            err = 0;
            break;
        }
    }
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "handle_handshake: no supported protocols found\n");
        return -1;
    }
    // === Create response EXI document ===
    init_appHandEXIDocument(&handshake_resp);
	handshake_resp.supportedAppProtocolRes_isUsed = 1u;
	handshake_resp.supportedAppProtocolRes.ResponseCode = appHandresponseCodeType_OK_SuccessfulNegotiation;
	handshake_resp.supportedAppProtocolRes.SchemaID = handshake_req.supportedAppProtocolReq.AppProtocol.array[i].SchemaID; /* signal the protocol by the provided schema id*/
	handshake_resp.supportedAppProtocolRes.SchemaID_isUsed = 1u;
	*stream.pos = V2GTP_HEADER_LENGTH;
	stream.capacity = 8; // as it should be for send
	err = encode_appHandExiDocument(&stream, &handshake_resp);
	if (err != 0) {
	    if (chattyv2g) fprintf(stderr, "handle_handshake: error encoding handshake response\n");
	    return -1;
	}
	// === Write response ===
	err = write_v2gtpHeader(buf, buffer_pos-V2GTP_HEADER_LENGTH, V2GTP_EXI_TYPE);
	if (err != 0) {
	    if (chattyv2g) fprintf(stderr, "handle_handshake: error writing response header\n");
        return -1;
	}
	err = combowriten(cconn, buf, (unsigned int)buffer_pos, tc);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "handle_handshake: sslwriten failed\n");
        return -1;
    }
    return 0;
}


// == Handle a V2GTP request
int secc_handle_request(comboconn_t *cconn, Chan *tc,
                        handle_func_t handle_func)
{
    uint8_t buf[BUFFER_SIZE];
    uint16_t payload_len;
    uint16_t buffer_pos = 0;
    bitstream_t stream = {
        .size = BUFFER_SIZE,
        .data = buf,
        .pos  = &buffer_pos,
        .buffer = 0,
        .capacity = 0, // Set to 8 for send and 0 for recv
    };
    int err;
    err = comboreadn(cconn, buf, V2GTP_HEADER_LENGTH, tc);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "secc_handle_request: sslreadn error\n");
        return -1;
    }
    err = read_v2gtpHeader(buf, &payload_len);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "secc_handle_request error: read_v2gtpHeader\n");
        return -1;
    }
    if ((size_t)payload_len + V2GTP_HEADER_LENGTH > BUFFER_SIZE) {
        if (chattyv2g) fprintf(stderr, "secc_handle_request error: Buffer too small for request\n");
        return -1;
    }
    err = comboreadn(cconn, buf + V2GTP_HEADER_LENGTH, payload_len, tc);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "secc_handle_request error: sslreadn\n");
        return -1;
    }
    struct v2gEXIDocument exi_in;
    struct v2gEXIDocument exi_out;
    err = deserializeStream2EXI(&stream, &exi_in);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "secc_handle_request: handle decoding error\n");
        return -1;
    }
    memset(&exi_out, 0, sizeof(exi_out));
    // === Call the user-defined handle function ===
    err = handle_func(&exi_in, &exi_out);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "secc_handle_request: external handle_func returned error\n");
        return -1;
    }
    stream.capacity = 8;
    err = serializeEXI2Stream(&exi_out, &stream);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "secc_handle_request: invalid response, unable to encode\n");
        return -1;
    }
    //=== Write response ===
    err = combowriten(cconn, buf, (unsigned int) *stream.pos, tc);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr,  "secc_handle_request: sslwriten failed\n");
        return -1;
    }
    if (chattyv2g) fprintf(stderr,  "Succesful request\n");
    return 0;
}

typedef struct {
    int sockfd;
    handle_func_t handle_func;
    const char *crt_path;
    const char *key_path;
} secc_listen_args_t;


// === Handle a single TCP connection ===
void secc_handle_tcp(void *vargs)
{
    secc_listen_args_t *args = (secc_listen_args_t*)vargs;
    handle_func_t handle_func = args->handle_func;
    int sockfd = args->sockfd;
    int err;
    Chan tc;
    comboconn_t cconn = {.tls_enabled = false,
                         .sockfd = sockfd};
    rendez(vargs, NULL);
    err = tchaninit(&tc);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "secc_handle_tcp: tchaninit error\n");
        goto exit;
    }
    tchanset(&tc, (uvlong)V2G_SECC_Sequence_Timeout * TIME_SECOND);
    err = handle_handshake(&cconn, &tc);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "secc_handle_tcp error: handle_handshake");
        goto exit;
    }
    for(;;) {
        tchanset(&tc, (uvlong)V2G_SECC_Sequence_Timeout * TIME_SECOND);
        err = secc_handle_request(&cconn, &tc, handle_func);
        if (err != 0) {
            break;
        }
    }
    exit:
    if (sockfd != -1) {
        shutdown(sockfd, 2);
        close(sockfd);
    }
    chanfree(&tc);
}

// === Handle a single TLS connection ===
void secc_handle_tls(void *arg)
{
    struct handletls_args_t *targs = arg;
    int err;
    const char *pers = "secc_ssl_server";
    ctr_drbg_context ctr_drbg;
    bool close_notify = false;
    Chan tc;
    int sockfd = targs->fd;
    struct tls_global_params_t *tlsp = targs->global;
    comboconn_t cconn = {.tls_enabled = true};
    rendez(arg, NULL);
    ssl_context *ssl = &cconn.ssl;
    //=====================================
    //      TLS connection setup
    //=====================================
    memset(ssl, 0, sizeof(ssl_context));
    memset(&ctr_drbg, 0, sizeof(ctr_drbg_context));
    // === Setup random number generator for tls ===
    err = ctr_drbg_init(&ctr_drbg, entropy_func, &tlsp->entropy,
                        (const unsigned char*)pers,
                        strlen(pers));
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "failed\n  ! ctr_drbg_init returned %d\n", err);
        goto exit;
    }
    // === Setup ssl connection ===
    if (chattyv2g) fprintf(stderr, "init ssl connection\n");
    err = ssl_init(ssl);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "failed\n  ! ssl_init returned %d\n\n", err);
        goto exit;
    }
    ssl_set_endpoint(ssl, SSL_IS_SERVER);
    if (IGNORE_SSL_CERTIFICATE_VALIDITY) {
        // DONT CHECK CERTS DUE TO TESTING!!
        ssl_set_authmode(ssl, SSL_VERIFY_NONE);
    } else {
        ssl_set_authmode(ssl, SSL_VERIFY_REQUIRED);
    }
    ssl_set_rng(ssl, ctr_drbg_random, &ctr_drbg);
    ssl_set_dbg(ssl, my_debug, stdout);
    ssl_set_bio(ssl, net_recv, &sockfd,
                      net_send, &sockfd);
    ssl_set_session_cache(ssl, ssl_cache_get, &tlsp->cache,
                          ssl_cache_set, &tlsp->cache);
    ssl_set_ca_chain(ssl, tlsp->srvcert.next, NULL, NULL);
    if ((err = ssl_set_own_cert(ssl, &tlsp->srvcert, &tlsp->pkey)) != 0) {
        if (chattyv2g) fprintf(stderr,  " failed\n  ! ssl_set_own_cert returned %d\n\n", err);
        goto exit;
    }

    ssl_set_ciphersuites(ssl, V2G_CIPHER_SUITES);
    // === Perform SSL handshake ===
    if (chattyv2g) fprintf(stderr, "starting ssl handshake\n");
    while ((err = ssl_handshake(ssl)) != 0) {
        if (err != POLARSSL_ERR_NET_WANT_READ &&
            err != POLARSSL_ERR_NET_WANT_WRITE) {
            if (chattyv2g) fprintf(stderr, "failed\n  ! ssl_handshake returned %d\n\n", err);
            goto exit;
        }
    }
    err = tchaninit(&tc);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "secc_handle_tls: tchaninit error\n");
        goto exit;
    }
    tchanset(&tc, (uvlong)V2G_SECC_Sequence_Timeout * TIME_SECOND);
    close_notify = true;
    err = handle_handshake(&cconn, &tc);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "secc_handle_tls error: handle_handshake");
        goto exit;
    }
    for(;;) {
        tchanset(&tc, (uvlong)V2G_SECC_Sequence_Timeout * TIME_SECOND);
        err = secc_handle_request(&cconn, &tc, tlsp->handle_func);
        if (err != 0) {
            break;
        }
    }
    // === Shutdown TLS connection ===
    exit:
    if (close_notify) {
        ssl_close_notify(ssl);
        chanfree(&tc); //when closenotify is set, chan is always init'd
    }
    if (sockfd != -1) {
        shutdown(sockfd, 2);
        close(sockfd);
    }
    ctr_drbg_free(&ctr_drbg);
    ssl_free(ssl);
    if (chattyv2g) fprintf(stderr, "closing connection to client\n");
}

typedef struct{
    int sockfd;
    handle_func_t handle_func;
} handletcp_args_t ;

void secc_listen_tcp_child(void *vargs)
{
    int err;
    secc_listen_args_t *args = (secc_listen_args_t*) vargs;
    int sockfd = args->sockfd;
    handletcp_args_t handle_args = {.handle_func = args->handle_func};
    rendez(vargs, NULL);
    for (;;) {
        struct sockaddr_in6 raddr;
        unsigned int raddr_len = sizeof(raddr);
        // === Wait for a connection ===
        handle_args.sockfd = accept(sockfd, (struct sockaddr*) &raddr, &raddr_len);
        if (handle_args.sockfd < 0) {
            if (chattyv2g) fprintf(stderr, "%s: %m\n", "accept");
            return;
        }
        if (chattyv2g) fprintf(stderr, "accepted connection\n");
        err = threadcreate(secc_handle_tcp, &handle_args, 1024 * 1024);
        if (err < 0) {
            if (chattyv2g) fprintf(stderr, "%s: %m\n", "threadcreate");
            abort();
        };
        rendez(&handle_args, NULL);
    }
}
// Listen for new connections
void secc_listen_tls_child(void *vargs)
{
    int err;
    secc_listen_args_t *listen_args = (secc_listen_args_t*) vargs;
    int sockfd = listen_args->sockfd;
    handle_func_t handle_func = listen_args->handle_func;
    struct handletls_args_t handle_args;
    struct tls_global_params_t *tlsp;
    tlsp = (struct tls_global_params_t*)malloc(sizeof(struct tls_global_params_t));
    if (tlsp == NULL) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "secc_listen_tls, malloc error");
        rendez(vargs, NULL);
        return;
    }
    // === Init ===
    tlsp->handle_func = handle_func;
    ssl_cache_init(&tlsp->cache);
    entropy_init(&tlsp->entropy);
    err = entropy_gather(&tlsp->entropy);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "secc_listen_tls, entropy gather error\n");
        rendez(vargs, NULL);
        return ;
    }
    x509_crt_init(&tlsp->srvcert);
    pk_init(&tlsp->pkey);
    // === Parse certificate and .key file ===
    err = x509_crt_parse_file(&tlsp->srvcert, listen_args->crt_path);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, " failed\n  !  x509_crt_parse returned %d\n\n", err);
        rendez(vargs, NULL);
        return ;
    }
    err = pk_parse_keyfile(&tlsp->pkey, listen_args->key_path, NULL);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, " failed\n  !  pk_parse_key returned %d\n\n", err);
        rendez(vargs, NULL);
        return ;
    }
    handle_args.global = tlsp;
    rendez(vargs, NULL);
    // === TLS listen loop ===
    if (chattyv2g) fprintf(stderr, "start TLS listen\n");
    for (;;) {
        struct sockaddr_in6 raddr;
        unsigned int raddr_len = sizeof(raddr);
        // === Wait for a connection ===
        handle_args.fd = accept(sockfd, (struct sockaddr*) &raddr, &raddr_len);
        if (handle_args.fd < 0) {
            if (chattyv2g) fprintf(stderr, "%s: %m\n", "accept");
            return ;
        }
        if (chattyv2g) fprintf(stderr, "accepted connection\n");
        err = threadcreate(secc_handle_tls, &handle_args, 1024 * 1024);
        if (err < 0) {
            if (chattyv2g) fprintf(stderr, "%s: %m\n", "threadcreate");
            abort();
        };
        rendez(&handle_args, NULL);

    }

}

void secc_listen_tcp(int sockfd,
                     handle_func_t handle_func) {
    secc_listen_args_t listen_args = {
        .sockfd = sockfd,
        .handle_func = handle_func,
    };
    threadcreate(secc_listen_tcp_child, &listen_args, 1024 * 1024);
    rendez(&listen_args, NULL);
}

void secc_listen_tls(int sockfd,
                     handle_func_t handle_func,
                     const char *crt_path, const char *key_path) {
    secc_listen_args_t listen_args = {
        .sockfd = sockfd,
        .handle_func = handle_func,
        .crt_path = crt_path,
        .key_path = key_path,
    };
    threadcreate(secc_listen_tls_child, &listen_args, 1024 * 1024);
    rendez(&listen_args, NULL);
}

//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
//======================================
//          Client (EV)
//======================================
//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

// Push a request to the pending request queue
void push_blocking_request(evcc_conn_t *conn,
                           blocking_request_t *breq)
{
    //if (chattyv2g) fprintf(stderr, "push request\n");
    if (conn->last_req == NULL) {
        conn->first_req = breq;
        conn->last_req = breq;
    } else {
        conn->last_req->next = breq;
    }
    //if (chattyv2g) fprintf(stderr, "done pushing request\n");
}

// Pop a request from the pending request queue
int pop_blocking_request (evcc_conn_t *conn,
                          blocking_request_t **breq)
{
    //if (chattyv2g) fprintf(stderr, "pop request\n");
    if (conn->first_req == NULL) {
        if (chattyv2g) fprintf(stderr, "pop_blocking_request error: no blocking requests");
        return -1;
    }
    *breq = conn->first_req;
    if ((*breq)->next == NULL) {
        conn->first_req = NULL;
        conn->last_req = NULL;
    } else {
        conn->first_req = (*breq)->next;
    }
    //if (chattyv2g) fprintf(stderr, "done popping request\n");
    return 0;
}

void evcc_close_conn (evcc_conn_t *conn)
{
    int kill_sig = 0;
    chansendnb(&conn->kill_chan, &kill_sig);
    qlock(&conn->mutex);
    conn->alive = false;
    qunlock(&conn->mutex);
    chanrecv(&conn->kill_confirm_chan, NULL);
    chanfree(&conn->kill_chan);
    chanfree(&conn->kill_confirm_chan);
    x509_crt_free(&conn->cacert);
    pk_free(&conn->pkey);
    ssl_free(&conn->cconn.ssl);
    ctr_drbg_free(&conn->ctr_drbg);
    entropy_free(&conn->entropy);
    shutdown(conn->cconn.sockfd, 2);
    close(conn->cconn.sockfd);
}

// Commit a raw (byte) request to a tls connection
ssize_t v2g_raw_request(evcc_conn_t *conn, byte *buffer,
                        size_t request_len, size_t buffer_len, uvlong timeout_ns)
{
    ssize_t err;
    ssize_t response_len = -1;
    Chan tc;
    Alt alts[3];
    err = tchaninit(&tc);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "v2g_raw_request: tchaninit error\n");
        return -1;
    }
    tchanset(&tc, timeout_ns);
    qlock(&conn->mutex);
    if (!conn->alive) {
        if (chattyv2g) fprintf(stderr, "v2g_raw_request: cannot send request, connection dead\n");
        conn->alive = false;
        qunlock(&conn->mutex);
        evcc_close_conn(conn);
        chanfree(&tc);
        return -1;
    }
    err = combowriten(&conn->cconn, buffer, request_len, &tc);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "v2g_raw_request: sslwriten\n");
        conn->alive = false;
        qunlock(&conn->mutex);
        evcc_close_conn(conn);
        chanfree(&tc);
        return -1;
    }
	blocking_request_t breq = {
		.buffer = buffer,
		.buffer_len = buffer_len,
		.next = NULL,
	};
	chaninit(&breq.wake_chan, sizeof(ssize_t), 1);
	push_blocking_request(conn, &breq);
    qunlock(&conn->mutex);
    alts[0].c = &breq.wake_chan;
    alts[0].v = &response_len;
    alts[0].op = CHANRECV;
    alts[1].c = &tc;
    alts[1].v = NULL;
    alts[1].op = CHANRECV;
    alts[2].op = CHANEND;
    switch (alt(alts)) {
        case 0:
            break;
        case 1:
            if (chattyv2g) fprintf(stderr, "v2g_raw_request: timeout\n");
            evcc_close_conn(conn);
            // Wait until stream_reader is done to avoid race conditions
            chanrecv(&breq.wake_chan, &err);
            //response_len = -1;
            break;
        default:
            if (chattyv2g) fprintf(stderr, "critical error at v2g_raw_request: alt error\n");
            abort();
    }
    chanfree(&breq.wake_chan);
    chanfree(&tc);
    return response_len;
}

// Create a handshake request (exchanging app protocol versions)
int v2g_handshake_request(evcc_conn_t *conn)
{
	int err;
	ssize_t len;
    uint8_t buffer[BUFFER_SIZE];
	uint16_t buffer_pos = V2GTP_HEADER_LENGTH;
    bitstream_t stream = {
        .size = BUFFER_SIZE,
        .data = buffer,
        .pos  = &buffer_pos,
        .buffer = 0,
        .capacity = 8, // Set to 8 for send and 0 for in
    };
    const char *ns0 = ISO_15118_MSG_DEF;
    // the DIN addition (add later?)
	//char *ns1 = "urn:din:70121:2012:MsgDef";
    struct appHandEXIDocument handshake;
	struct appHandEXIDocument handshake_resp;
    init_appHandEXIDocument(&handshake);
    handshake.supportedAppProtocolReq_isUsed = 1u;
	handshake.supportedAppProtocolReq.AppProtocol.arrayLen = 1;
	// Set the protocols:
	handshake.supportedAppProtocolReq.AppProtocol.array[0].ProtocolNamespace.charactersLen =
			writeStringToEXIString(ns0, handshake.supportedAppProtocolReq.AppProtocol.array[0].ProtocolNamespace.characters);
	handshake.supportedAppProtocolReq.AppProtocol.array[0].SchemaID = 1;
	handshake.supportedAppProtocolReq.AppProtocol.array[0].VersionNumberMajor = 1;
	handshake.supportedAppProtocolReq.AppProtocol.array[0].VersionNumberMinor = 0;
	handshake.supportedAppProtocolReq.AppProtocol.array[0].Priority = 1;
	// Implement DIN support?


    if ((err = encode_appHandExiDocument(&stream, &handshake)) == 0) {
        if (chattyv2g) fprintf(stderr, "====================\n");
		if (write_v2gtpHeader(stream.data, buffer_pos-V2GTP_HEADER_LENGTH, V2GTP_EXI_TYPE) == 0) {
			if (chattyv2g) fprintf(stderr, "EV side: send message to the EVSE\n");
		}
	}
	// === Commit request ===
	if (chattyv2g) fprintf(stderr, "raw handshake request\n");

    len = v2g_raw_request(conn, buffer, buffer_pos, BUFFER_SIZE,
                          V2G_EVCC_Msg_Timeout_SupportedAppProtocolReq * TIME_SECOND);
    if (len <= 0) {
        if (chattyv2g) fprintf(stderr, "v2g_handshake_request error: v2g_raw request\n");
        return -1;
    }
    // === Handle response ===
    if (chattyv2g) fprintf(stderr, "done with raw handhake request\n");
    buffer_pos = 0;
    uint16_t payload_len;
    err = read_v2gtpHeader(stream.data, &payload_len);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "v2g_handshake_request error: read_v2gtpHeader\n");
        return -1;
    }
	buffer_pos = V2GTP_HEADER_LENGTH;
    err = decode_appHandExiDocument(&stream, &handshake_resp);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "v2g_handshake_request error: decode_appHandExiDocument\n");
        return -1;
    }
		if (chattyv2g) fprintf(stderr, "EV side: Response of the EVSE \n");
	if (handshake_resp.supportedAppProtocolRes.ResponseCode
	    != appHandresponseCodeType_OK_SuccessfulNegotiation) {
	    if (chattyv2g) fprintf(stderr, "\t\tResponseCode=ERROR_UnsuccessfulNegotiation\n");
        return -1;
	}
	if (chattyv2g) fprintf(stderr, "\t\tResponseCode=OK_SuccessfulNegotiation\n");
	if (chattyv2g) fprintf(stderr,  "\t\tSchemaID=%d\n",
		        handshake_resp.supportedAppProtocolRes.SchemaID);
	return 0;
}

// Create a v2g request to the EVSE
int v2g_request(evcc_conn_t *conn, struct v2gEXIDocument *exiIn,
                struct v2gEXIDocument *exiOut) {
//struct v2gEXIDocument *exiOut) {
	int err;
	ssize_t len;
    uint8_t buffer[BUFFER_SIZE];
	uint16_t buffer_pos = V2GTP_HEADER_LENGTH;
    bitstream_t stream = {
        .size = BUFFER_SIZE,
        .data = buffer,
        .pos  = &buffer_pos,
        .buffer = 0,
        .capacity = 8, // Set to 8 for send and 0 for in
    };
    uvlong req_timeout = get_req_timeout(exiIn);
	// === EV side ===
	err = serializeEXI2Stream(exiIn, &stream);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "v2g_request error: serializeEXI2Stream\n");
	    return -1;
	}
    len = v2g_raw_request(conn, buffer, buffer_pos, BUFFER_SIZE, req_timeout);
    if (len <= 0) {
        if (chattyv2g) fprintf(stderr, "v2g_request error: v2g_raw_request\n");
        return -1;
    }
    buffer_pos = 0;
    err = deserializeStream2EXI(&stream, exiOut);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "v2g_request error: deserializeStream2EXI\n");
        return -1;
    }
   // if (chattyv2g) fprintf(stderr, "succesful v2g_request\n");
    return 0;
}

// Read responses from requests to EVSE and deliver them to requester
static void evcc_connect_stream_reader(void *arg)
{
	ssize_t err, len;
    evcc_conn_t *conn = arg;
	blocking_request_t  *breq;
	byte header_buf[V2GTP_HEADER_LENGTH];
    for(;;) {
        uint16_t payload_len;
        err = (ssize_t)comboreadn(&conn->cconn, header_buf,
                         V2GTP_HEADER_LENGTH, &conn->kill_chan);
        if (err < 0) {
            if (chattyv2g) fprintf(stderr,  "evcc_connect_tls_stream_reader error: sslreadn error\n");
            break;
        }
        // === Check header for response size ===
        err = (ssize_t)read_v2gtpHeader(header_buf, &payload_len);
        if (err != 0) {
            if (chattyv2g) fprintf(stderr, "evcc_connect_tls_stream_reader error: invalid v2gtp header\n");
            break;
        }
        qlock(&conn->mutex);
        // === pop the first request of the queue ===
        err = (ssize_t)pop_blocking_request(conn, &breq);
		if (err != 0) {
		    qunlock(&conn->mutex);
            if (chattyv2g) fprintf(stderr, "evcc_connect_tls_stream_reader: pop_blocking_request error\n");
            break;
        }
        qunlock(&conn->mutex);
        if ((size_t)payload_len + V2GTP_HEADER_LENGTH > breq->buffer_len) {
            err = -1;
            chansend(&breq->wake_chan, &err);
            if (chattyv2g) fprintf(stderr, "evcc_connect_tls_stream_reader error: Buffer too small for request\n");
            break;
        }
        err = (ssize_t)comboreadn(&conn->cconn, breq->buffer + V2GTP_HEADER_LENGTH,
                         payload_len, &conn->kill_chan);
        if (err != 0) {
            chansend(&breq->wake_chan, &err);
            if (chattyv2g) fprintf(stderr, "evcc_connect_tls_stream_reader error: sslreadn\n");
            break;
        }
        memcpy(breq->buffer, header_buf, V2GTP_HEADER_LENGTH);
        len = V2GTP_HEADER_LENGTH + (ssize_t)payload_len;
        chansend(&breq->wake_chan, &len);
    }
    if (chattyv2g) fprintf(stderr, "disconnected\n");
    qlock(&conn->mutex);
    conn->alive = false;
    err = -1;
    for (breq = conn->first_req; breq != NULL; breq = breq->next) {
        chansend(&breq->wake_chan, &err);
    }
    qunlock(&conn->mutex);
    // === Free connection ===
    chansend(&conn->kill_confirm_chan, NULL);
}

int init_evcc_conn(evcc_conn_t *conn, bool tls_enabled) {
    conn->first_req = NULL;
    conn->last_req = NULL;
    conn->cconn.sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    conn->cconn.tls_enabled = tls_enabled;
    if (conn->cconn.sockfd < 0) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "socket");
        return -1;
    }
    return 0;
}

// Connect to an EVSE

int evcc_connect_tcp (evcc_conn_t *conn)
{
    int err = 0;
    err = init_evcc_conn(conn, false);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "evcc_connect_tcp: init_evcc_conn\n");
        return -1;
    }
    // === Init ===
    chaninit(&conn->kill_chan, sizeof(int), 1);
    chaninit(&conn->kill_confirm_chan, sizeof(int), 1);
    err = connect (conn->cconn.sockfd, (struct sockaddr*)&conn->addr,
                   sizeof (struct sockaddr_in6));
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "evcc_connect_tcp connect: %m\n");
        goto exit;
    }
	conn->alive = true;
    memset(&conn->mutex, 0, sizeof(conn->mutex));
    err = threadcreate(evcc_connect_stream_reader, conn, 1024 * 1024);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "evcc_connect_tcp: threadcreate error");
        goto exit;
    }
    err = v2g_handshake_request(conn);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "v2g handshake error\n");
        goto exit; // stuff is freed in stream reader
    }
    if (chattyv2g) fprintf(stderr, "v2g handshake succesful\n");
    return 0;
    // === Only ends here if an error has happened ===
    exit:
    shutdown(conn->cconn.sockfd, 2);
    close(conn->cconn.sockfd);
    return -1;
}

int evcc_connect_tls(evcc_conn_t *conn,
                     const char *crt_path, const char *key_path)
{
    int err = 0;
    const char *pers = "secc_ssl_client";
    err = init_evcc_conn(conn, true);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "evcc_connect_tls: init_evcc_conn\n");
        return -1;
    }
    // === Init ===
    chaninit(&conn->kill_chan, sizeof(int), 1);

    // === Setup entropy ===
    entropy_init(&conn->entropy);
    x509_crt_init(&conn->cacert);
    pk_init(&conn->pkey);
    memset(&conn->ctr_drbg, 0, sizeof(ctr_drbg_context));
    // === Setup random number generator for tls ===
    err = ctr_drbg_init(&conn->ctr_drbg, entropy_func, &conn->entropy,
                        (const unsigned char *) pers,
                        strlen(pers));
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "ctr_drbg_init error\n");
        goto exit;
    }
    // === Parse certificate and .key file ===
    err = x509_crt_parse_file(&conn->cacert, crt_path);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr,  " evcc_connect_tls: x509_crt_parse returned %d\n\n", err);
        goto exit;
    }
    err = pk_parse_keyfile(&conn->pkey, key_path, NULL);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "evcc_connect_tls: pk_parse_key returned %d\n\n", err);
        goto exit;
    }
    err = connect(conn->cconn.sockfd, (struct sockaddr*)&conn->addr,
                  sizeof(struct sockaddr_in6));
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "evcc_connect_tls connect: %m\n");
        goto exit;
    }
    // === init ssl ==
    memset(&conn->cconn.ssl, 0, sizeof(ssl_context));
    ssl_init(&conn->cconn.ssl);
    ssl_set_endpoint(&conn->cconn.ssl, SSL_IS_CLIENT);
    // OPTIONAL is not optimal for security,
    // but makes interop easier in this simplified example
    if (IGNORE_SSL_CERTIFICATE_VALIDITY) {
        // DONT CHECK CERTS DUE TO TESTING!!
        ssl_set_authmode(&conn->cconn.ssl, SSL_VERIFY_OPTIONAL);
    } else {
        ssl_set_authmode(&conn->cconn.ssl, SSL_VERIFY_REQUIRED);
    }
    ssl_set_ciphersuites(&conn->cconn.ssl, V2G_CIPHER_SUITES);
    ssl_set_ca_chain(&conn->cconn.ssl, &conn->cacert, NULL, "EVCC (client)");
    err = ssl_set_own_cert(&conn->cconn.ssl, &conn->cacert, &conn->pkey);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr,  "evcc_connect_tls: ssl_set_own_cert returned %d\n\n", err);
        goto exit;
    }
    ssl_set_rng(&conn->cconn.ssl, ctr_drbg_random, &conn->ctr_drbg);
    ssl_set_dbg(&conn->cconn.ssl, my_debug, stdout);
    ssl_set_bio(&conn->cconn.ssl, net_recv, &conn->cconn.sockfd,
                net_send, &conn->cconn.sockfd);
    // === Perform SSL handshake ===
    while ((err = ssl_handshake(&conn->cconn.ssl)) != 0) {
        if (err != POLARSSL_ERR_NET_WANT_READ && err != POLARSSL_ERR_NET_WANT_WRITE)
        {
            if (chattyv2g) fprintf(stderr,  "evcc_connect_tls: ssl_handshake returned -0x%x\n\n", err);
            goto exit;
        }
    }
    // === Check certificate validity ===
    if ((err = ssl_get_verify_result(&conn->cconn.ssl)) != 0) {
        if (chattyv2g) fprintf(stderr,  "evcc_connect_tls failed\n");

        if ((err & BADCERT_EXPIRED) != 0) {
            if (chattyv2g) fprintf(stderr,  "  ! server certificate has expired\n");
        }
        if ((err & BADCERT_REVOKED) != 0) {
            if (chattyv2g) fprintf(stderr,  "  ! server certificate has been revoked\n");
        }
        if ((err & BADCERT_CN_MISMATCH) != 0) {
            if (chattyv2g) fprintf(stderr,  "  ! CN mismatch (expected CN=%s)\n", "PolarSSL Server 1");
        }
        if ((err & BADCERT_NOT_TRUSTED) != 0) {
            if (chattyv2g) fprintf(stderr,  "  ! self-signed or not signed by a trusted CA\n");
        }
        if (chattyv2g) fprintf(stderr,  "\n");
    } else {
        if (chattyv2g) fprintf(stderr,  " ok\n");
    }
	conn->alive = true;
	    if (chattyv2g) fprintf(stderr, "init mutex\n");
    memset(&conn->mutex, 0, sizeof(conn->mutex));
    err = threadcreate(evcc_connect_stream_reader, conn, 1024 * 1024);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "threadcreate error");
        goto exit;
    }
    err = v2g_handshake_request(conn);
    if (err != 0) {
        if (chattyv2g) fprintf(stderr, "v2g handshake error\n");
        goto exit; // stuff is freed in stream reader
    }
    if (chattyv2g) fprintf(stderr, "TLS handshake succesful\n");
    return 0;
    // === Only ends here if an error has happened ===
    exit:
    x509_crt_free(&conn->cacert);
    ssl_free(&conn->cconn.ssl);
    ctr_drbg_free(&conn->ctr_drbg);
    entropy_free(&conn->entropy);
    shutdown(conn->cconn.sockfd, 2);
    close(conn->cconn.sockfd);
    return -1;
}
