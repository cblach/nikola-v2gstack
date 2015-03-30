
#include "v2gstack.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include "polarssl/ssl_cache.h"

#include "appHandEXIDatatypes.h"
#include "appHandEXIDatatypesEncoder.h"
#include "appHandEXIDatatypesDecoder.h"
/*
#if DEPLOY_DIN_CODEC == SUPPORT_YES
#include "dinEXIDatatypes.h"
#include "dinEXIDatatypesEncoder.h"
#include "dinEXIDatatypesDecoder.h"
#endif // DEPLOY_DIN_CODEC == SUPPORT_YES
*/
#include "v2gEXIDatatypesEncoder.h"
#include "v2gEXIDatatypesDecoder.h"

#include "v2gtp.h"

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
#define TIME_MILLISECOND ( TIME_MICROSECOND * 1000 )
#define TIME_SECOND ( TIME_MILLISECOND * 1000 )

#define BUFFER_SIZE 4096
#define MAX_CLIENT_REQUEST_QUEUE_LEN 100
#define ISO_15118_MSG_DEF "urn:iso:15118:2:2010:MsgDef"
//===================================
//             Typdefs
//===================================
typedef uint8_t byte;
typedef unsigned long long uvlong;
struct ev_blocking_request_t{
    Chan wake_chan;
    byte* buffer; // Used both for request & response
    size_t buffer_len; // size of the underlying buffer
    struct ev_blocking_request_t* next;
};

typedef struct{
    ssl_context* ssl;
    byte* buffer;
    unsigned int n;
} ssln_arg;


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

void print_byte_array( byte* arr, size_t n )
{
    int i;
    printf("[");
    // Highly ineffictive but whatever it's TESTING!! :D
    for( i = 0; i < n; i++) {
        printf( " %02x", arr[i] );
    }
    printf(" ]\n");
}

void print_ssl_read_err( int err)
{
    switch (err) {
        case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
            printf( "connection was closed gracefully\n");
            return;
        case POLARSSL_ERR_NET_CONN_RESET:
            printf( "connection was reset by peer\n");
            return;
        case POLARSSL_ERR_NET_WANT_READ:
        case POLARSSL_ERR_NET_WANT_WRITE:
            printf("ssl socket error; want read/want write\n");
            return;
        case 0:
            printf("EOF\n");
            return;
        default:
            printf( "ssl_read returned -0x%04x\n", -err );
            return;
    }
}

//======================================
//            SSL IO functions
//======================================

static ssize_t iocall_sslreadn( void* args, atomic_int *cancel )
{
    ssln_arg* sargs = args;
    int bytes_read = 0;
    int tries = 0;
    int ret;
    while (bytes_read < sargs->n && atomic_load(cancel) == 0) {
        ret = ssl_read(sargs->ssl, sargs->buffer + bytes_read,
                       sargs->n - bytes_read);
        if( ret == POLARSSL_ERR_NET_WANT_READ ||
            ret == POLARSSL_ERR_NET_WANT_WRITE ) {
            if (tries > 30) {
                printf("sslreadn: Too many socket read errors\n");
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

static ssize_t iocall_sslwriten( void* args, atomic_int *cancel )
{
    ssln_arg* sargs = args;
    int bytes_written = 0;
    int ret;
    while (bytes_written < sargs->n && atomic_load(cancel) == 0) {
        ret = ssl_write(sargs->ssl, sargs->buffer + bytes_written,
                        sargs->n - bytes_written);
        if (ret < 1) {
            print_ssl_read_err(ret);
            return -1;
        }
        bytes_written += ret;
    }
    return 0;
}

static int sslreadn( ssl_context *ssl, byte* buffer,
                       unsigned int n, Chan* tc ) {
    Alt alts[3];
    ssln_arg args = {
        .ssl = ssl,
        .buffer = buffer,
        .n = n,
    };
    ssize_t ret;
    int err;
    Chan *ioc = iochan(1048576 - PTHREAD_STACK_MIN);
    if (ioc == NULL) {
        printf("sslreadn error: iochan error\n");
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
            printf("sslreadn error: timeout\n");
            err = -1;
            break;
        default:
            printf("critical sslreadn: alt error\n");
            abort();
    }
    chanfree(ioc);
    return err;
}

static int sslwriten( ssl_context *ssl, byte* buffer,
                               unsigned int n, Chan* tc ){
    Alt alts[3];
    ssln_arg args = {
        .ssl = ssl,
        .buffer = buffer,
        .n = n,
    };
    ssize_t ret;
    int err;
    Chan *ioc = iochan(1048576 - PTHREAD_STACK_MIN);
    if (ioc == NULL) {
        printf("sslwriten error: iochan error\n");
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
            printf("sslwriten error: timeout\n");
            err = -1;
            break;
        default:
            printf("critical sslwriten: alt error\n");
            abort();
    }
    chanfree(ioc);
    return err;
}

uint16_t get_secc_port()
{
    // No mutexes are used since it's assumed
    // secc_listen_tls is only started once:
    // i.e. in program init
    return SECC_Port;
}

void my_debug( void *ctx, int level, const char *str )
{
    ((void)level);
    fprintf( (FILE *) ctx, "%s", str );
    fflush(  (FILE *) ctx  );
}

//======================================
//          EXI functions
//======================================

static int serializeEXI2Stream(struct v2gEXIDocument* exiIn, bitstream_t* stream)
{
	int errn;
	*stream->pos = V2GTP_HEADER_LENGTH;  /* v2gtp header */
	if( (errn = encode_v2gExiDocument(stream, exiIn)) == 0) {
		errn = write_v2gtpHeader(stream->data, (*stream->pos)-V2GTP_HEADER_LENGTH, V2GTP_EXI_TYPE);
	}
	return errn;
}


/* deserializes V2G TP header and decodes right away EXI stream */
static int deserializeStream2EXI(bitstream_t* streamIn, struct v2gEXIDocument* exi)
{
	int errn;
	uint16_t payloadLength;

	*streamIn->pos = 0;
	if ( (errn = read_v2gtpHeader(streamIn->data, &payloadLength)) == 0) {
		*streamIn->pos += V2GTP_HEADER_LENGTH;

		errn = decode_v2gExiDocument(streamIn, exi);
	}
	return errn;
}

static int writeStringToEXIString(char* string, exi_string_character_t* exiString)
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
static int compare_exi_string_to_string( exi_string_character_t* existring, char* string, int n )
{
	int pos = 0;
	while ( string[pos]!='\0' && pos < n ) {
	    if ( (exi_string_character_t)string[pos] != existring[pos] ) {
            break;
	    }
	    if ( pos == n - 1 ) {
	        return 0;
	    }
	    pos++;
	}
	return -1;
}

uvlong get_req_timeout(struct v2gEXIDocument* exiIn ){
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
	    printf("get_req_timeout: unknown request, using default timeout\n");
	    return (uvlong)V2G_EVCC_Msg_Timeout_Default * TIME_SECOND;
	}
}

//**************************************
//======================================
//      Server ( EVSE )
//======================================
//**************************************

struct tls_global_params_t{
    x509_crt srvcert;
    pk_context pkey;
    entropy_context entropy;
    ssl_cache_context cache;
    int ( *handle_func )( struct v2gEXIDocument*,
                           struct v2gEXIDocument*);
};
struct handletls_args_t{
    int fd;
    struct tls_global_params_t* global;
};

// Bind the TLS listener to a dynamic port
int bind_tls(uint16_t* port)
{
    int err;
    struct sockaddr_in6 bound_laddr;
    unsigned int bound_laddr_len = sizeof( bound_laddr);
    struct sockaddr_in6 laddr = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(0), // dynamic port
    };
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if( sock < 0 ) {
        perror("socket");
        return -1;
    }
    memcpy( laddr.sin6_addr.s6_addr, SECC_LOCALHOST_ADDR, 16 );
    if( listen( sock, 127 ) < 0 ) {
        close( sock );
        perror("listen");
        return -1;
    }
    // === Set the dynamic port number if called with pointer ===
    if( port != NULL) {
        err = getsockname( sock, (struct sockaddr*) &bound_laddr, &bound_laddr_len );
        if( err < 0 ) {
            close( sock );
            perror("getsockname");
            return -1;
        }
        *port = ntohs( bound_laddr.sin6_port );
    }
    return sock;
}

// Handle v2g handshake ( exchange of supported app protocols)
int handle_handshake( ssl_context* ssl, Chan* tc )
{
    int err, i, strlen;
    exi_string_character_t* str;
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
    err = sslreadn(ssl, buf, V2GTP_HEADER_LENGTH, tc);
    if (err != 0){
        printf("handle_handshake: sslreadn error\n");
        return -1;
    }
    err = read_v2gtpHeader(buf, &payload_len);
    if (err != 0) {
        printf("handle_handshake: invalid v2gtp header\n");
        return -1;
    }
    if (payload_len + V2GTP_HEADER_LENGTH > BUFFER_SIZE) {
        printf("Buffer too small for request\n");
        return -1;
    }
    // === Read handshake request ===
    err = sslreadn(ssl, buf + V2GTP_HEADER_LENGTH, payload_len, tc);
    if  (err != 0) {
        printf("handle_handshake: sslreadn error\n");
        return -1;
    }
    buffer_pos = V2GTP_HEADER_LENGTH;
    err = decode_appHandExiDocument(&stream, &handshake_req);
    if (err != 0) {
        printf("handle_handshake error: decode_appHandExiDocument\n");
        return -1;
    }
    // === Validate handshake request ===
    err = -1;
    for (i = 0; i < handshake_req.supportedAppProtocolReq.AppProtocol.arrayLen ; i++) {
        str = handshake_req.supportedAppProtocolReq.AppProtocol.array[0].ProtocolNamespace.characters;
        strlen = handshake_req.supportedAppProtocolReq.AppProtocol.array[0].ProtocolNamespace.charactersLen;
        if (compare_exi_string_to_string( str, ISO_15118_MSG_DEF, strlen) == 0) {
            err = 0;
            break;
        }
    }
    if (err != 0) {
        printf("handle_handshake: no supported protocols found\n");
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
	    printf("handle_handshake: error encoding handshake response\n");
	    return -1;
	}
	// === Write response ===
	err = write_v2gtpHeader(buf, buffer_pos-V2GTP_HEADER_LENGTH, V2GTP_EXI_TYPE);
	if (err != 0) {
	    printf("handle_handshake: error writing response header\n");
        return -1;
	}
	err = sslwriten(ssl, buf, (unsigned int)buffer_pos, tc);
    if (err != 0) {
        printf("handle_handshake: sslwriten failed\n");
        return -1;
    }
    return 0;
}

// === Handle a single TLS connection ===
void secc_handle_tls( void* arg )
{
    struct handletls_args_t* targs = arg;
    int err;
    unsigned char buf[1024];
    const char *pers = "secc_ssl_server";
    ssl_context ssl;
    ctr_drbg_context ctr_drbg;
    bool close_notify = false;
    Chan tc;
    int sockfd = targs->fd;
    struct tls_global_params_t* tlsp = targs->global;
    rendez(arg, NULL);
    //=====================================
    //      TLS connection setup
    //=====================================
    memset(&ssl, 0, sizeof(ssl_context));
    memset(&ctr_drbg, 0, sizeof(ctr_drbg_context));
    // === Setup random number generator for tls ===
    err = ctr_drbg_init(&ctr_drbg, entropy_func, &tlsp->entropy,
                        (const unsigned char *)pers,
                        strlen( pers ));
    if (err != 0) {
        printf("failed\n  ! ctr_drbg_init returned %d\n", err );
        goto exit;
    }
    // === Setup ssl connection ===
    printf("init ssl connection\n");
    err = ssl_init(&ssl);
    if( err != 0 ) {
        printf("failed\n  ! ssl_init returned %d\n\n", err );
        goto exit;
    }
    ssl_set_endpoint(&ssl, SSL_IS_SERVER);
    if (IGNORE_SSL_CERTIFICATE_VALIDITY) {
        // DONT CHECK CERTS DUE TO TESTING!!
        ssl_set_authmode(&ssl, SSL_VERIFY_NONE);
    } else {
        ssl_set_authmode(&ssl, SSL_VERIFY_REQUIRED);
    }
    ssl_set_rng(&ssl, ctr_drbg_random, &ctr_drbg);
    ssl_set_dbg(&ssl, my_debug, stdout);
    ssl_set_bio(&ssl, net_recv, &sockfd,
                      net_send, &sockfd);
    ssl_set_session_cache( &ssl, ssl_cache_get, &tlsp->cache,
                           ssl_cache_set, &tlsp->cache );
    ssl_set_ca_chain(&ssl, tlsp->srvcert.next, NULL, NULL);
    if ((err = ssl_set_own_cert(&ssl, &tlsp->srvcert, &tlsp->pkey)) != 0) {
        printf( " failed\n  ! ssl_set_own_cert returned %d\n\n", err );
        goto exit;
    }

    ssl_set_ciphersuites(&ssl, V2G_CIPHER_SUITES);
    // === Perform SSL handshake ===
    printf("starting ssl handshake\n");
    while ((err = ssl_handshake(&ssl)) != 0) {
        if (err != POLARSSL_ERR_NET_WANT_READ &&
            err != POLARSSL_ERR_NET_WANT_WRITE) {
            printf("failed\n  ! ssl_handshake returned %d\n\n", err );
            goto exit;
        }
    }
    err = tchaninit(&tc);
    if (err != 0) {
        printf("secc_handle_tls: tchaninit error\n");
        goto exit;
    }
    tchanset(&tc, (uvlong)V2G_SECC_Sequence_Timeout * TIME_SECOND);
    close_notify = true;
    err = handle_handshake( &ssl, &tc );
    if (err != 0) {
        printf("secc_handle_tls error: handle_handshake");
        goto exit;
    }
    for(;;) {
        // === Handle request ===
        uint16_t payload_len;
        tchanset(&tc, (uvlong)V2G_SECC_Sequence_Timeout * TIME_SECOND);
        err = sslreadn(&ssl, buf, V2GTP_HEADER_LENGTH, &tc);
        if (err != 0) {
            printf("secc_handle_tls: sslreadn error\n");
            goto exit;
        }
        err = read_v2gtpHeader( buf, &payload_len);
        if (err != 0) {
            printf("secc_handle_tls error: read_v2gtpHeader\n");
            goto exit;
        }
        if (payload_len + V2GTP_HEADER_LENGTH > BUFFER_SIZE) {
            printf("secc_handle_tls error: Buffer too small for request\n");
            goto exit;
        }
        err = sslreadn(&ssl, buf + V2GTP_HEADER_LENGTH, payload_len, &tc);
        if (err != 0) {
            printf("secc_handle_tls error: sslreadn\n");
            goto exit;
        }
        uint16_t buffer_pos = 0;
        bitstream_t stream = {
            .size = BUFFER_SIZE,
            .data = buf,
            .pos  = &buffer_pos,
            .buffer = 0,
            .capacity = 0, // Set to 8 for send and 0 for recv
        };
        struct v2gEXIDocument exi_in;
        struct v2gEXIDocument exi_out;
        err = deserializeStream2EXI(&stream, &exi_in);
        if (err != 0) {
            printf("secc_handle_tls: handle decoding error\n");
            goto exit;
        }
        // === Call the user-defined handle function ===
        err = tlsp->handle_func( &exi_in, &exi_out );
        if (err != 0) {
            printf("secc_handle_tls: external handle_func returned error\n");
            goto exit;
        }
        stream.capacity = 8;
        err = serializeEXI2Stream(&exi_out, &stream);
        if (err != 0) {
            printf("secc_handle_tls: invalid response, unable to encode\n");
            goto exit;
        }
        //=== Write response ===
        err = sslwriten(&ssl, buf, (unsigned int) *stream.pos, &tc);
        if (err != 0) {
            printf( "secc_handle_tls: sslwriten failed\n");
            goto exit;
        }
        printf( "Succesful request\n");
    }
    // === Shutdown TLS connection ===
    exit:
    if (close_notify) {
        ssl_close_notify(&ssl);
        chanfree(&tc); //when closenotify is set, chan is always init'd
    }
    if (sockfd != -1) {
        shutdown(sockfd, 2);
        close(sockfd);
    }
    ctr_drbg_free(&ctr_drbg);
    ssl_free(&ssl);
    printf("closing connection to client\n");
}

// Listen for new connections
int secc_listen_tls(int sockfd,
                    int ( *handle_func )( struct v2gEXIDocument*,
                                          struct v2gEXIDocument* ))
{
    int err;
    struct handletls_args_t args;
    struct tls_global_params_t* tlsp = (struct tls_global_params_t*)malloc(sizeof(struct tls_global_params_t));
    if (tlsp == NULL) {
        perror("secc_listen_tls, malloc error\n");
        return -1;
    }
    // === Init ===
    tlsp->handle_func = handle_func;
    ssl_cache_init(&tlsp->cache);
    entropy_init(&tlsp->entropy);
    err = entropy_gather(&tlsp->entropy);
    if (err != 0) {
        printf("secc_listen_tls, entropy gather error\n");
        return -1;
    }
    x509_crt_init(&tlsp->srvcert);
    pk_init(&tlsp->pkey);
    // === Parse certificate and .key file ===
    err = x509_crt_parse_file(&tlsp->srvcert, "certs/evse.crt");
    if (err != 0) {
        printf(" failed\n  !  x509_crt_parse returned %d\n\n", err);
        return -1;
    }
    err = pk_parse_keyfile( &tlsp->pkey, "certs/evse.key", NULL);
    if (err != 0) {
        printf(" failed\n  !  pk_parse_key returned %d\n\n", err);
        return -1;
    }
    args.global = tlsp;
    // === TLS listen loop ===
    printf("start TLS listen\n");
    for (;;) {
        struct sockaddr_in6 raddr;
        unsigned int raddr_len = sizeof( raddr);
        // === Wait for a connection ===
        args.fd = accept(sockfd, (struct sockaddr*) &raddr, &raddr_len);
        if (args.fd < 0) {
            perror("accept");
            return -1;
        }
        printf("accepted connection\n");
        err = threadcreate(secc_handle_tls, &args, 1024 * 1024);
        if (err < 0) {
            perror("threadcreate");
            abort();
        };
        rendez(&args, NULL);

    }

}

//**************************************
//======================================
//          Client ( EV )
//======================================
//**************************************

// Push a request to the pending request queue
void push_blocking_request( struct ev_tls_conn_t* conn, struct ev_blocking_request_t* breq )
{
    //printf("push request\n");
    if( conn->last_req == NULL ) {
        conn->first_req = breq;
        conn->last_req = breq;
    } else {
        conn->last_req->next = breq;
    }
    //printf("done pushing request\n");
}

// Pop a request from the pending request queue
int pop_blocking_request( struct ev_tls_conn_t* conn, struct ev_blocking_request_t** breq )
{
    //printf("pop request\n");
    if( conn->first_req == NULL ) {
        printf("pop_blocking_request error: no blocking requests");
        return -1;
    }
    *breq = conn->first_req;
    if( (*breq)->next == NULL ) {
        conn->first_req = NULL;
        conn->last_req = NULL;
    } else {
        conn->first_req = (*breq)->next;
    }
    //printf("done popping request\n");
    return 0;
}

static void evcc_kill_conn( struct ev_tls_conn_t* conn ){
    int kill_sig = 0;
    chansendnb(&conn->kill_chan, &kill_sig);
    qlock(&conn->mutex);
    conn->alive = false;
    qunlock(&conn->mutex);
}

// Commit a raw (byte) request to a tls connection
ssize_t v2g_raw_request( struct ev_tls_conn_t* conn, byte* buffer,
                     size_t request_len, size_t buffer_len, uvlong timeout_ns )
{
    int err;
    ssize_t response_len;
    Chan tc;
    Alt alts[3];
    err = tchaninit(&tc);
    if (err != 0) {
        printf("v2g_raw_request: tchaninit error\n");
        return -1;
    }
    tchanset(&tc, timeout_ns);
    qlock( &conn->mutex );
    if( !conn->alive ) {
        printf("v2g_raw_request: cannot send request, connection dead\n");
        conn->alive = false;
        qunlock( &conn->mutex );
        evcc_kill_conn(conn);
        chanfree(&tc);
        return -1;
    }
    err = sslwriten( &conn->ssl, buffer, request_len, &tc );
    if( err != 0){
        printf("v2g_raw_request: sslwriten\n");
        conn->alive = false;
        qunlock( &conn->mutex );
        evcc_kill_conn(conn);
        chanfree(&tc);
        return -1;
    }
	struct ev_blocking_request_t breq = {
		.buffer = buffer,
		.buffer_len = buffer_len,
		.next = NULL,
	};
	chaninit( &breq.wake_chan, sizeof(int), 1);
	push_blocking_request( conn, &breq );
    qunlock( &conn->mutex );
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
            printf("v2g_raw_request: timeout\n");
            evcc_kill_conn(conn);
            // Wait until stream_reader is done to avoid race conditions
            chanrecv(&breq.wake_chan, &err);
            response_len = -1;
            break;
        default:
            printf("critical error at v2g_raw_request: alt error\n");
            abort();
    }
    chanfree(&tc);
    return response_len;
}

// Create a handshake request (exchanging app protocol versions)
int v2g_handshake_request( struct ev_tls_conn_t* conn )
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
    char* ns0 = ISO_15118_MSG_DEF;
    // the DIN addition ( add later?)
	//char* ns1 = "urn:din:70121:2012:MsgDef";
    struct appHandEXIDocument handshake;
	struct appHandEXIDocument handshake_resp;
    init_appHandEXIDocument( &handshake );
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


    if( (err = encode_appHandExiDocument(&stream, &handshake)) == 0) {
        printf("====================\n");
		if ( write_v2gtpHeader(stream.data, buffer_pos-V2GTP_HEADER_LENGTH, V2GTP_EXI_TYPE) == 0 ) {
			printf("EV side: send message to the EVSE\n");
		}
	}
	// === Commit request ===
	printf("raw handshake request\n");

    len = v2g_raw_request( conn, buffer, buffer_pos, BUFFER_SIZE,
                           V2G_EVCC_Msg_Timeout_SupportedAppProtocolReq * TIME_SECOND );
    if( len <= 0 ){
        printf("v2g_handshake_request error: v2g_raw request\n");
        return 0;
    }
    // === Handle response ===
    printf("done with raw handhake request\n");
    buffer_pos = 0;
    uint16_t payload_len;
    err = read_v2gtpHeader(stream.data, &payload_len);
    if( err != 0 ) {
        printf("v2g_handshake_request error: read_v2gtpHeader\n");
        return -1;
    }
	buffer_pos = V2GTP_HEADER_LENGTH;
    err = decode_appHandExiDocument(&stream, &handshake_resp);
    if( err != 0 ) {
        printf("v2g_handshake_request error: decode_appHandExiDocument\n");
        return -1;
    }
		printf("EV side: Response of the EVSE \n");
	if( handshake_resp.supportedAppProtocolRes.ResponseCode
	    != appHandresponseCodeType_OK_SuccessfulNegotiation) {
	    printf("\t\tResponseCode=ERROR_UnsuccessfulNegotiation\n");
        return -1;
	}
	printf("\t\tResponseCode=OK_SuccessfulNegotiation\n");
	printf( "\t\tSchemaID=%d\n",
		        handshake_resp.supportedAppProtocolRes.SchemaID);
	return 0;
}

// Create a v2g request to the EVSE
int v2g_request( struct ev_tls_conn_t* conn, struct v2gEXIDocument* exiIn,
                 struct v2gEXIDocument* exiOut){
//struct v2gEXIDocument* exiOut) {
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
	/* EV side */
	err = serializeEXI2Stream( exiIn, &stream);
    if (err != 0) {
        printf("v2g_request error: serializeEXI2Stream\n");
	    return err;
	}
    len = v2g_raw_request( conn, buffer, buffer_pos, BUFFER_SIZE, req_timeout );
    if (len <= 0) {
        printf("v2g_request error: v2g_raw_request\n");
        return 0;
    }
    buffer_pos = 0;
    err = deserializeStream2EXI( &stream, exiOut);
    if (err != 0) {
        printf("v2g_request error: deserializeStream2EXI\n");
        return 0;
    }
   // printf("succesful v2g_request\n");
    return 0;
}

// Read responses from requests to EVSE and deliver them to requester
static void evcc_connect_tls_stream_reader( void* arg )
{
	int err, len;
    struct ev_tls_conn_t* conn = arg;
	struct ev_blocking_request_t* breq;
	byte header_buf[V2GTP_HEADER_LENGTH];
    for(;;) {
        uint16_t payload_len;
        err = sslreadn( &conn->ssl, header_buf,
                          V2GTP_HEADER_LENGTH, &conn->kill_chan );
        if( err < 0 ){
            printf( "evcc_connect_tls_stream_reader error: sslreadn error\n");
            break;
        }
        // === Check header for response size ===
        err = read_v2gtpHeader( header_buf, &payload_len);
        if( err != 0 ) {
            printf("evcc_connect_tls_stream_reader error: invalid v2gtp header\n");
            break;
        }
        qlock( &conn->mutex );
        // === pop the first request of the queue ===
        err = pop_blocking_request( conn, &breq );
		if( err != 0){
		    qunlock( &conn->mutex );
            printf("evcc_connect_tls_stream_reader: pop_blocking_request error\n");
            break;
        }
        qunlock( &conn->mutex );
        if( payload_len + V2GTP_HEADER_LENGTH > breq->buffer_len ) {
            err = -1;
            chansend( &breq->wake_chan, &err );
            printf("evcc_connect_tls_stream_reader error: Buffer too small for request\n");
            break;
        }
        err = sslreadn( &conn->ssl, breq->buffer + V2GTP_HEADER_LENGTH,
                        payload_len, &conn->kill_chan );
        if( err != 0 ) {
            chansend( &breq->wake_chan, &err );
            printf("evcc_connect_tls_stream_reader error: sslreadn\n");
            break;
        }
        memcpy( breq->buffer, header_buf, V2GTP_HEADER_LENGTH );
        len = V2GTP_HEADER_LENGTH + payload_len;
        chansend( &breq->wake_chan, &len );
    }
    printf("disconnected\n");
    qlock(&conn->mutex);
    conn->alive = false;
    err = -1;
    for( breq = conn->first_req; breq != NULL; breq = breq->next ) {
        chansend( &breq->wake_chan, &err );
    }
    qunlock(&conn->mutex);
    // === Free connection ===
    chanfree(&conn->kill_chan);
    x509_crt_free( &conn->cacert );
    ssl_free( &conn->ssl );
    ctr_drbg_free( &conn->ctr_drbg );
    entropy_free( &conn->entropy );
    shutdown(conn->serverfd, 2);
    close(conn->serverfd);
}

// Connect to an EVSE
int evcc_connect_tls( struct ev_tls_conn_t* conn )
{
    int err = 0;
    const char *pers = "secc_ssl_client";
    // === Init ===
    chaninit(&conn->kill_chan, sizeof(int), 1);
    conn->first_req = NULL;
    conn->last_req = NULL;
    conn->serverfd = socket(AF_INET6, SOCK_STREAM, 0);
    if( conn->serverfd < 0 ) {
        perror("socket");
        return -1;
    }
    // === Setup entropy ===
    entropy_init( &conn->entropy );
    x509_crt_init( &conn->cacert );
    memset( &conn->ctr_drbg, 0, sizeof( ctr_drbg_context ) );
    // === Setup random number generator for tls ===
    err = ctr_drbg_init( &conn->ctr_drbg, entropy_func, &conn->entropy,
                         (const unsigned char *) pers,
                         strlen( pers ) );
    if( err != 0 ) {
        printf("ctr_drbg_init error\n");
        goto exit;
    }
    // === Parse certificate and .key file ===
    err = x509_crt_parse_file( &conn->cacert, "certs/ev.crt" );
    if( err != 0 ) {
        printf( " failed\n  !  x509_crt_parse returned %d\n\n", err );
        goto exit;
    }
    printf("\n");
    err = connect( conn->serverfd, (struct sockaddr*)&conn->addr,
                   sizeof( struct sockaddr_in6) );
    if( err != 0 ) {
        perror("connect");
        goto exit;
    }
    printf("debug: connected\n");
    // === init ssl ==
    memset( &conn->ssl, 0, sizeof(ssl_context) );
    ssl_init( &conn->ssl );
    ssl_set_endpoint( &conn->ssl, SSL_IS_CLIENT );
    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    if( IGNORE_SSL_CERTIFICATE_VALIDITY ){
        // DONT CHECK CERTS DUE TO TESTING!!
        ssl_set_authmode( &conn->ssl, SSL_VERIFY_OPTIONAL );
    } else {
        ssl_set_authmode( &conn->ssl, SSL_VERIFY_REQUIRED );
    }
    ssl_set_ciphersuites(&conn->ssl, V2G_CIPHER_SUITES);
    ssl_set_ca_chain( &conn->ssl, &conn->cacert, NULL, "PolarSSL Server 1" );
    ssl_set_rng( &conn->ssl, ctr_drbg_random, &conn->ctr_drbg );
    ssl_set_dbg( &conn->ssl, my_debug, stdout );
    ssl_set_bio( &conn->ssl, net_recv, &conn->serverfd,
                       net_send, &conn->serverfd );
    // === Perform SSL handshake ===
    while( ( err = ssl_handshake( &conn->ssl ) ) != 0 )
    {
        if( err != POLARSSL_ERR_NET_WANT_READ && err != POLARSSL_ERR_NET_WANT_WRITE )
        {
            printf( " failed\n  ! ssl_handshake returned -0x%x\n\n", err );
            goto exit;
        }
    }
    // === Check certificate validity ===
    if( ( err = ssl_get_verify_result( &conn->ssl ) ) != 0 ) {
        printf( " failed\n" );

        if( ( err & BADCERT_EXPIRED ) != 0 ) {
            printf( "  ! server certificate has expired\n" );
        }
        if( ( err & BADCERT_REVOKED ) != 0 ) {
            printf( "  ! server certificate has been revoked\n" );
        }
        if( ( err & BADCERT_CN_MISMATCH ) != 0 ) {
            printf( "  ! CN mismatch (expected CN=%s)\n", "PolarSSL Server 1" );
        }
        if( ( err & BADCERT_NOT_TRUSTED ) != 0 ) {
            printf( "  ! self-signed or not signed by a trusted CA\n" );
        }
        printf( "\n" );
    } else {
        printf( " ok\n" );
    }
	conn->alive = true;
    memset(&conn->mutex, 0, sizeof(conn->mutex));
    err = threadcreate( evcc_connect_tls_stream_reader, conn, 1024 * 1024 );
    if( err != 0 ){
        printf("threadcreate error");
        goto exit;
    }
    err = v2g_handshake_request( conn );
    if( err != 0 ){
        printf("v2g handshake error\n");
        goto exit; // stuff is freed in stream reader
    }
    printf("TLS handshake succesful\n");
    return 0;
    // === Only ends here if an error has happened ===
    exit:
    x509_crt_free( &conn->cacert );
    ssl_free( &conn->ssl );
    ctr_drbg_free( &conn->ctr_drbg );
    entropy_free( &conn->entropy );
    shutdown(conn->serverfd, 2);
    close(conn->serverfd);
    return -1;
}
