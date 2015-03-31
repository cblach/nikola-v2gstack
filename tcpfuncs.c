#ifndef byte
typedef uint8_t byte;
#endif

typedef struct{
    int sockfd;
    byte* buffer;
    unsigned int n;
} tcpn_arg;

static ssize_t iocall_readn( void* vargs, atomic_int *cancel )
{
    tcpn_arg* args = vargs;
    int bytes_read = 0;
    int tries = 0;
    int ret;
    while (bytes_read < args->n && atomic_load(cancel) == 0) {
        ret = read(args->sockfd, args->buffer + bytes_read,
                   args->n - bytes_read);
        if( ret == POLARSSL_ERR_NET_WANT_READ ||
            ret == POLARSSL_ERR_NET_WANT_WRITE ) {
            if (tries > 30) {
                printf("sslreadn: Too many socket read errors\n");
                return -1;
            }
            continue;
        }
        if (ret < 1) {
            if (ret != 0) {
                perror("iocall_readn: read err");
            }
            return -1;
        }
        bytes_read += ret;
    }
    return 0;
}

static ssize_t iocall_writen( void* vargs, atomic_int *cancel )
{
    tcpn_arg* args = vargs;
    int bytes_written = 0;
    int ret;
    while (bytes_written < args->n && atomic_load(cancel) == 0) {
        ret = write(args->sockfd, args->buffer + bytes_written,
                    args->n - bytes_written);
        if (ret < 1) {
            if (ret != 0) {
                perror("iocall_writen: write err");
            }
            return -1;
        }
        bytes_written += ret;
    }
    return 0;
}

static int readn( int sockfd, byte* buffer,
                  unsigned int n, Chan* tc ) {
    Alt alts[3];
    tcpn_arg args = {
        .sockfd = sockfd,
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

static int writen( int sockfd, byte* buffer,
                   unsigned int n, Chan* tc ){
    Alt alts[3];
    tcpn_arg args = {
        .sockfd = sockfd,
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
