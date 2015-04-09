#ifndef SERVER_H
#define SERVER_H

#include <OpenV2G/v2gEXIDatatypes.h>
#include <polarssl/x509.h>

extern x509_crt Trusted_contract_rootcert_chain;

int create_response_message(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);

#endif
