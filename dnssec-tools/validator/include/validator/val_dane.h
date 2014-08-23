
/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_DANE_H
#define VAL_DANE_H

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>

#include <openssl/bn.h>
#include <openssl/sha.h>
#ifdef HAVE_CRYPTO_SHA2_H /* netbsd */
#include <crypto/sha2.h>
#endif
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern          "C" {
#endif

/*
 * DANE usage types
 */
#define DANE_USE_CA_CONSTRAINT  0
#define DANE_USE_SVC_CONSTRAINT 1
#define DANE_USE_TA_ASSERTION   2
#define DANE_USE_DOMAIN_ISSUED  3

/*
 * DANE usage types
 */
#define DANE_SEL_FULLCERT   0
#define DANE_SEL_PUBKEY     1

/*
 * DANE matching types
 */
#define DANE_MATCH_EXACT    0
#define DANE_MATCH_SHA256   1
#define DANE_MATCH_SHA512   2

/*
 * DANE parameters 
 */
#define DANE_PARAM_PROTO_TCP    0
#define DANE_PARAM_PROTO_UDP    1
#define DANE_PARAM_PROTO_SCTP   2
#define DANE_PARAM_PROTO_STR_TCP "tcp"
#define DANE_PARAM_PROTO_STR_UDP "udp"
#define DANE_PARAM_PROTO_STR_SCTP "sctp"


/*
 * DANE specific return codes 
 */
#define VAL_DANE_NOERROR        0
#define VAL_DANE_CANCELLED      1
#define VAL_DANE_INTERNAL_ERROR 2
#define VAL_DANE_NOTVALIDATED   3
#define VAL_DANE_IGNORE_TLSA    4
#define VAL_DANE_MALFORMED_TLSA 5
#define VAL_DANE_CHECK_FAILED   6

/*
 * These are the parameters that the user would supply
 * to control the manner in which DANE validation is performed.
 */
struct val_daneparams {
    int port;
    int proto; 
};

/*
 * The DANE record details are returned in the following structure 
 */
struct val_danestatus {
    long ttl;
    int usage;
    int selector;
    int type;
    size_t datalen;
    unsigned char *data;
    struct val_danestatus *next;
};


struct val_ssl_data {
    val_context_t *context;
    char *qname;
    struct val_danestatus *danestatus;
};

typedef int (*val_dane_callback)(void *callback_data, 
                                 int retval,
                                 struct val_danestatus **res);

/*
 * Prototypes
 */
const char *p_dane_error(int rc);
void val_free_dane(struct val_danestatus *dres);
int val_dane_submit(val_context_t *context, 
                    const char *name,
                    struct val_daneparams *params,
                    val_dane_callback callback, 
                    void *callback_data,
                    val_async_status **status);
int val_getdaneinfo(val_context_t *context,
                    const char *name,
                    struct val_daneparams
                    *params,
                    struct val_danestatus **dres);
int val_dane_match(val_context_t *ctx,
                   struct val_danestatus *dane_cur, 
                   const unsigned char *data, 
                   int len);

int val_dane_cert_namechk(val_context_t *context,
                   char *qname,
                   const unsigned char *data, 
                   int len); 

int val_enable_dane_ssl(val_context_t *ctx,
                        SSL_CTX *sslctx,
                        char *qname,
                        struct val_danestatus *danestatus,
                        struct val_ssl_data **ssl_dane_data);

void val_free_dane_ssl(struct val_ssl_data *ssl_dane_data);

#ifdef __cplusplus
}                               /* extern "C" */
#endif
#endif                          /* VAL_DANE_H */
