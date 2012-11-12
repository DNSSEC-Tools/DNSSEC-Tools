/*
 * Copyright 2005-2012 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Suresh Krishnaswamy
 *
 */

/* 
 * DESCRIPTION
 * This file contains the implementation for DANE (RFC 6698) 
 */

#include "validator-internal.h"
#include "val_context.h"
#include "validator/val_dane.h"

#include <openssl/bn.h>
#include <openssl/sha.h>
#ifdef HAVE_CRYPTO_SHA2_H /* netbsd */
#include <crypto/sha2.h>
#endif
#include <openssl/x509.h>
#include <openssl/evp.h>

/*
 * Internal callback structure
 */
typedef struct _val_dane_async_status {
    val_context_t *context;
    struct val_daneparams *dparam;
    val_dane_callback callback;
    void *callback_data;
    val_async_status *das; /* helps us cancel this lookup */
} _val_dane_async_status_t;


/*
 * Construct a linked list of DANE structures from the result linked
 * list
 */
static int 
get_dane_from_result(struct val_daneparams *dparam,
                     struct val_result_chain *results,
                     struct val_danestatus **dres)
{
    struct val_result_chain *res;
    struct val_rrset_rec *rrset;
    struct val_danestatus *dtail, *dcur;
    u_char *cp, *end;
    int rc = VAL_DANE_NOERROR;

    *dres = NULL;

    dtail = NULL;
    dcur = NULL;

    for (res = results; res != NULL; res = res->val_rc_next) {

        if (val_does_not_exist(res->val_rc_status))
            return VAL_DANE_MISSING_TLSA;

        /* DANE resource records MUST be validated */
        if (!val_isvalidated(res->val_rc_status))
            return VAL_DANE_NOTVALIDATED;

        rrset = res->val_rc_rrset;
        if(!res->val_rc_alias && rrset && 
                rrset->val_rrset_type == ns_t_tlsa) {
            struct val_rr_rec  *rr = rrset->val_rrset_data; 

            while (rr) {

                /* 
                 * XXX Use dparam to match the specific RR that we need
                 */

                dcur = (struct val_danestatus *) MALLOC (sizeof(struct
                            val_danestatus));
                if (dcur == NULL) {
                    rc = VAL_DANE_INTERNAL_ERROR;
                    goto err;
                }
                /* Parse the RR into the DANE structure */
                cp = rr->rr_rdata;
                end = cp + rr->rr_rdata_length;
                if (end - cp < 3) {
                    /* 
                     * Don't have enough data for the fixed length TLSA
                     * fields
                     */
                    rc = VAL_DANE_MALFORMED_TLSA;
                    goto err;
                }
                /* 
                 * expose the TTL information to indicate how long the 
                 * application is allowed to cache this data
                 */
                dcur->ttl = rrset->val_rrset_ttl;
                dcur->usage = *cp++;
                dcur->selector = *cp++;
                dcur->type = *cp++;
                dcur->datalen = end - cp;
                dcur->next = NULL;
                if (dcur->datalen > 0) {
                    dcur->data = (u_char *) MALLOC (dcur->datalen * sizeof(u_char));
                    if (dcur->data == NULL) {
                        rc = VAL_DANE_INTERNAL_ERROR;
                        goto err;
                    }
                    memcpy(dcur->data, cp, dcur->datalen);
                } else {
                    dcur->data = NULL;
                }

                if (dtail == NULL) {
                    /* add the head element */
                    dtail = dcur;
                    *dres = dcur;
                } else {
                    dtail->next = dcur;
                    dtail = dcur;
                }

                rr = rr->rr_next;
            }
        }
    }

    return rc;

err:
    val_free_dane(*dres);
    *dres = NULL;
    return rc;
}


/*
 * Contstruct the DANE query name from the lookup name, port and
 * protocol
 */
static int 
get_dane_prefix(const char *name, 
                struct val_daneparams *params,
                char *dane_name,
                size_t dane_namelen)
{
    const char *proto;

    if (name == NULL || params == NULL || dane_name == NULL) 
        return VAL_BAD_ARGUMENT;

    if (params->proto == DANE_PARAM_PROTO_TCP)
        proto = DANE_PARAM_PROTO_STR_TCP;
    else if (params->proto == DANE_PARAM_PROTO_UDP)
        proto = DANE_PARAM_PROTO_STR_UDP;
    else if (params->proto == DANE_PARAM_PROTO_SCTP)
        proto = DANE_PARAM_PROTO_STR_SCTP;
    else
        return VAL_BAD_ARGUMENT;

    snprintf(dane_name, dane_namelen,
            "_%d._%s.%s", params->port, proto, name);

    return VAL_NO_ERROR;
}

/*
 * Internal callback, invoked when TLSA async lookup completes.
 */
static int
_dane_async_callback(val_async_status *as, int event,
                      val_context_t *ctx, void *cb_data,
                      val_cb_params_t *cbp) 
{
    _val_dane_async_status_t *dstat;
    struct val_danestatus *dres;
    int rc = VAL_NO_ERROR;
    int dane_rc = VAL_DANE_NOERROR;
        
    dres = NULL;
    dstat = (_val_dane_async_status_t *) cb_data;

    if (NULL == cbp || NULL == as) {
        val_log(ctx, LOG_DEBUG, "_dane_async_callback no callback data!");
        return VAL_NO_ERROR;
    }
    val_log(ctx, LOG_DEBUG,
            "_dane_async_callback for %p, %s %s(%d)", 
            as, cbp->name, p_type(cbp->type_h), cbp->type_h);

    rc = cbp->retval;

    if (rc != VAL_NO_ERROR) {
        dane_rc = VAL_DANE_INTERNAL_ERROR;
        goto done;
    }

    if (event == VAL_AS_EVENT_CANCELED) {
        dane_rc = VAL_DANE_CANCELLED;
        goto done;
    }

    /* Parse results into val_danestatus structure */

    /* 
     * XXX Use struct val_daneparams to filter our results
     */
    dane_rc = get_dane_from_result(dstat->dparam,
                                   cbp->results, 
                                   &dres);

done:
    (*dstat->callback)(dstat->callback_data, dane_rc, &dres); 

    /* callback keeps the dres structure; don't free */
    dres = NULL;

    /* Free up the val_cb_params_t structure */
    if(cbp->name)
        FREE(cbp->name);
    val_free_result_chain(cbp->results);
    val_free_answer_chain(cbp->answers);
    cbp->name = NULL;
    cbp->results = NULL;
    cbp->answers = NULL;

    /* 
     * XXX Shouldn't we free up the main cbp pointer as well?
     */

    FREE(dstat);

    return VAL_NO_ERROR;
}

/*
 * return an error string for the given DANE related error code
 */
const char *p_dane_error(int rc)
{
    const char *err;
    switch (rc) {
        case VAL_DANE_NOERROR:
            err = "VAL_DANE_NOERROR";
            break;
        case VAL_DANE_CANCELLED:
            err = "VAL_DANE_CANCELLED";
            break;
        case VAL_DANE_INTERNAL_ERROR:
            err = "VAL_DANE_INTERNAL_ERROR";
            break;
        case VAL_DANE_NOTVALIDATED:
            err = "VAL_DANE_NOTVALIDATED";
            break;
        case VAL_DANE_MISSING_TLSA:
            err = "VAL_DANE_MISSING_TLSA";
            break;
        default:
            err = "UNKNOWN DANE error";
            break;
    }

    return err;
}

/* 
 * Free up the list of DANE TLSA records 
 */
void val_free_dane(struct val_danestatus *dres)
{
    struct val_danestatus *prev, *cur;

    prev = NULL;
    cur = dres;

    while (cur) {
        prev = cur;
        cur = cur->next;
        if (prev->data)
            FREE(prev->data);
        FREE(prev);
    }
}

/*
 * Async validation of DANE records
 */
int val_dane_submit(val_context_t *context, 
                    const char *name,
                    struct val_daneparams *params,
                    val_dane_callback callback, 
                    void *callback_data,
                    val_async_status **status)
{
    _val_dane_async_status_t *dstat = NULL;
    val_context_t *ctx;
    int rc;
    char dane_name[NS_MAXDNAME];

    if (name == NULL || status == NULL)
       return VAL_BAD_ARGUMENT; 

    ctx = val_create_or_refresh_context(context);
    if (ctx == NULL)
        return VAL_INTERNAL_ERROR;

    /*
     * Check if valid DANE lookup name can be constructed
     */
    rc = get_dane_prefix(name, params, dane_name, NS_MAXDNAME); 
    if (rc != VAL_NO_ERROR)
        return rc;

    /*
     * Do all the memory allocations upfront
     */
    dstat = (_val_dane_async_status_t *) 
                MALLOC (sizeof(_val_dane_async_status_t));
    if (NULL == dstat) 
        return VAL_ENOMEM;

    /*
     * Save the caller information so that we can
     * invoke the correct callback function when we're done
     */
    dstat->context = ctx;
    dstat->dparam = params;
    dstat->callback = callback; 
    dstat->callback_data = callback_data; 
    dstat->das = NULL; 

    /*
     * Begin our internal async lookup for DANE related records
     */
    val_log(ctx, LOG_DEBUG,
            "val_dane_submit(): checking for TLSA records");

    rc = val_async_submit(ctx, dane_name, ns_c_in, ns_t_tlsa, 0,
                          &_dane_async_callback, dstat,
                          &dstat->das);

    CTX_UNLOCK_POL(ctx);   

    if (VAL_NO_ERROR != rc) {
        FREE(dstat);
        *status = NULL;
    } else {
        *status = dstat->das;
    }

    return rc;
}

/*
 * Synchronous validation of DANE records
 */
int val_getdaneinfo(val_context_t *context,
                    const char *name,
                    struct val_daneparams *params,
                    struct val_danestatus **dres)
{
    val_context_t *ctx;
    struct val_result_chain *results = NULL;
    int rc;
    char dane_name[NS_MAXDNAME];
    int dane_rc = VAL_DANE_NOERROR;

    if (name == NULL || params == NULL || dres == NULL)
       return VAL_DANE_INTERNAL_ERROR; 

    ctx = val_create_or_refresh_context(context);
    if (ctx == NULL)
        return VAL_DANE_INTERNAL_ERROR;

    *dres = NULL;

    /*
     * Check if valid DANE lookup name can be constructed
     */
    rc = get_dane_prefix(name, params, dane_name, NS_MAXDNAME); 
    if (rc != VAL_NO_ERROR)
        return VAL_DANE_INTERNAL_ERROR;

    if ((rc = val_resolve_and_check(ctx, dane_name, ns_c_in, ns_t_tlsa,
                                    0, &results))
            != VAL_NO_ERROR) {
        val_log(ctx, LOG_INFO,
                "val_getdaneinfo(): val_resolve_and_check failed - %s",
                p_val_err(rc));
        return VAL_DANE_INTERNAL_ERROR;
    }    

    /* Parse results into val_danestatus structure */
    /* 
     * XXX Use struct val_daneparams to filter our results
     */
    dane_rc = get_dane_from_result(params,
                                   results, 
                                   dres);

    return dane_rc;
}

static
int get_pkeybuf(const unsigned char *data, int len, 
                int *pkeyLen, unsigned char **pkeybuf)
{
    X509 *cert;
    EVP_PKEY *pkey;
    int rv = 0;
    const unsigned char *tmp = data;

    if (pkeyLen == NULL || pkeybuf == NULL)
        return -1;

    *pkeyLen = 0;
    *pkeybuf = NULL;

    cert = d2i_X509(NULL, &tmp, len);
    if (cert == NULL)
        return -1;

    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        X509_free(cert);
        return -1;
    }

    *pkeyLen = i2d_PUBKEY(pkey, NULL);
    if (*pkeyLen > 0)
        *pkeybuf = (unsigned char *)MALLOC((*pkeyLen) * sizeof(unsigned char));
    if (*pkeybuf == NULL) {
        rv = -1;
    } else {
        unsigned char *tmp2 = *pkeybuf;
        i2d_PUBKEY(pkey, &tmp2);
    }
    EVP_PKEY_free(pkey); 
    X509_free(cert);
    return rv;
}

int val_dane_match(val_context_t *ctx,
                   struct val_danestatus *dane_cur, 
                   const unsigned char *data, 
                   int len)
{
    SHA256_CTX ctx256;
    SHA512_CTX ctx512;

    if (dane_cur == NULL || data == NULL)
        return -1;

    val_log(ctx, LOG_DEBUG,
            "val_dane_match(): checking for DANE cert match - sel:%d type:%d", 
            dane_cur->selector, dane_cur->type);

    if ((dane_cur->selector != DANE_SEL_FULLCERT) &&
        (dane_cur->selector != DANE_SEL_PUBKEY)) {
        val_log(ctx, LOG_DEBUG,
            "val_dane_match(): Unknown DANE selector:%d",
            dane_cur->selector);
        return -1;
    }

    if (dane_cur->type == DANE_MATCH_EXACT) {
        X509 *cert;
        X509 *tlsa_cert;
#if 0
    {
        char buf1[1028];
        char buf2[1028];
        size_t buflen1 = 1024;
        size_t buflen2 = 1024;
        fprintf(stderr,
            "val_dane_match(): checking for exact DANE cert match %s \n\n %s", 
            get_hex_string(data, len, buf1, buflen1),
            get_hex_string(dane_cur->data, dane_cur->datalen, buf2, buflen2));
    }
#endif

        if (dane_cur->selector == DANE_SEL_FULLCERT) {
            const unsigned char *tmp = data;
            const unsigned char *tmp2 = dane_cur->data;
            cert = d2i_X509(NULL, &tmp, len);
            tlsa_cert = d2i_X509(NULL, &tmp2, 
                                 dane_cur->datalen);
            if ((cert != NULL) && (X509_cmp(tlsa_cert, cert) == 0)) {
                X509_free(cert);
                X509_free(tlsa_cert);
                val_log(ctx, LOG_DEBUG, "val_dane_match(): DANE_SEL_FULLCERT/DANE_MATCH_EXACT success");
                return 0;
            }
            val_log(ctx, LOG_DEBUG, "val_dane_match(): DANE_SEL_FULLCERT/DANE_MATCH_EXACT failed");
            X509_free(cert);
            X509_free(tlsa_cert);
        } else {
            int pkeyLen = 0;
            unsigned char *pkeybuf = NULL;

            if (0 != get_pkeybuf(data, len, &pkeyLen, &pkeybuf))
                return -1;

            if (pkeyLen == dane_cur->datalen &&
                0 == memcmp(pkeybuf, dane_cur->data, pkeyLen)) {

                val_log(ctx, LOG_DEBUG, "val_dane_match(): DANE_SEL_PUBKEY/DANE_MATCH_EXACT success");
                FREE(pkeybuf);
                return 0;
            }
            val_log(ctx, LOG_DEBUG, "val_dane_match(): DANE_SEL_PUBKEY/DANE_MATCH_EXACT failed");
            FREE(pkeybuf);
            return 0;
        }

    } else if (dane_cur->type == DANE_MATCH_SHA256) {

        unsigned char cert_sha[SHA256_DIGEST_LENGTH];
        memset(cert_sha, 0, SHA256_DIGEST_LENGTH);

        if (dane_cur->selector == DANE_SEL_FULLCERT) {
            SHA256(data, len, cert_sha);
        } else {
            int pkeyLen = 0;
            unsigned char *pkeybuf = NULL;
            if (0 != get_pkeybuf(data, len, &pkeyLen, &pkeybuf))
                return -1;
#if 0
            {
                char buf1[1028];
                size_t buflen1 = 1024;
                fprintf(stderr, "pkeylen = %d, pkeybuf = %s\n",
                        pkeyLen, 
                        get_hex_string(pkeybuf, pkeyLen, buf1, buflen1));
            }
#endif
            SHA256(pkeybuf, pkeyLen, cert_sha);
            FREE(pkeybuf);
        }

#if 0
        {
        char buf1[1028];
        char buf2[1028];
        size_t buflen1 = 1024;
        size_t buflen2 = 1024;
        fprintf(stderr,
            "val_dane_match(): checking for DANE SHA256 match %s with %s", 
            get_hex_string(cert_sha, SHA256_DIGEST_LENGTH, buf1, buflen1),
            get_hex_string(dane_cur->data, dane_cur->datalen, buf2, buflen2));
        }
#endif

        if (dane_cur->datalen == SHA256_DIGEST_LENGTH && 
            0 == memcmp(cert_sha, dane_cur->data, SHA256_DIGEST_LENGTH)) {
            val_log(ctx, LOG_DEBUG, "val_dane_match(): DANE_MATCH_SHA256 success");
            return 0;
        }
        val_log(ctx, LOG_DEBUG, 
                "val_dane_match(): DANE SHA256 does NOT match (len = %d)", 
                dane_cur->datalen);
        val_log(ctx, LOG_DEBUG, "val_dane_match(): DANE_MATCH_SHA256 failed");
    } else if (dane_cur->type == DANE_MATCH_SHA512) {

        unsigned char cert_sha[SHA512_DIGEST_LENGTH];
        memset(cert_sha, 0, SHA512_DIGEST_LENGTH);

        if (dane_cur->selector  == DANE_SEL_FULLCERT) {
            SHA512(data, len, cert_sha);
        } else {
            int pkeyLen = 0;
            unsigned char *pkeybuf = NULL;
            if (0 != get_pkeybuf(data, len, &pkeyLen, &pkeybuf))
                return -1;
            SHA512(pkeybuf, pkeyLen, cert_sha);
            FREE(pkeybuf);
        }

#if 0
        {
        char buf1[1028];
        char buf2[1028];
        size_t buflen1 = 1024;
        size_t buflen2 = 1024;
        fprintf(stderr,
            "val_dane_match(): checking for DANE SHA512 match %s with %s", 
            get_hex_string(cert_sha, SHA512_DIGEST_LENGTH, buf1, buflen1),
            get_hex_string(dane_cur->data, dane_cur->datalen, buf2, buflen2));
        }
#endif

        if (dane_cur->datalen == SHA512_DIGEST_LENGTH &&
            0 == memcmp(cert_sha, dane_cur->data, SHA512_DIGEST_LENGTH)) {
            val_log(ctx, LOG_DEBUG, "val_dane_match(): DANE_MATCH_SHA512 success");
            return 0;
        }
        val_log(ctx, LOG_DEBUG, "val_dane_match(): DANE_MATCH_SHA512 failed");
    } else {
        val_log(ctx, LOG_DEBUG,
            "val_dane_match(): Error - Unknown DANE type:%d", dane_cur->type);
    }

    return -1;
}

