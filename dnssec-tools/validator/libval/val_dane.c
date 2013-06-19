/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
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
get_dane_from_result(val_context_t *ctx,
                     struct val_daneparams *dparam,
                     struct val_result_chain *results,
                     struct val_danestatus **dres)
{
    struct val_result_chain *res;
    struct val_rrset_rec *rrset;
    struct val_danestatus *dtail, *dcur;
    u_char *cp, *end;
    int rc = VAL_DANE_NOERROR;
    int validated;

    *dres = NULL;
    dtail = NULL;
    dcur = NULL;
    validated = 1;

    for (res = results; res != NULL; res = res->val_rc_next) {

        /*
         * If the answer is not even trusted then return failure
         */
        if (!val_istrusted(res->val_rc_status))
            return VAL_DANE_NOTVALIDATED;

        /* 
         * not validated is okay for non-existence conditions
         */
        if (!validated || !val_isvalidated(res->val_rc_status))
            validated = 0;

        /* 
         * skip the aliases 
         */
        if (res->val_rc_alias) {
            continue;
        }

        if (val_does_not_exist(res->val_rc_status))
            return VAL_DANE_IGNORE_TLSA;

        /* 
         * We're now about to process the DANE record
         * DANE resource records MUST be validated 
         */
        if (!validated)
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
                    FREE(dcur);
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
                if (dcur->datalen <= 0) {
                    FREE(dcur);
                    rc = VAL_DANE_MALFORMED_TLSA;
                    goto err;
                }
                dcur->next = NULL;
                dcur->data = (u_char *) MALLOC (dcur->datalen * sizeof(u_char));
                if (dcur->data == NULL) {
                    FREE(dcur);
                    rc = VAL_DANE_INTERNAL_ERROR;
                    goto err;
                }
                memcpy(dcur->data, cp, dcur->datalen);
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
    dane_rc = get_dane_from_result(ctx,
                                   dstat->dparam,
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
        case VAL_DANE_IGNORE_TLSA:
            err = "VAL_DANE_IGNORE_TLSA";
            break;
        case VAL_DANE_MALFORMED_TLSA:
            err = "VAL_DANE_MALFORMED_TLSA";
            break;
        case VAL_DANE_CHECK_FAILED:
            err = "VAL_DANE_CHECK_FAILED";
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

    ctx = val_create_or_refresh_context(context);/* does CTX_LOCK_POL_SH */
    if (ctx == NULL)
        return VAL_INTERNAL_ERROR;

    /*
     * Check if valid DANE lookup name can be constructed
     */
    rc = get_dane_prefix(name, params, dane_name, NS_MAXDNAME); 
    if (rc != VAL_NO_ERROR) {
        CTX_UNLOCK_POL(ctx);
        return rc;
    }

    /*
     * Do all the memory allocations upfront
     */
    dstat = (_val_dane_async_status_t *) 
                MALLOC (sizeof(_val_dane_async_status_t));
    if (NULL == dstat) {
        CTX_UNLOCK_POL(ctx);
        return VAL_ENOMEM;
    }

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

    ctx = val_create_or_refresh_context(context);/* does CTX_LOCK_POL_SH */
    if (ctx == NULL)
        return VAL_DANE_INTERNAL_ERROR;

    *dres = NULL;

    /*
     * Check if valid DANE lookup name can be constructed
     */
    rc = get_dane_prefix(name, params, dane_name, NS_MAXDNAME); 
    if (rc != VAL_NO_ERROR) {
        CTX_UNLOCK_POL(ctx);
        return VAL_DANE_INTERNAL_ERROR;
    }

    if ((rc = val_resolve_and_check(ctx, dane_name, ns_c_in, ns_t_tlsa,
                                    0, &results))
            != VAL_NO_ERROR) {
        val_log(ctx, LOG_INFO,
                "val_getdaneinfo(): val_resolve_and_check failed - %s",
                p_val_err(rc));
        CTX_UNLOCK_POL(ctx);
        return VAL_DANE_INTERNAL_ERROR;
    }    

    /* Parse results into val_danestatus structure */
    /* 
     * XXX Use struct val_daneparams to filter our results
     */
    dane_rc = get_dane_from_result(ctx,
                                   params,
                                   results, 
                                   dres);
    val_log(ctx, LOG_DEBUG,
            "val_getdaneinfo(): returning %s(%d)", 
            p_dane_error(dane_rc), dane_rc);

    CTX_UNLOCK_POL(ctx);
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

int val_dane_match(val_context_t *context,
                   struct val_danestatus *dane_cur, 
                   const unsigned char *data, 
                   int len)
{
    val_context_t *ctx;

    if (dane_cur == NULL || data == NULL)
        return VAL_DANE_CHECK_FAILED;

    ctx = val_create_or_refresh_context(context);/* does CTX_LOCK_POL_SH */
    if (ctx == NULL)
        return VAL_DANE_INTERNAL_ERROR;

    val_log(ctx, LOG_DEBUG,
            "val_dane_match(): checking for DANE cert match - sel:%d type:%d", 
            dane_cur->selector, dane_cur->type);

    if ((dane_cur->selector != DANE_SEL_FULLCERT) &&
        (dane_cur->selector != DANE_SEL_PUBKEY)) {
        val_log(ctx, LOG_NOTICE,
            "val_dane_match(): Unknown DANE selector:%d",
            dane_cur->selector);
        CTX_UNLOCK_POL(ctx);
        return VAL_DANE_CHECK_FAILED;
    }

    if (dane_cur->type == DANE_MATCH_EXACT) {
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
            if (len == dane_cur->datalen &&
                    !memcmp(data, dane_cur->data, len)) {

                val_log(ctx, LOG_INFO, "val_dane_match(): DANE_SEL_FULLCERT/DANE_MATCH_EXACT success");
                CTX_UNLOCK_POL(ctx);
                return VAL_DANE_NOERROR;
            }

            val_log(ctx, LOG_NOTICE, "val_dane_match(): DANE_SEL_FULLCERT/DANE_MATCH_EXACT failed");
            CTX_UNLOCK_POL(ctx);
            return VAL_DANE_CHECK_FAILED;

        } else {
            int pkeyLen = 0;
            unsigned char *pkeybuf = NULL;

            if (0 != get_pkeybuf(data, len, &pkeyLen, &pkeybuf)) {
                CTX_UNLOCK_POL(ctx);
                return VAL_DANE_CHECK_FAILED;
            }

            if (pkeyLen == dane_cur->datalen &&
                0 == memcmp(pkeybuf, dane_cur->data, pkeyLen)) {

                val_log(ctx, LOG_INFO, "val_dane_match(): DANE_SEL_PUBKEY/DANE_MATCH_EXACT success");
                FREE(pkeybuf);
                CTX_UNLOCK_POL(ctx);
                return VAL_DANE_NOERROR;
            }
            val_log(ctx, LOG_NOTICE, "val_dane_match(): DANE_SEL_PUBKEY/DANE_MATCH_EXACT failed");
            FREE(pkeybuf);
            CTX_UNLOCK_POL(ctx);
            return VAL_DANE_CHECK_FAILED;

        }

    } else if (dane_cur->type == DANE_MATCH_SHA256) {

        unsigned char cert_sha[SHA256_DIGEST_LENGTH];
        memset(cert_sha, 0, SHA256_DIGEST_LENGTH);

        if (dane_cur->selector == DANE_SEL_FULLCERT) {
            SHA256(data, len, cert_sha);
        } else {
            int pkeyLen = 0;
            unsigned char *pkeybuf = NULL;
            if (0 != get_pkeybuf(data, len, &pkeyLen, &pkeybuf)) {
                CTX_UNLOCK_POL(ctx);
                return VAL_DANE_CHECK_FAILED;
            }
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
            val_log(ctx, LOG_INFO, "val_dane_match(): DANE_MATCH_SHA256 success");
            CTX_UNLOCK_POL(ctx);
            return VAL_DANE_NOERROR;
        }
        val_log(ctx, LOG_NOTICE, 
                "val_dane_match(): DANE SHA256 does NOT match (len = %d)", 
                dane_cur->datalen);
        CTX_UNLOCK_POL(ctx);
        return VAL_DANE_CHECK_FAILED;

    } else if (dane_cur->type == DANE_MATCH_SHA512) {

        unsigned char cert_sha[SHA512_DIGEST_LENGTH];
        memset(cert_sha, 0, SHA512_DIGEST_LENGTH);

        if (dane_cur->selector  == DANE_SEL_FULLCERT) {
            SHA512(data, len, cert_sha);
        } else {
            int pkeyLen = 0;
            unsigned char *pkeybuf = NULL;
            if (0 != get_pkeybuf(data, len, &pkeyLen, &pkeybuf)) {
                CTX_UNLOCK_POL(ctx);
                return VAL_DANE_CHECK_FAILED;
            }
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
            val_log(ctx, LOG_INFO, "val_dane_match(): DANE_MATCH_SHA512 success");
            CTX_UNLOCK_POL(ctx);
            return VAL_DANE_NOERROR;
        }
        val_log(ctx, LOG_NOTICE, "val_dane_match(): DANE_MATCH_SHA512 failed");
        CTX_UNLOCK_POL(ctx);
        return VAL_DANE_CHECK_FAILED;

    } 

    val_log(ctx, LOG_NOTICE,
            "val_dane_match(): Error - Unknown DANE type:%d", dane_cur->type);
    CTX_UNLOCK_POL(ctx);
    return VAL_DANE_CHECK_FAILED;
}

static int
val_dane_check_TA(val_context_t *context,
                  X509_STORE_CTX *x509ctx,
                  struct val_danestatus *danestatus,
                  int *do_pkix_chk)

{
    struct val_danestatus *dane_cur = NULL;
    int have_dane = 0;
    unsigned char *cert_data = NULL;
    unsigned char *c = NULL;
    int cert_datalen = 0;
    int rv;
    int i;
    int err;
    int depth;
    STACK_OF(X509) *certList;
    X509 *cert = NULL;

    if (context == NULL || x509ctx == NULL || certList == NULL || 
        danestatus == NULL || do_pkix_chk == NULL)
        return VAL_DANE_CHECK_FAILED;

    err = X509_STORE_CTX_get_error(x509ctx);
    if (err == 0)
        depth = sk_X509_num(certList);
    else
        depth = X509_STORE_CTX_get_error_depth(x509ctx);

    certList = X509_STORE_CTX_get_chain(x509ctx);

    dane_cur = danestatus;
    while(dane_cur)  {
    
        *do_pkix_chk = 1;
        switch (dane_cur->usage) {
            case DANE_USE_TA_ASSERTION: /*2*/
                *do_pkix_chk = 0;
                /* fall-through */
            case DANE_USE_CA_CONSTRAINT: /*0*/ {
                val_log(context, LOG_INFO, 
                    "Checking DANE {sel=%d, type=%d, usage=%d}",
                    dane_cur->selector,
                    dane_cur->type,
                    dane_cur->usage);
                have_dane = 1;
                /* 
                 * Check that the TLSA cert matches one of the certs
                 * in the chain
                 */
                for (i = 0; i <= depth; i++) {
                    cert = sk_X509_value(certList, i);
                    cert_datalen = i2d_X509(cert, NULL);
                    if (cert_datalen > 0) {
                        cert_data = OPENSSL_malloc(cert_datalen);
                        if (cert_data) {
                            c = cert_data;
                            cert_datalen = i2d_X509(cert, &c);
                            if(cert_datalen > 0 &&
                                val_dane_match(context,
                                    dane_cur,
                                    (const unsigned char *)cert_data,
                                    cert_datalen) == 0) {
                                    rv = VAL_DANE_NOERROR;
                                    OPENSSL_free(cert_data);
                                    goto done;
                                }
                            }
                            OPENSSL_free(cert_data);
                        }
                    }
                }
                val_log(context, LOG_NOTICE, 
                        "DANE: val_dane_check_TA() for usage %d failed",
                        dane_cur->usage);
                break;

            default:
                break;
        }

        dane_cur = dane_cur->next;
    }

    if (have_dane)
        rv = VAL_DANE_CHECK_FAILED; 
    else 
        rv = VAL_DANE_NOERROR;

done:
    if (have_dane) {
        if (rv == VAL_DANE_NOERROR)
            val_log(context, LOG_INFO, "DANE check successful");
        else {
            val_log(context, LOG_NOTICE, "DANE check failed");
        }
    }

    return rv;
}

static int 
val_dane_check_EE(val_context_t *context,
                  X509_STORE_CTX *x509ctx,
                  struct val_danestatus *danestatus,
                  int *do_pkix_chk) 
{
    struct val_danestatus *dane_cur = NULL;
    int have_dane = 0;
    unsigned char *cert_data = NULL;
    unsigned char *c = NULL;
    int cert_datalen = 0;
    int rv;
    X509 *cert;

    if (context == NULL || x509ctx == NULL || 
        danestatus == NULL || do_pkix_chk == NULL)
        return VAL_DANE_CHECK_FAILED;

    cert = x509ctx->cert;

    dane_cur = danestatus;
    while(dane_cur)  {
        *do_pkix_chk = 1;
        switch (dane_cur->usage) {
            case DANE_USE_DOMAIN_ISSUED: /*3*/
                *do_pkix_chk = 0;
                /* fall-through */
            case DANE_USE_SVC_CONSTRAINT: /*1*/ 
                val_log(context, LOG_INFO, 
                        "Checking DANE {sel=%d, type=%d, usage=%d}",
                        dane_cur->selector,
                        dane_cur->type,
                        dane_cur->usage);
                have_dane = 1;
                cert_datalen = i2d_X509(cert, NULL);
                if (cert_datalen > 0) {
                    cert_data = OPENSSL_malloc(cert_datalen);
                    if (cert_data) {
                        c = cert_data;
                        cert_datalen = i2d_X509(cert, &c);
                        if(cert_datalen > 0 &&
                                val_dane_match(context,
                                    dane_cur,
                                    (const unsigned char *)cert_data,
                                    cert_datalen) == 0) {
                            val_log(context, LOG_INFO, "DANE: val_dane_match() success");
                            rv = VAL_DANE_NOERROR;
                            OPENSSL_free(cert_data);
                            goto done;
                        }
                        OPENSSL_free(cert_data);
                    }
                }
                val_log(context, LOG_NOTICE, 
                        "DANE: val_dane_check_EE() for usage %d failed",
                        dane_cur->usage);
                break;

            default:
                break;
        }

        dane_cur = dane_cur->next;
    }

    if (have_dane)
        rv = VAL_DANE_CHECK_FAILED; 
    else 
        rv = VAL_DANE_NOERROR;

done:
    if (have_dane) {
        if (rv == VAL_DANE_NOERROR)
            val_log(context, LOG_INFO, "DANE check successful");
        else {
            val_log(context, LOG_NOTICE, "DANE check failed");
        }
    }

    return rv;
}

static int 
val_X509_peer_cert_verify_cb(X509_STORE_CTX *ctx, void *arg)
{
    char    buf[256];           
    struct val_ssl_data *ssl_dane_data;
    int err;
    int do_pkix_chk = 0;

    ssl_dane_data = (struct val_ssl_data *) arg;
    if (ssl_dane_data == NULL)
        return 0;

    X509_NAME_oneline(X509_get_subject_name(ctx->cert), buf, 256);
    printf("DEBUG: val_X509_peer_cert_verify_cb peer subject = %s\n", buf);

    if (VAL_DANE_NOERROR != 
            val_dane_check_EE(ssl_dane_data->context, 
                              ctx,
                              ssl_dane_data->danestatus,
                              &do_pkix_chk))
       return 0; 


    if (do_pkix_chk == 0)
        return 1;

    err=X509_verify_cert(ctx);
    if (err) {
        printf("DEBUG: X509_verify_cert() error = %d\n", err);
        return err;
    }

    /*
     * Check trust anchors
     */
    if (VAL_DANE_NOERROR !=
        val_dane_check_TA(ssl_dane_data->context,
                          ctx,
                          ssl_dane_data->danestatus,
                          &do_pkix_chk))
        return 0;

    err = X509_STORE_CTX_get_error(ctx);
    if (err) {
        if (do_pkix_chk == 0) {
            /* reset err status */
            // XXX TODO Only reset the error for certain error conditions
            // XXX TODO Need to determine what these error conditions
            X509_STORE_CTX_set_error(ctx, X509_V_OK);
            return 1;
        }
        return 0;
    }

    return 1;
}

/*
 * NOTE: This does a CTX_LOCK
 */
int
val_enable_dane_ssl(val_context_t *context,
                    SSL_CTX *sslctx,
                    struct val_danestatus **danestatus,
                    struct val_ssl_data **ssl_dane_data)
{
    int ret = VAL_NO_ERROR;

    if (context == NULL || sslctx == NULL || 
        danestatus == NULL || ssl_dane_data == NULL)
        return VAL_BAD_ARGUMENT;


    *ssl_dane_data = (struct val_ssl_data *)MALLOC(sizeof(struct val_ssl_data));
    if (*ssl_dane_data == NULL) {
        return VAL_OUT_OF_MEMORY;
    }

    if (*danestatus == NULL) {
        /* Lookup DANE information if we don't already have it */
        SSL *con;
        BIO *bio;
        char *node;
        struct val_daneparams daneparams;

        bio = SSL_get_wbio(con);
        node = BIO_get_conn_hostname(bio);
        memset(&daneparams, 0, sizeof(daneparams));
        daneparams.port = atoi(BIO_get_conn_port(bio));
        daneparams.proto = DANE_PARAM_PROTO_TCP;

        ret = val_getdaneinfo(context, node, &daneparams, 
                              danestatus);

        if (ret == VAL_DANE_IGNORE_TLSA) {
            return VAL_NO_ERROR;
        } 
        
        if (ret != VAL_NO_ERROR) {
            goto err;
        }
    }

    (*ssl_dane_data)->context = context;
    (*ssl_dane_data)->danestatus = *danestatus;

    /*
     * Callback from EE cert validation
     */ 
    SSL_CTX_set_cert_verify_callback(sslctx, 
                                     val_X509_peer_cert_verify_cb,
                                     (void *)(*ssl_dane_data));

err:
    return ret;

}

void
val_free_dane_ssl(struct val_ssl_data *ssl_dane_data)
{
    if (ssl_dane_data == NULL)
        return;

    CTX_UNLOCK_POL(ssl_dane_data->context);
    FREE(ssl_dane_data);
}
