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

static int
clone_danestatus(struct val_danestatus *dstatus,
                 struct val_danestatus **dstatus_p)
{
    struct val_danestatus *dcur = NULL;
    struct val_danestatus *dtail = NULL;
    struct val_danestatus *dnew = NULL;

    if (dstatus == NULL || dstatus_p == NULL)
        return VAL_BAD_ARGUMENT;

    *dstatus_p = NULL;
    dcur = dstatus;

    while (dcur) {

        dnew = (struct val_danestatus *) MALLOC (sizeof (struct
                    val_danestatus));
        if (dnew == NULL)
            goto err;

        dnew->ttl = dcur->ttl;
        dnew->usage = dcur->usage;
        dnew->selector = dcur->selector;
        dnew->type = dcur->type;
        dnew->datalen = dcur->datalen;
        dnew->data = (unsigned char *) MALLOC (dcur->datalen *
                sizeof(unsigned char));
        if (dnew->data == NULL) {
            FREE(dnew);
            goto err;
        }
        memcpy(dnew->data, dcur->data, dcur->datalen);
        dnew->next = NULL;
        if (dtail) {
            dtail->next = dnew;
        } else {
            *dstatus_p = dnew;
        }
        dtail = dnew;
        dcur = dcur->next;
    }

    return VAL_NO_ERROR;

err:
    val_free_dane(*dstatus_p);
    *dstatus_p = NULL;
    return VAL_OUT_OF_MEMORY;
}

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
         * Ensure that all records (including aliases) are validated.
         */
        if (!val_isvalidated(res->val_rc_status))
            validated = 0;

        /* 
         * skip the aliases 
         */
        if (res->val_rc_alias) {
            continue;
        }

        /* 
         * provably non-existence does not imply error 
         */
        if (val_does_not_exist(res->val_rc_status))
            return VAL_DANE_IGNORE_TLSA;

        /* 
         * and neither does provably insecure conditions 
         */
        if (res->val_rc_status == VAL_PINSECURE)
            return VAL_DANE_IGNORE_TLSA;

        /* 
         * We're now about to process the DANE record
         * DANE resource records MUST be validated 
         */
        if (!validated)
            return VAL_DANE_NOTVALIDATED;

        rrset = res->val_rc_rrset;
        if(rrset && rrset->val_rrset_type == ns_t_tlsa) {
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
int get_pkeybuf(X509 *cert, int *pkeyLen, unsigned char **pkeybuf)
{
    EVP_PKEY *pkey;
    int rv = 0;

    if (cert == NULL || pkeyLen == NULL || pkeybuf == NULL)
        return -1;

    *pkeyLen = 0;
    *pkeybuf = NULL;

    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
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
    return rv;
}


/*
 * check if the qname matches any of the names provided in the given
 * string array. Wildcards of the form *.name can also match as long as
 * name is a substring within qname.
 */
static int
do_cert_namechk(val_context_t *context,
        char *qname, X509 *cert)
{
    int num;
    int i;

    GENERAL_NAMES *saNames = NULL;
    GENERAL_NAME *cur = NULL;
    X509_NAME *subj = NULL;
    int retval = 1;
    ASN1_STRING *astr;
    char *cp;

    if (qname == NULL || cert == NULL)
        return 0;

    /*
     * XXX This should be replaced with X509_check_host() at some point
     */

    /* compare against subject alt names */
    saNames = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (saNames) {
        num = sk_GENERAL_NAME_num(saNames); 
        for (i=0; i<num; i++) {
            cur = sk_GENERAL_NAME_value(saNames, i);
            if (cur->type == GEN_DNS) {
                astr = cur->d.dNSName;
                cp = (char *)astr->data;

                /* check for exact match or wildcard match */
                if (cp &&
                    ((!strcmp(cp, qname)) ||
                     (*cp == '*' && *(cp+1) == '.' && 
                                strstr(qname, cp+2)))) {
                    retval = 1;
                    goto done;
                }
                else {
                    retval = 0;
                    /* keep trying */
                }
            }
        }
    }

    /* compare against subject name */
    subj = X509_get_subject_name(cert);
    i = -1;
    while ((i = X509_NAME_get_index_by_NID(subj, NID_commonName, i)) >=0) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(subj, i);
        astr = X509_NAME_ENTRY_get_data(entry);
        cp = (char *)astr->data;

        /* check for exact match or wildcard match */
        if (cp &&
            ((!strcmp(cp, qname)) ||
              (*cp == '*' && *(cp+1) == '.' && 
                  strstr(qname, cp+2)))) {
            retval = 1;
            goto done;
        } else {
            retval = 0;
            /* keep trying */
        }
    }


done:
    if (saNames) {
        //sk_GENERAL_NAME_pop_free(saNames, GENERAL_NAME_free);
        GENERAL_NAMES_free(saNames);
    }

    return retval;
}

/*
 * Do certificate name checks for DER encoded Cert
 */

int 
val_dane_cert_namechk(val_context_t *context,
                   char *qname,
                   const unsigned char *data, 
                   int len) 
{
    X509 *cert;
    const unsigned char *tmp = data;
    int ret;

    if (data == NULL)
        return 0;

    cert = d2i_X509(NULL, &tmp, len);
    if (cert == NULL)
        return 0;

    ret = do_cert_namechk(context, qname, cert);

    X509_free(cert);

    return ret;
}

/*
 * Matches a DANE record against the correct part of a key, either in
 * raw or a calculated hash of the part.
 */
static int 
val_dane_match_internal(val_context_t *context,
                           struct val_danestatus *dane_cur, 
                           const unsigned char *data,
                           int len,
                           X509 *cert)
{
    val_context_t *ctx;

    if (cert == NULL || data == NULL || len <= 0 || dane_cur == NULL)
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

            if (0 != get_pkeybuf(cert, &pkeyLen, &pkeybuf)) {
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
            if (0 != get_pkeybuf(cert, &pkeyLen, &pkeybuf)) {
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
            if (0 != get_pkeybuf(cert, &pkeyLen, &pkeybuf)) {
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

/*
 * Match DER encoded certificate 
 */
int val_dane_match(val_context_t *context,
                   struct val_danestatus *dane_cur, 
                   const unsigned char *data, 
                   int len) 
{
    X509 *cert;
    const unsigned char *tmp = data;
    int ret;

    if (data == NULL)
        return 0;

    cert = d2i_X509(NULL, &tmp, len);
    if (cert == NULL)
        return 0;

    ret = val_dane_match_internal(context, dane_cur, 
                                  data, len, cert);


    X509_free(cert);

    return ret;
}

static int 
val_X509_peer_cert_verify_cb(X509_STORE_CTX *x509ctx, void *arg)
{
    char    buf[256];           
    struct val_ssl_data *ssl_dane_data;
    int err;
    int i;
    X509 *cert;
    val_context_t *context;
    struct val_danestatus *dane_cur = NULL;
    int depth = -1;
    STACK_OF(X509) *certList = NULL;
    int pkix_succeeded = 0;
    int rv = VAL_DANE_CHECK_FAILED;
    int cert_datalen = 0;
    unsigned char *cert_data = NULL;
    unsigned char *c = NULL;

    ssl_dane_data = (struct val_ssl_data *) arg;
    if (x509ctx == NULL || ssl_dane_data == NULL)
        return 0;

    cert = x509ctx->cert;
    context = ssl_dane_data->context;

    /* 
     * look-ahead to see if we have any DANE record that requires PKIX
     * validation. If so go ahead and do the PKIX validation
     */
    depth = -1;
    certList = NULL;
    pkix_succeeded = 0;

    if(ssl_dane_data->danestatus == NULL) { 
        return X509_verify_cert(x509ctx);
    }

    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));

    /* 
     * Do PKIX checks only if we need to.
     * PKIX checks requried for all types except DANE_USE_DOMAIN_ISSUED 
     */
    for (dane_cur = ssl_dane_data->danestatus; dane_cur; 
            dane_cur = dane_cur->next) {

        if(dane_cur->usage != DANE_USE_DOMAIN_ISSUED) {

            pkix_succeeded = X509_verify_cert(x509ctx);
            err = X509_STORE_CTX_get_error(x509ctx);
            /*
             * Only bypass errors related to cert issuer
             */
            if (err != X509_V_OK &&
                err != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT && 
                err != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY &&
                err != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT &&
                err != X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ) {

                val_log(context,
                        LOG_INFO, "DANE: cert PKIX verification failed = %s", buf);
                return 0;
            }

            certList = X509_STORE_CTX_get_chain(x509ctx);
            depth = sk_X509_num(certList);
            if (depth <= 0 ||
                (!pkix_succeeded && 
                    --depth != X509_STORE_CTX_get_error_depth(x509ctx))) {

                /*
                 * All of the above error conditions should occur at the
                 * end of the PKIX validation chain.  If this assumption
                 * does not hold return an error condition.
                 *
                 * Note that I am making the following assumptions: 
                 *
                 * 1) that the error returned from
                 *    X509_STORE_CTX_get_error corresponds to the
                 *    "closest" error (moving from the peer cert to the
                 *    TA); i.e.  there are no other error conditions
                 *    between depth 0 and X509_STORE_CTX_get_error_depth
                 * 2) Other verification checks on this cert have passed;
                 *    else the error condition would have been
                 *    overridden by the other (more serious) error
                 *    condition. It appears from
                 *    openssl/crypto/x509/x509_vfy.c that this is the
                 *    case, but I could be wrong.
                 * 
                 * If we realize that this understanding of the openssl
                 * code is wrong we should disable DANE usage
                 * type 2 till we come up with an alternative approach
                 * for supporting TA assertion.
                 */
                val_log(context,
                        LOG_WARNING, "DANE: BADSTATE X509 error depth different from cert length = %s", buf);
                return 0;
            }

            /* we only need to do PKIX checks once */
            break;
        }
    }

    /* 
     * We've either completed PKIX checks or we only have TLSA records
     * of type DANE_USE_DOMAIN_ISSUED (in which case PKIX checks are not
     * necessary)
     */

    /*
     * Do certificate name checks
     */
    if (!do_cert_namechk(context, ssl_dane_data->qname, cert)) {
        val_log(context,
                LOG_WARNING, "DANE: Cert namecheck failed for %s", buf);
        return 0;
    }


    dane_cur = ssl_dane_data->danestatus;

    if (((cert_datalen = i2d_X509(cert, NULL)) <= 0) ||
         ((cert_data = OPENSSL_malloc(cert_datalen)) == NULL) ||
         (((c = cert_data)) && (cert_datalen = i2d_X509(cert, &c)) <= 0)) {

        if (cert_data)
            OPENSSL_free(cert_data);
        return 0;
    } 

    /*
     * Keep looking for a good TLSA match
     */
    while(dane_cur)  {
        val_log(context, LOG_INFO, 
               "Checking DANE {sel=%d, type=%d, usage=%d}",
               dane_cur->selector,
               dane_cur->type,
               dane_cur->usage);

        switch (dane_cur->usage) {
            case DANE_USE_SVC_CONSTRAINT: /*1*/ 
                /* PKIX checks must pass */
                if (!pkix_succeeded) {
                    val_log(context,
                            LOG_INFO, "DANE: cert PKIX verification failed = %s", buf);
                   break; 
                }
                /* fall through */
            case DANE_USE_DOMAIN_ISSUED: /*3*/
                if (val_dane_match_internal(context,
                        dane_cur, cert_data, cert_datalen, cert) == 0) {
                    val_log(context, LOG_INFO, 
                            "DANE: passed EE certificate checks = %s", buf);
                    rv = VAL_DANE_NOERROR;
                    goto done;
                }
                break;

            case DANE_USE_CA_CONSTRAINT: /*0*/ 
                /* PKIX checks must pass */
                if (!pkix_succeeded) {
                    val_log(context,
                            LOG_INFO, "DANE: cert PKIX verification failed = %s", buf);
                   break; 
                }
                /* fall through */
            case DANE_USE_TA_ASSERTION: /*2*/
                /* 
                 * Check that the TLSA cert matches one of the certs
                 * in the chain
                 */
                for (i = 0; i <= depth; i++) {
                    cert = sk_X509_value(certList, i);
                    if (val_dane_match_internal(context,
                            dane_cur, cert_data, cert_datalen, cert) == 0) {
                        /* reset err status */
                        val_log(context, 
                                LOG_INFO, "DANE: skipping TA PKIX validation = %s", buf);
                        rv = VAL_DANE_NOERROR;
                        goto done;
                    }
                }
                break;

            default:
                break;
        }

        val_log(context, LOG_INFO, 
                "DANE: check for usage %d failed", dane_cur->usage);

        dane_cur = dane_cur->next;
    }

done:

    if (cert_data)
        OPENSSL_free(cert_data);

    if (rv == VAL_DANE_NOERROR) {
        val_log(context, LOG_INFO, "DANE check successful");
        X509_STORE_CTX_set_error(x509ctx, X509_V_OK);
        return 1;
    }

    val_log(context, LOG_NOTICE, "DANE check failed");
    return 0;
}

/*
 * NOTE: This does a CTX_LOCK
 */
int
val_enable_dane_ssl(val_context_t *ctx,
                    SSL_CTX *sslctx,
                    char *qname,
                    struct val_danestatus *danestatus,
                    struct val_ssl_data **ssl_dane_data)
{
    val_context_t *context = NULL;
    int ret = VAL_NO_ERROR;
    struct val_danestatus *danestatus_p = NULL;

    if (sslctx == NULL || ssl_dane_data == NULL || 
            danestatus == NULL || qname == NULL)
        return VAL_BAD_ARGUMENT;

    context = val_create_or_refresh_context(ctx);/* does CTX_LOCK_POL_SH */
    if (context == NULL)
        return VAL_OUT_OF_MEMORY;

    *ssl_dane_data = (struct val_ssl_data *)MALLOC(sizeof(struct val_ssl_data));
    if (*ssl_dane_data == NULL) {
        CTX_UNLOCK_POL(context);
        return VAL_OUT_OF_MEMORY;
    }

    (*ssl_dane_data)->qname = STRDUP(qname);
    if ((*ssl_dane_data)->qname == NULL) {
        FREE(*ssl_dane_data);
        CTX_UNLOCK_POL(context);
        return VAL_OUT_OF_MEMORY;
    }

    if (VAL_NO_ERROR != (ret = clone_danestatus(danestatus, &danestatus_p))) {
        FREE((*ssl_dane_data)->qname);
        FREE(*ssl_dane_data);
        CTX_UNLOCK_POL(context);
        return ret;
    }

    (*ssl_dane_data)->danestatus = danestatus_p;
    (*ssl_dane_data)->context = context;

    /*
     * Callback from EE cert validation
     */ 
    SSL_CTX_set_cert_verify_callback(sslctx, 
                                     val_X509_peer_cert_verify_cb,
                                     (void *)(*ssl_dane_data));
    /*
     * Don't call CTX_UNLOCK_POL since we release the lock only when we
     * free ssl_dane_data
     */

    return VAL_NO_ERROR;
}

void
val_free_dane_ssl(struct val_ssl_data *ssl_dane_data)
{
    if (ssl_dane_data == NULL)
        return;

    FREE(ssl_dane_data->qname);
    val_free_dane(ssl_dane_data->danestatus);
    CTX_UNLOCK_POL(ssl_dane_data->context);
    FREE(ssl_dane_data);
}
