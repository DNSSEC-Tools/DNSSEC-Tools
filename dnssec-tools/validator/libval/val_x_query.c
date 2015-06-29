
/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

/*
 * DESCRIPTION
 * Contains implementation of the val_res_query and val_search 
 * functions, and their helpers.
 */

#include "validator-internal.h"

#include "val_cache.h"
#include "val_support.h"
#include "val_assertion.h"
#include "val_context.h"

#define OUTER_HEADER_LEN (sizeof(HEADER) + wire_name_length(name_n) + sizeof(u_int16_t) + sizeof(u_int16_t))


/*
 * Calculate rrset length 
 */
static size_t
find_rrset_len(struct val_rrset_rec *rrset)
{
    struct val_rr_rec  *rr;
    size_t resp_len = 0;
    size_t rrset_name_n_len;
    u_char name_n[NS_MAXCDNAME];

    if (rrset == NULL)
        return 0;

    if (ns_name_pton(rrset->val_rrset_name, name_n, sizeof(name_n)) == -1) {
        return 0;
    }
    rrset_name_n_len = wire_name_length(name_n);

    /* data */
    for (rr = rrset->val_rrset_data; rr; rr = rr->rr_next) {
        resp_len +=
            rrset_name_n_len + sizeof(u_int16_t) + sizeof(u_int16_t) +
            sizeof(u_int32_t)
            + sizeof(u_int16_t) + rr->rr_rdata_length;
    }
    /* signatures */
    for (rr = rrset->val_rrset_sig; rr; rr = rr->rr_next) {
        resp_len +=
            rrset_name_n_len + sizeof(u_int16_t) + sizeof(u_int16_t) +
            sizeof(u_int32_t)
            + sizeof(u_int16_t) + rr->rr_rdata_length;
    }
    return resp_len;
}

/* 
 * determine the size of the response from individual rrsets
 */  
static size_t
determine_size(struct val_result_chain *res)
{
    size_t resp_len = 0;

    if (res == NULL)
        return 0;
    
    if (res->val_rc_rrset) {
        resp_len += find_rrset_len(res->val_rc_rrset);
    }
    if (res->val_rc_proof_count) {
        int             i;
        for (i = 0; i < res->val_rc_proof_count; i++) {
            if (res->val_rc_proofs[i])
                resp_len +=
                    find_rrset_len(res->val_rc_proofs[i]->val_ac_rrset);
        }
    }
    return resp_len;
}


/*
 * Update the response buffer with the contents of an rrset.
 *
 * Update one of anbuf, nsbuf and arbuf depending on whether
 * the rrset was present in the answer, authority or additional
 * section.
 *
 * Returns 0 on success and -1 on error
 */
static int
encode_response_rrset(struct val_rrset_rec *rrset,
                      val_status_t val_rc_status,
                      size_t resp_len,
                      u_char **anbuf,
                      size_t *anbufindex,
                      size_t *ancount,
                      u_char **nsbuf,
                      size_t *nsbufindex,
                      size_t *nscount,
                      u_char **arbuf,
                      size_t *arbufindex,
                      size_t *arcount, 
                      int *an_auth, 
                      int *ns_auth)
{
    u_char  *cp;
    size_t *bufindex = NULL;
    struct val_rr_rec  *rr;
    size_t rrset_name_n_len;
    size_t *count;
    u_int16_t class_h, type_h;
    u_int32_t ttl_h;
    u_char name_n[NS_MAXCDNAME];

    if (rrset == NULL)
        return 0;

    /* 
     * Sanity check the values of class and type 
     * Should not be larger than sizeof u_int16_t
     */
    if (rrset->val_rrset_class < 0 || rrset->val_rrset_type < 0 || 
        rrset->val_rrset_type > ns_t_max || rrset->val_rrset_class > ns_c_max ||
        rrset->val_rrset_ttl < 0) {
        return 0;
    } 

    if (ns_name_pton(rrset->val_rrset_name, name_n, sizeof(name_n)) == -1) {
        return 0;
    }

    rrset_name_n_len = wire_name_length(name_n);
    class_h = (u_int16_t) rrset->val_rrset_class;
    type_h = (u_int16_t) rrset->val_rrset_type;
    ttl_h = (u_int32_t) rrset->val_rrset_ttl;
    

    /** other inputs are checked by the calling method **/
    
    if (rrset->val_rrset_section == VAL_FROM_ANSWER) {
        cp = *anbuf + *anbufindex;
        bufindex = anbufindex;
        count = ancount;
        if (!val_istrusted(val_rc_status)) {
            *an_auth = 0;
        }
    } else if (rrset->val_rrset_section == VAL_FROM_AUTHORITY) {
        cp = *nsbuf + *nsbufindex;
        bufindex = nsbufindex;
        count = nscount;
        if (!val_istrusted(val_rc_status)) {
            *ns_auth = 0;
        }
    } else {                    /* VAL_FROM_ADDITIONAL */
        cp = *arbuf + *arbufindex;
        bufindex = arbufindex;
        count = arcount;
    }

    /*
     * Answer/Authority/Additional section 
     */
    /* for each data */
    for (rr = rrset->val_rrset_data; rr; rr = rr->rr_next) {

        u_int16_t rr_data_length_n = (u_int16_t)rr->rr_rdata_length;
        if (rr->rr_rdata_length > rr_data_length_n)
            return -1;
        if ((*bufindex + rrset_name_n_len + 10 +
             rr_data_length_n) > resp_len) {
            /** log error message?  */
            return -1;
        }

        (*count)++;

        memcpy(cp, name_n, rrset_name_n_len);
        cp += rrset_name_n_len;

        NS_PUT16(type_h, cp);
        NS_PUT16(class_h, cp);
        NS_PUT32(ttl_h, cp);
        NS_PUT16(rr_data_length_n, cp);
        memcpy(cp, rr->rr_rdata, rr_data_length_n);
        cp += rr_data_length_n;

    }  
    /* for each rrsig */
    for (rr = rrset->val_rrset_sig; rr; rr = rr->rr_next) {

        u_int16_t rr_data_length_n = (u_int16_t)rr->rr_rdata_length;
        if (rr->rr_rdata_length > rr_data_length_n)
            return -1;

        if ((*bufindex + rrset_name_n_len + 10 +
             rr_data_length_n) > resp_len) {
            /** log error message?  */
            return -1;
        }

        (*count)++;

        memcpy(cp, name_n, rrset_name_n_len);
        cp += rrset_name_n_len;
        NS_PUT16(ns_t_rrsig, cp);
        NS_PUT16(class_h, cp);
        NS_PUT32(ttl_h, cp);
        NS_PUT16(rr_data_length_n, cp);
        memcpy(cp, rr->rr_rdata, rr_data_length_n);
        cp += rr_data_length_n;

    }                           // end for each rr

    *bufindex += find_rrset_len(rrset);
    if (*bufindex > resp_len) {
        /** log error message?  */
        return -1;
    }

    return 0;
}

/*
 * Function: compose_answer
 *
 * Purpose: Convert the list of val_result_chain structures returned 
 *          by the validator into a linked list of val_response structures
 *
 * Parameters:
 *              name_n -- The domain name.
 *              type_h -- The DNS type.
 *             class_h -- The DNS class.
 *             results -- A linked list of val_result_chain structures returned
 *                        by the validator's val_resolve_and_check function.
 *                resp -- The structures within which answers are to be returned 
 * Return value: VAL_NO_ERROR on success, and a negative valued error code 
 *               (see val_errors.h) on failure.
 */

int
compose_answer(const char * name,
               int type_h,
               int class_h,
               struct val_result_chain *results,
               struct val_response *f_resp)
{
    struct val_result_chain *res = NULL;
    size_t ancount = 0;        // Answer Count
    size_t nscount = 0;        // Authority Count
    size_t arcount = 0;        // Additional Count
    size_t anbufindex = 0, nsbufindex = 0, arbufindex = 0;
    u_char  *anbuf = NULL, *nsbuf = NULL, *arbuf = NULL;
    int an_auth = 1;
    int ns_auth = 1;
    u_char  *rp = NULL;
    size_t          resp_len = 0;
    HEADER         *hp = NULL;
    size_t          len;
    int             retval;
    u_char name_n[NS_MAXCDNAME];
    u_int16_t class_n, type_n;

    struct val_rrset_rec *rrset;
    int validated = 1;
    int trusted = 1;

    SET_LAST_ERR(0);

    ancount = 0;
    nscount = 0;
    arcount = 0;
    anbufindex = 0;
    nsbufindex = 0;
    arbufindex = 0;
    anbuf = NULL;
    nsbuf = NULL;
    arbuf = NULL;
    an_auth = 1;
    ns_auth = 1;

    rp = NULL;
    resp_len = 0;

    retval = VAL_NO_ERROR;
    //SET_LAST_ERR(NETDB_INTERNAL);
    SET_LAST_ERR(NO_RECOVERY);
    
    if ((f_resp == NULL) || (name == NULL))
        return VAL_BAD_ARGUMENT;

    memset(f_resp, 0, sizeof(struct val_response));

    /* 
     * Sanity check the values of class and type 
     * Should not be larger than sizeof u_int16_t
     */
    if (class_h < 0 || type_h < 0 || 
        type_h > ns_t_max || class_h > ns_c_max) {
        return VAL_BAD_ARGUMENT;
    } 
    class_n = (u_int16_t) class_h;
    type_n = (u_int16_t) type_h;

    if ((retval = ns_name_pton(name, name_n, sizeof(name_n))) == -1) {
        return VAL_BAD_ARGUMENT;
    }

    for (res = results; res; res = res->val_rc_next) {
        resp_len += determine_size(res);
    }

    f_resp->vr_val_status = VAL_UNTRUSTED_ANSWER;
    f_resp->vr_length = (resp_len + OUTER_HEADER_LEN);
    f_resp->vr_response = (u_char *) MALLOC(f_resp->vr_length *
                                     sizeof(u_char));
    if (f_resp->vr_response == NULL) {
            f_resp->vr_length = 0;
            return VAL_OUT_OF_MEMORY;
    }
    memset(f_resp->vr_response, 0, f_resp->vr_length * sizeof(u_char));
    
    /*
     * Header 
     */
    rp = f_resp->vr_response;
    hp = (HEADER *) rp;
    memset(hp, 0, sizeof(HEADER));
    rp += sizeof(HEADER);

    /*
     * Question section 
     */
    len = wire_name_length(name_n);
    memcpy(rp, name_n, len);
    rp += len;
    NS_PUT16(type_n, rp);
    NS_PUT16(class_n, rp);
    hp->qdcount = htons(1);

    if (results == NULL) {
        return VAL_NO_ERROR;
    }

    /*
     * temporary buffers for different sections 
     */
    anbuf = (u_char *) MALLOC(resp_len * sizeof(u_char));
    nsbuf = (u_char *) MALLOC(resp_len * sizeof(u_char));
    arbuf = (u_char *) MALLOC(resp_len * sizeof(u_char));
    if ((anbuf == NULL) || (nsbuf == NULL) || (arbuf == NULL)) {
        if (anbuf)
            FREE(anbuf);
        if (nsbuf)
            FREE(nsbuf);
        if (arbuf)
            FREE(arbuf);
        return VAL_OUT_OF_MEMORY;
    }


    for (res = results; res; res = res->val_rc_next) {

        f_resp->vr_val_status = res->val_rc_status;

        /* set the value of merged trusted and validated status values */
        if (!(validated && val_isvalidated(res->val_rc_status))) 
            validated = 0;
        if (!(trusted && val_istrusted(res->val_rc_status))) 
            trusted = 0;

        if (res->val_rc_rrset) {
            rrset = res->val_rc_rrset;
            if (-1 ==
                encode_response_rrset(rrset,
                                      res->val_rc_status, resp_len,
                                      &anbuf, &anbufindex, &ancount,
                                      &nsbuf, &nsbufindex, &nscount,
                                      &arbuf, &arbufindex, &arcount,
                                      &an_auth, &ns_auth)) {
                retval = VAL_BAD_ARGUMENT;
                goto err;
            }
        } 

        if (res->val_rc_proof_count) {
            int             i;
            for (i = 0; i < res->val_rc_proof_count; i++) {
                rrset = res->val_rc_proofs[i]->val_ac_rrset;
                if (-1 ==
                    encode_response_rrset(rrset,
                                          res->val_rc_status,
                                          resp_len, &anbuf, &anbufindex,
                                          &ancount, &nsbuf, &nsbufindex,
                                          &nscount, &arbuf, &arbufindex,
                                          &arcount, &an_auth, &ns_auth)) {
                    retval = VAL_BAD_ARGUMENT;
                    goto err;
                }
            }
        }

        hp->ad = trusted ? 1:0; 

        hp->ancount = htons(ancount);
        hp->nscount = htons(nscount);
        hp->arcount = htons(arcount);

        switch (res->val_rc_status) {
            case VAL_NONEXISTENT_TYPE:
            case VAL_NONEXISTENT_TYPE_NOCHAIN: 
                hp->rcode = ns_r_noerror;
		        SET_LAST_ERR(NO_DATA);
                break;

            case VAL_NONEXISTENT_NAME:
            case VAL_NONEXISTENT_NAME_NOCHAIN: 
                hp->rcode = ns_r_nxdomain;
                SET_LAST_ERR(HOST_NOT_FOUND);
                break;

            case VAL_DNS_ERROR: 
                hp->rcode = ns_r_servfail;
                SET_LAST_ERR(TRY_AGAIN);
                break;
                
            default:
                if (hp->ancount > 0) {
                    hp->rcode = ns_r_noerror;
                    SET_LAST_ERR(NETDB_SUCCESS);
                }
                else {
                    hp->rcode = ns_r_nxdomain;
                    SET_LAST_ERR(NO_DATA);
                }
                break;
        }
    }

    if (anbuf) {
        memcpy(rp, anbuf, anbufindex);
        rp += anbufindex;
    }

    if (nsbuf) {
        memcpy(rp, nsbuf, nsbufindex);
        rp += nsbufindex;
    }

    if (arbuf) {
        memcpy(rp, arbuf, arbufindex);
        rp += arbufindex;
    }
    FREE(anbuf);
    FREE(nsbuf);
    FREE(arbuf);

    /* 
     * we lose a level of granularity in the validation status
     * when we do a "merge"
     */
    if (validated)
        f_resp->vr_val_status = VAL_VALIDATED_ANSWER;
    else if (trusted)
        f_resp->vr_val_status = VAL_TRUSTED_ANSWER;
    else
        f_resp->vr_val_status = VAL_UNTRUSTED_ANSWER;

    return VAL_NO_ERROR;

  err:
    FREE(anbuf);
    FREE(nsbuf);
    FREE(arbuf);
    FREE(f_resp->vr_response);
    f_resp->vr_response = NULL;
    f_resp->vr_length = 0;
    f_resp->vr_val_status = VAL_UNTRUSTED_ANSWER;

    return retval;

}

/*
 * This routine is provided for compatibility with programs that 
 * depend on the res_query() function. 
 */
/*
 * Function: val_res_query
 *
 * Purpose: A DNSSEC-aware function intended as a replacement to res_query().
 *
 * This routine makes a query for {domain_name, type, class} and returns the 
 * result in resp. 
 * The result of validation for a particular resource record is available in
 * the val_status field of the val_response structure.
 *
 * Parameters:
 * ctx -- The validation context.  May be NULL for default value.
 * domain_name -- The domain name to be queried.  Must not be NULL.
 * class -- The DNS class (typically IN)
 * type  -- The DNS type  (for example: A, CNAME etc.)
 * 
 */
int
val_res_query(val_context_t * context, 
              const char *dname, 
              int class_h,
              int type, 
              u_char * answer, 
              int anslen,
              val_status_t * val_status)
{
    struct val_response resp;
    int    retval = VAL_NO_ERROR;
    size_t bytestocopy = 0;
    size_t totalbytes = 0;
    HEADER *hp = NULL;
    struct val_result_chain *results;
    val_context_t *ctx = NULL;

    if (dname == NULL || val_status == NULL || answer == NULL) { 
        goto err;
    }
        
    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL)
        goto err;
    
    val_log(ctx, LOG_DEBUG,
            "val_res_query(): called with dname=%s, class=%s, type=%s",
            dname, p_class(class_h), p_type(type));

    /*
     * Query the validator 
     */
    if (VAL_NO_ERROR ==
        (retval =
         val_resolve_and_check(ctx, dname, class_h, type, 
                        0, &results))) {
        /*
         * Construct the answer response in resp 
         */
        retval =
            compose_answer(dname, type, class_h, results, &resp);

        val_free_result_chain(results);
        results = NULL;
    }

    CTX_UNLOCK_POL(ctx);

    if (retval != VAL_NO_ERROR) {
        goto err;
    }
    
    totalbytes = resp.vr_length;

    bytestocopy = (resp.vr_length > anslen) ? anslen : resp.vr_length;
    memcpy(answer, resp.vr_response, bytestocopy);
    *val_status = resp.vr_val_status;
    FREE(resp.vr_response);

    hp = (HEADER *) answer;
    if (!hp || (hp->rcode != ns_r_noerror) || hp->ancount <= 0) {
        return -1;
    }

    return totalbytes;

err:
    val_log(ctx, LOG_ERR, "val_res_query(%s, %d, %d): Error - %s", 
            dname, p_class(class_h), p_type(type), p_val_err(retval));
    //SET_LAST_ERR(NETDB_INTERNAL);
    SET_LAST_ERR(NO_RECOVERY);
    errno = EINVAL;
    return -1;
}

/*
 * wrapper around val_res_query() that is closer to res_search() 
 */
int
val_res_search(val_context_t * context, const char *dname, int class_h,
              int type, u_char * answer, int anslen,
              val_status_t * val_status)
{
    int             retval = -1;
    char           *dot, *search, *pos;
    char            buf[NS_MAXDNAME];
    int             last_err;
    val_context_t *ctx = NULL;
    SET_LAST_ERR(NO_RECOVERY);
    //SET_LAST_ERR(NETDB_INTERNAL);
    
    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    val_log(ctx, LOG_DEBUG,
            "val_res_query(): called with dname=%s, class=%s, type=%s",
            dname, p_class(class_h), p_type(type));

    if ((dname == NULL) || (val_status == NULL) || (answer == NULL)) {
        val_log(ctx, LOG_ERR, "val_res_search(%s, %d, %d): Error - %s", 
            dname, p_class(class_h), p_type(type), p_val_err(VAL_BAD_ARGUMENT));
        errno = EINVAL;
        retval = -1;
        goto done;
    }

    /*
     * if there are no dots and we have a search path, use it
     */
    dot = strchr(dname, '.');
    if ( (NULL == dot) && ctx->search) {

        /** dup list so we can modify it */
        char *save = search = strdup(ctx->search);

        while (search) {

            /*
             * search path should be space/tab separated list.
             */
            pos = search;
            while (*pos && *pos != ' ' && *pos != '\t')
                ++pos;
            if (*pos)
                *pos++ = 0;
            
            snprintf(buf, sizeof(buf), "%s.%s", dname, search);
            retval = val_res_query(ctx, buf, class_h, type, answer, anslen,
                                   val_status);
            /*
             * Continue looping if we don't have a valid result
             * and we haven't run into any hard error.
             */
            if (retval < 0) {
                last_err = GET_LAST_ERR();
                if (last_err != HOST_NOT_FOUND &&/* name does not exist */
                    last_err != TRY_AGAIN) {/* DNS error */
                    if (save)
                        free(save);
                    goto done;
                }
                /* need to re-try */
            } else {
                /* success */
                if (save)
                    free(save);
                goto done;
            }

            if (*pos)
                search = pos;
            else
                break;
        }
        if (save)
            free(save);
    }
    
    /** try dname as-is */
    retval = val_res_query(ctx, dname, class_h, type, answer, anslen,
                           val_status);

done:
    CTX_UNLOCK_POL(ctx);

    return retval;
}
