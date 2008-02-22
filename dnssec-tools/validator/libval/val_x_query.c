
/*
 * Copyright 2005-2007 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

/*
 * DESCRIPTION
 * Contains implementation of the val_query, val_res_query and val_search 
 * functions, and their helpers.
 */

#include "validator-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <netinet/in.h>
#include <resolv.h>
#include <errno.h>

#include <validator/resolver.h>
#include <validator/validator.h>
#include <validator/validator-internal.h>
#ifndef NAMESER_HAS_HEADER
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#else
#include "arpa/header.h"
#endif
#endif                          /* NAMESER_HAS_HEADER */

#include "val_cache.h"
#include "val_support.h"
#include "val_assertion.h"

#define OUTER_HEADER_LEN (sizeof(HEADER) + wire_name_length(name_n) + sizeof(u_int16_t) + sizeof(u_int16_t))

#ifndef h_errno                 /* can be a macro */
extern int      h_errno;
#endif

/*
 * Calculate rrset length 
 */
static int
find_rrset_len(struct val_rrset *rrset)
{
    struct val_rr_rec  *rr;
    int             resp_len = 0;
    int             rrset_name_n_len;

    if (rrset == NULL)
        return 0;

    rrset_name_n_len = wire_name_length(rrset->val_rrset_name_n);
    /* data */
    for (rr = rrset->val_rrset_data; rr; rr = rr->rr_next) {
        resp_len +=
            rrset_name_n_len + sizeof(u_int16_t) + sizeof(u_int16_t) +
            sizeof(u_int32_t)
            + sizeof(u_int16_t) + rr->rr_rdata_length_h;
    }
    /* signatures */
    for (rr = rrset->val_rrset_sig; rr; rr = rr->rr_next) {
        resp_len +=
            rrset_name_n_len + sizeof(u_int16_t) + sizeof(u_int16_t) +
            sizeof(u_int32_t)
            + sizeof(u_int16_t) + rr->rr_rdata_length_h;
    }
    return resp_len;
}

/* 
 * determine the size of the response from individual rrsets
 */  
static int
determine_size(struct val_result_chain *res)
{
    int             resp_len = 0;

    if (res == NULL)
        return 0;
    
    if (res->val_rc_answer && res->val_rc_answer->val_ac_rrset) {
        resp_len += find_rrset_len(res->val_rc_answer->val_ac_rrset);
    }
    if (res->val_rc_proof_count) {
        int             i;
        for (i = 0; i < res->val_rc_proof_count; i++) {
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
encode_response_rrset(struct val_rrset *rrset,
                      val_status_t val_rc_status,
                      int resp_len,
                      unsigned char **anbuf,
                      int *anbufindex,
                      int *ancount,
                      unsigned char **nsbuf,
                      int *nsbufindex,
                      int *nscount,
                      unsigned char **arbuf,
                      int *arbufindex,
                      int *arcount, 
                      int *an_auth, 
                      int *ns_auth)
{
    unsigned char  *cp;
    int            *bufindex = NULL;
    struct val_rr_rec  *rr;
    int             rrset_name_n_len;
    int            *count;

    if (rrset == NULL)
        return 0;

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
    rrset_name_n_len = wire_name_length(rrset->val_rrset_name_n);
    /* for each data */
    for (rr = rrset->val_rrset_data; rr; rr = rr->rr_next) {

        if ((*bufindex + rrset_name_n_len + 10 +
             rr->rr_rdata_length_h) > resp_len) {
            /** log error message?  */
            return -1;
        }

        (*count)++;

        memcpy(cp, rrset->val_rrset_name_n, rrset_name_n_len);
        cp += rrset_name_n_len;
        NS_PUT16(rrset->val_rrset_type_h, cp);
        NS_PUT16(rrset->val_rrset_class_h, cp);
        NS_PUT32(rrset->val_rrset_ttl_h, cp);
        NS_PUT16(rr->rr_rdata_length_h, cp);
        memcpy(cp, rr->rr_rdata, rr->rr_rdata_length_h);
        cp += rr->rr_rdata_length_h;

    }  
    /* for each rrsig */
    for (rr = rrset->val_rrset_sig; rr; rr = rr->rr_next) {

        if ((*bufindex + rrset_name_n_len + 10 +
             rr->rr_rdata_length_h) > resp_len) {
            /** log error message?  */
            return -1;
        }

        (*count)++;

        memcpy(cp, rrset->val_rrset_name_n, rrset_name_n_len);
        cp += rrset_name_n_len;
        NS_PUT16(ns_t_rrsig, cp);
        NS_PUT16(rrset->val_rrset_class_h, cp);
        NS_PUT32(rrset->val_rrset_ttl_h, cp);
        NS_PUT16(rr->rr_rdata_length_h, cp);
        memcpy(cp, rr->rr_rdata, rr->rr_rdata_length_h);
        cp += rr->rr_rdata_length_h;

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
 *               flags -- Handles the VAL_QUERY_MERGE_RRSETS flag.  If
 *                        this flag is set, multiple answers are returned in a 
 *                        form similar to res_query.  
 *
 * Return value: VAL_NO_ERROR on success, and a negative valued error code 
 *               (see val_errors.h) on failure.
 */

int
compose_answer(const u_char * name_n,
               const u_int16_t type_h,
               const u_int16_t class_h,
               struct val_result_chain *results,
               struct val_response **f_resp, 
               u_int8_t flags)
{
    struct val_result_chain *res = NULL;
    int             ancount = 0;        // Answer Count
    int             nscount = 0;        // Authority Count
    int             arcount = 0;        // Additional Count
    int             anbufindex = 0, nsbufindex = 0, arbufindex = 0;
    unsigned char  *anbuf = NULL, *nsbuf = NULL, *arbuf = NULL;
    int             an_auth = 1;
    int             ns_auth = 1;
    unsigned char  *rp = NULL;
    int             resp_len = 0;
    HEADER         *hp = NULL;
    int             len;
    int             retval;

    struct val_response *head_resp = NULL;
    struct val_response *cur_resp = NULL;
    struct val_rrset *rrset;
    int validated = 1;
    int trusted = 1;

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
    
    if ((f_resp == NULL) || (name_n == NULL))
        return VAL_BAD_ARGUMENT;

    if (flags & VAL_QUERY_MERGE_RRSETS) {
        for (res = results; res; res = res->val_rc_next) {
            resp_len += determine_size(res);
        }
        /*
         * Allocate a single element of the val_response array to hold the result 
         */
        head_resp =
            (struct val_response *) MALLOC(sizeof(struct val_response));
        if (head_resp == NULL)
            return VAL_OUT_OF_MEMORY;
        head_resp->vr_response =
            (unsigned char *) MALLOC((resp_len + OUTER_HEADER_LEN) *
                                     sizeof(unsigned char));
        if (head_resp->vr_response == NULL) {
            FREE(head_resp);
            head_resp = NULL;
            return VAL_OUT_OF_MEMORY;
        }
        head_resp->vr_length = (resp_len + OUTER_HEADER_LEN);
        head_resp->vr_val_status = VAL_DONT_KNOW;
        head_resp->vr_next = NULL;

        /*
         * temporary buffers for different sections 
         */
        anbuf = (unsigned char *) MALLOC(resp_len * sizeof(unsigned char));
        nsbuf = (unsigned char *) MALLOC(resp_len * sizeof(unsigned char));
        arbuf = (unsigned char *) MALLOC(resp_len * sizeof(unsigned char));
        if ((anbuf == NULL) || (nsbuf == NULL) || (arbuf == NULL)) {
            if (anbuf)
                FREE(anbuf);
            if (nsbuf)
                FREE(nsbuf);
            if (arbuf)
                FREE(arbuf);
            return VAL_OUT_OF_MEMORY;
        }
        /*
         * Header 
         */
        rp = head_resp->vr_response;
        hp = (HEADER *) rp;
        bzero(hp, sizeof(HEADER));
        rp += sizeof(HEADER);

        /*
         * Question section 
         */
        len = wire_name_length(name_n);
        memcpy(rp, name_n, len);
        rp += len;
        NS_PUT16(type_h, rp);
        NS_PUT16(class_h, rp);
        hp->qdcount = htons(1);
    }

    for (res = results; res; res = res->val_rc_next) {

        /* set the value of merged trusted and validated status values */
        if (!(validated && val_isvalidated(res->val_rc_status))) 
            validated = 0;
        if (!(trusted && val_istrusted(res->val_rc_status))) 
            trusted = 0;
            
        if (!(flags & VAL_QUERY_MERGE_RRSETS)) {
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

            resp_len = determine_size(res);
            if (NULL == 
                    (cur_resp = (struct val_response *)
                        MALLOC(sizeof(struct val_response)))) {
                retval = VAL_OUT_OF_MEMORY;
                goto err;
            }
            if (NULL == 
                   (cur_resp->vr_response = (unsigned char *) 
                        MALLOC((resp_len + OUTER_HEADER_LEN) *
                                sizeof(unsigned char)))) {
                FREE(cur_resp);
                retval = VAL_OUT_OF_MEMORY;
                goto err;
            }

            cur_resp->vr_length = (resp_len + OUTER_HEADER_LEN);
            cur_resp->vr_val_status = res->val_rc_status;

            cur_resp->vr_next = NULL;
            if (head_resp != NULL)
                cur_resp->vr_next = head_resp;
            head_resp = cur_resp;
            /*
             * temporary buffers for different sections 
             */
            anbuf =
                (unsigned char *) MALLOC(resp_len * sizeof(unsigned char));
            nsbuf =
                (unsigned char *) MALLOC(resp_len * sizeof(unsigned char));
            arbuf =
                (unsigned char *) MALLOC(resp_len * sizeof(unsigned char));
            if ((anbuf == NULL) || (nsbuf == NULL) || (arbuf == NULL)) {
                if (anbuf)
                    FREE(anbuf);
                if (nsbuf)
                    FREE(nsbuf);
                if (arbuf)
                    FREE(arbuf);
                retval = VAL_OUT_OF_MEMORY;
                goto err;
            }
            /*
             * Header 
             */
            rp = head_resp->vr_response;
            hp = (HEADER *) rp;
            bzero(hp, sizeof(HEADER));
            rp += sizeof(HEADER);

            /*
             * Question section 
             */
            len = wire_name_length(name_n);
            memcpy(rp, name_n, len);
            rp += len;
            NS_PUT16(type_h, rp);
            NS_PUT16(class_h, rp);
            hp->qdcount = htons(1);
        }

        if (res->val_rc_answer && res->val_rc_answer->val_ac_rrset) {
            rrset = res->val_rc_answer->val_ac_rrset;
            if (-1 ==
                encode_response_rrset(rrset, res->val_rc_status, resp_len,
                                      &anbuf, &anbufindex, &ancount,
                                      &nsbuf, &nsbufindex, &nscount,
                                      &arbuf, &arbufindex, &arcount,
                                      &an_auth, &ns_auth)) {
                retval = VAL_BAD_ARGUMENT;
                goto err;
            }
        } else if (res->val_rc_proof_count) {
            int             i;
            for (i = 0; i < res->val_rc_proof_count; i++) {
                rrset = res->val_rc_proofs[i]->val_ac_rrset;
                if (-1 ==
                    encode_response_rrset(rrset, res->val_rc_status,
                                          resp_len, &anbuf, &anbufindex,
                                          &ancount, &nsbuf, &nsbufindex,
                                          &nscount, &arbuf, &arbufindex,
                                          &arcount, &an_auth, &ns_auth)) {
                    retval = VAL_BAD_ARGUMENT;
                    goto err;
                }
            }
        }

        if (!(flags & VAL_QUERY_MERGE_RRSETS)) {
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
           
            hp->ad = val_istrusted(res->val_rc_status)? 1:0; 
        } else {
            hp->ad = trusted ? 1:0; 
        }

        hp->ancount = htons(ancount);
        hp->nscount = htons(nscount);
        hp->arcount = htons(arcount);

        switch (res->val_rc_status) {
            case VAL_NONEXISTENT_TYPE:
            case VAL_NONEXISTENT_TYPE_NOCHAIN: 
                hp->rcode = ns_r_noerror;
                break;

            case VAL_NONEXISTENT_NAME:
            case VAL_NONEXISTENT_NAME_NOCHAIN: 
                hp->rcode = ns_r_nxdomain;
                break;

            case VAL_DNS_RESPONSE_ERROR: 
            case VAL_DNS_WRONG_ANSWER: 
            case VAL_DNS_REFERRAL_ERROR: 
            case VAL_DNS_MISSING_GLUE: 
            case VAL_DNS_CONFLICTING_ANSWERS: 
                hp->rcode = ns_r_servfail;
                break;
                
            default:
                if (hp->ancount > 0) {
                    hp->rcode = ns_r_noerror;
                } else {
                    hp->rcode = ns_r_servfail;
                }
                break;
        }

        if (!(flags & VAL_QUERY_MERGE_RRSETS)) {
            FREE(anbuf);
            FREE(nsbuf);
            FREE(arbuf);
        }
    }

    if (flags & VAL_QUERY_MERGE_RRSETS) {
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
        if (results) {
            if (validated)
                head_resp->vr_val_status = VAL_VALIDATED_ANSWER;
            else if (trusted)
                head_resp->vr_val_status = VAL_TRUSTED_ANSWER;
            else
                head_resp->vr_val_status = VAL_UNTRUSTED_ANSWER;
        } else {
            head_resp->vr_val_status = VAL_UNTRUSTED_ANSWER;
        }
    }

    *f_resp = head_resp;
    return VAL_NO_ERROR;

  err:
    while (NULL != (cur_resp = head_resp)) {
        head_resp = head_resp->vr_next;
        FREE(cur_resp->vr_response);
        FREE(cur_resp);
    }

    *f_resp = NULL;
    return retval;

}


/*
 * This routine is provided for compatibility with programs that 
 * depend on the res_query() function. 
 */
/*
 * Function: val_query
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
 * flags -- 
 * At present only one flag is implemented VAL_QUERY_MERGE_RRSETS.  When this flag
 * is specified, val_query will merge the RRSETs into a single response message.
 * The validation status in this case will be VAL_SUCCESS only if all the
 * individual RRSETs have the VAL_SUCCESS status.  Otherwise, the status
 * will be one of the other error codes.
 * resp -- An array of val_response structures used to return the result.
 * 
 * Return value: VAL_NO_ERROR on success, and a negative valued error code 
 *               (see val_errors.h) on failure.
 *
 */
int
val_query(val_context_t * context,
          const char *domain_name,
          const u_int16_t class_h,
          const u_int16_t type,
          const u_int8_t flags, 
          struct val_response **resp)
{
    struct val_result_chain *results = NULL;
    int             retval;
    u_char          name_n[NS_MAXCDNAME];

    if ((resp == NULL) || (domain_name == NULL))
        return VAL_BAD_ARGUMENT;

    if (ns_name_pton(domain_name, name_n, sizeof(name_n)) == -1) 
        return VAL_BAD_ARGUMENT;

    *resp = NULL;

    val_log(context, LOG_DEBUG,
            "val_query(): called with dname=%s, class=%s, type=%s",
            domain_name, p_class(class_h), p_type(type));

    /*
     * Query the validator 
     */
    if (VAL_NO_ERROR ==
        (retval =
         val_resolve_and_check(context, name_n, class_h, type, flags,
                               &results))) {
        /*
         * Construct the answer response in resp 
         */
        retval =
            compose_answer(name_n, type, class_h, results, resp, flags);

        val_free_result_chain(results);
    }

    return retval;
}


/*
 * Release memory allocated by the val_query() function 
 */
int
val_free_response(struct val_response *resp)
{
    struct val_response *prev, *cur;
    cur = resp;

    while (cur) {
        prev = cur;
        cur = cur->vr_next;

        if (prev->vr_response != NULL)
            FREE(prev->vr_response);
        FREE(prev);
    }

    return VAL_NO_ERROR;
}

/*
 * wrapper around val_query() that is closer to res_query() 
 * Only difference is that it passes the VAL_QUERY_MERGE_RRSETS
 * flag automatically. 
 */
int
val_res_query(val_context_t * ctx, 
              const char *dname, 
              int class_h,
              int type, 
              u_char * answer, 
              int anslen,
              val_status_t * val_status)
{
    struct val_response *resp;
    int             retval = -1;
    int             bytestocopy = 0;
    int             totalbytes = 0;
    HEADER *hp = NULL;

    if (dname == NULL || val_status == NULL || answer == NULL) {
        val_log(ctx, LOG_ERR, "val_res_query(%s, %d, %d): Error - %s", 
            dname, p_class(class_h), p_type(type), p_val_err(VAL_BAD_ARGUMENT));
        h_errno = NETDB_INTERNAL;
        errno = EINVAL;
        return -1;
    }

    if (VAL_NO_ERROR !=
        (retval =
         val_query(ctx, dname, class_h, type, VAL_QUERY_MERGE_RRSETS,
                   &resp))) {
        val_log(ctx, LOG_ERR, "val_res_query(%s, %d, %d): Error - %s", 
            dname, p_class(class_h), p_type(type), p_val_err(retval));
        h_errno = NETDB_INTERNAL;
        errno = EINVAL;
        return -1;
    }

    totalbytes = resp->vr_length;

    bytestocopy = (resp->vr_length > anslen) ? anslen : resp->vr_length;
    memcpy(answer, resp->vr_response, bytestocopy);
    *val_status = resp->vr_val_status;
    val_free_response(resp);
    hp = (HEADER *) answer;

    if (hp) {
        if (hp->rcode == ns_r_servfail) {
            h_errno = TRY_AGAIN;
            return -1;
        } else if (hp->rcode == ns_r_nxdomain) {
            h_errno = HOST_NOT_FOUND;
            return -1;
        } else if (hp->rcode != ns_r_noerror) {
            /*
             * Not a success condition 
             */
            h_errno = NO_RECOVERY;
            return -1;
        } else if (hp->ancount > 0) {
            h_errno = NETDB_SUCCESS;
            return totalbytes;
        }
    }

    h_errno = NO_DATA;
    return -1;
}

/*
 * wrapper around val_query() that is closer to res_search() 
 */
int
val_res_search(val_context_t * ctx, const char *dname, int class_h,
              int type, u_char * answer, int anslen,
              val_status_t * val_status)
{
    int             retval = -1;
    char           *dot, *search, *pos;
    char            buf[NS_MAXDNAME];
    
    if ((dname == NULL) || (val_status == NULL) || (answer == NULL)) {
        val_log(ctx, LOG_ERR, "val_res_search(%s, %d, %d): Error - %s", 
            dname, p_class(class_h), p_type(type), p_val_err(VAL_BAD_ARGUMENT));
        h_errno = NETDB_INTERNAL;
        errno = EINVAL;
        return -1;
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
                *pos++;
            if (*pos)
                *pos++ = 0;
            
            snprintf(buf, sizeof(buf), "%s.%s", dname, search);
            retval = val_res_query(ctx, buf, class_h, type, answer, anslen,
                                   val_status);
            if ((retval >0) ||
                ((retval == -1) && (h_errno != HOST_NOT_FOUND))) {
                if (save)
                    free(save);
                return retval;
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

    return retval;
}
