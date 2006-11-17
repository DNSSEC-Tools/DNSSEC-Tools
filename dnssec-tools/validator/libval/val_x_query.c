
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
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

#include <resolver.h>
#include <validator.h>
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
    struct rr_rec  *rr;
    int             resp_len = 0;
    int             rrset_name_n_len;

    if (rrset == NULL)
        return 0;

    rrset_name_n_len = wire_name_length(rrset->val_rrset_name_n);
    for (rr = rrset->val_rrset_data; rr; rr = rr->rr_next) {
        resp_len +=
            rrset_name_n_len + sizeof(u_int16_t) + sizeof(u_int16_t) +
            sizeof(u_int32_t)
            + sizeof(u_int16_t) + rr->rr_rdata_length_h;
    }
    return resp_len;
}

int encode_response_rrset(struct val_rrset *rrset,
                           val_status_t     val_rc_status,
                           int resp_len,
                           unsigned char  **anbuf,
                           int             *anbufindex,
                           int             *ancount,
                           unsigned char  **nsbuf,
                           int             *nsbufindex,
                           int             *nscount,
                           unsigned char  **arbuf,
                           int             *arbufindex,
                           int             *arcount,
                           int             *an_auth,
                           int             *ns_auth) 
{
    unsigned char  *cp;
    int            *bufindex = NULL;
    struct rr_rec  *rr;
    int             rrset_name_n_len;
    int *count;

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
    } else { /* VAL_FROM_ADDITIONAL */
        cp = *arbuf + *arbufindex;
        bufindex = arbufindex;
        count = arcount;
    }

    /*
     * Answer/Authority/Additional section 
     */
    rrset_name_n_len = wire_name_length(rrset->val_rrset_name_n);
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

    }                       // end for each rr

    *bufindex += find_rrset_len(rrset);
    if (*bufindex > resp_len) {
        /** log error message?  */
        return -1; 
    }

    return 0;
}

static int determine_size (struct val_result_chain *res) 
{
    int resp_len = 0;

    if (res->val_rc_answer && res->val_rc_answer->val_ac_rrset) {
        resp_len +=
                find_rrset_len(res->val_rc_answer->val_ac_rrset);
    } 
    if (res->val_rc_proof_count) {
        int i;
        for (i = 0; i < res->val_rc_proof_count; i++) {
            resp_len +=
                    find_rrset_len(res->val_rc_proofs[i]->val_ac_rrset);
        }
    }
    return resp_len;
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
 *                        More flags may be added in future to
 *                        influence the evaluation and returned results.
 *
 * Return value: 0 on success, and a non-zero error-code on failure.
 */

int
compose_answer(const u_char * name_n,
               const u_int16_t type_h,
               const u_int16_t class_h,
               struct val_result_chain *results,
               struct val_response **f_resp, u_int8_t flags)
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

    struct val_response *head_resp = NULL; 
    struct val_response *cur_resp = NULL; 
    struct val_rrset *rrset;

    ancount = 0; nscount = 0; arcount = 0;
    anbufindex = 0; nsbufindex = 0; arbufindex = 0;
    anbuf = NULL; nsbuf = NULL; arbuf = NULL;
    an_auth = 1; ns_auth = 1;

    rp = NULL;
    resp_len = 0;
    
    if ((f_resp == NULL) || (name_n == NULL))
        return VAL_BAD_ARGUMENT;

    if (flags & VAL_QUERY_MERGE_RRSETS) {
        for (res = results; res; res = res->val_rc_next) {
            resp_len += determine_size(res);
        }
        /*
         * Allocate a single element of the val_response array to hold the result 
         */
        head_resp = (struct val_response *) MALLOC(sizeof(struct val_response));
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
        head_resp->vr_val_status = VAL_SUCCESS;
        head_resp->vr_next = NULL;
    
        /*
         * temporary buffers for different sections 
         */
        anbuf = (unsigned char *) MALLOC(resp_len * sizeof(unsigned char));
        nsbuf = (unsigned char *) MALLOC(resp_len * sizeof(unsigned char));
        arbuf = (unsigned char *) MALLOC(resp_len * sizeof(unsigned char));
        if ((anbuf == NULL) || (nsbuf == NULL) || (arbuf == NULL)) {
            if (anbuf) FREE(anbuf);
            if (nsbuf) FREE(nsbuf);
            if (arbuf) FREE(arbuf);
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

        if (!(flags & VAL_QUERY_MERGE_RRSETS)) {
            ancount = 0; nscount = 0; arcount = 0;
            anbufindex = 0; nsbufindex = 0; arbufindex = 0;
            anbuf = NULL; nsbuf = NULL; arbuf = NULL;
            an_auth = 1; ns_auth = 1;

            rp = NULL;
            resp_len = 0;
    
            resp_len = determine_size(res); 
            cur_resp = (struct val_response *) MALLOC(sizeof(struct val_response));
            if (cur_resp == NULL)
                goto err; 
            cur_resp->vr_response =
                (unsigned char *) MALLOC((resp_len + OUTER_HEADER_LEN) *
                                 sizeof(unsigned char));
            if (cur_resp->vr_response == NULL) {
                FREE(cur_resp);
                goto err;
            }
            cur_resp->vr_length = (resp_len + OUTER_HEADER_LEN);
            cur_resp->vr_val_status = VAL_SUCCESS;
            cur_resp->vr_next = NULL;
            if (head_resp != NULL)
                cur_resp->vr_next = head_resp;
            head_resp = cur_resp;
            /*
             * temporary buffers for different sections 
             */
            anbuf = (unsigned char *) MALLOC(resp_len * sizeof(unsigned char));
            nsbuf = (unsigned char *) MALLOC(resp_len * sizeof(unsigned char));
            arbuf = (unsigned char *) MALLOC(resp_len * sizeof(unsigned char));
            if ((anbuf == NULL) || (nsbuf == NULL) || (arbuf == NULL)) {
                if (anbuf) FREE(anbuf);
                if (nsbuf) FREE(nsbuf);
                if (arbuf) FREE(arbuf);
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
            if (-1 == encode_response_rrset(rrset, res->val_rc_status, resp_len,
                            &anbuf, &anbufindex, &ancount, 
                            &nsbuf, &nsbufindex, &nscount,
                            &arbuf, &arbufindex, &arcount,
                            &an_auth, &ns_auth))
                goto err;
        } else if (res->val_rc_proof_count) {
            int i;
            for (i=0; i<res->val_rc_proof_count; i++) {
                rrset = res->val_rc_proofs[i]->val_ac_rrset;
                if (-1 == encode_response_rrset(rrset, res->val_rc_status, resp_len,
                            &anbuf, &anbufindex, &ancount, 
                            &nsbuf, &nsbufindex, &nscount,
                            &arbuf, &arbufindex, &arcount,
                            &an_auth, &ns_auth))
                    goto err;
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

        hp->ancount = htons(ancount);
        hp->nscount = htons(nscount);
        hp->arcount = htons(arcount);

        /*
         * Set the AD bit if all RRSets in the Answer and Authority sections are authentic 
         */
        if (an_auth && ns_auth && ((ancount != 0) || (nscount != 0)))
            hp->ad = 1;
        else
            hp->ad = 0;

        head_resp->vr_val_status = res->val_rc_status;
        if (res->val_rc_status == VAL_NONEXISTENT_NAME) {
            hp->rcode = ns_r_nxdomain; 
        }

        if (!(flags & VAL_QUERY_MERGE_RRSETS)) {
            FREE(anbuf);
            FREE(nsbuf);
            FREE(arbuf);
        }
    }
    
    if (flags & VAL_QUERY_MERGE_RRSETS) {
        FREE(anbuf);
        FREE(nsbuf);
        FREE(arbuf);
    }

    *f_resp = head_resp;
    return VAL_NO_ERROR;

  err:
    while( NULL != (cur_resp = head_resp)) {
        head_resp = head_resp->vr_next;
        FREE(cur_resp->vr_response);
        FREE(cur_resp);
    }

    *f_resp = NULL;
    return VAL_OUT_OF_MEMORY;

}                               


/*
 * This routine is provided for compatibility with programs that 
 * depend on the res_query() function. 
 * If possible, one should use gethostbyname() or getaddrinfo() functions instead.
 */
/*
 * Function: val_query
 *
 * Purpose: A DNSSEC-aware function intended as a replacement to res_query().
 *          The scope of this function is global.
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
 * Return values:
 * VAL_NO_ERROR         Operation succeeded
 * VAL_BAD_ARGUMENT             The domain name or other arguments are invalid
 * VAL_OUT_OF_MEMORY    Could not allocate enough memory for operation
 *
 */
int
val_query(val_context_t * ctx,
          const char *domain_name,
          const u_int16_t class_h,
          const u_int16_t type,
          const u_int8_t flags, struct val_response **resp)
{
    struct val_result_chain *results = NULL;
    int             retval;
    val_context_t  *context;
    u_char          name_n[NS_MAXCDNAME];

    if ((resp == NULL) || (domain_name == NULL))
        return VAL_BAD_ARGUMENT;
    *resp = NULL;

    if (ctx == NULL) {
        if (VAL_NO_ERROR != (retval = val_create_context(NULL, &context)))
            return retval;
    } else
        context = (val_context_t *) ctx;

    val_log(context, LOG_DEBUG,
            "val_query called with dname=%s, class=%s, type=%s",
            domain_name, p_class(class_h), p_type(type));

    if (ns_name_pton(domain_name, name_n, sizeof(name_n)) == -1) {
        if ((ctx == NULL) && context)
            val_free_context(context);
        return (VAL_BAD_ARGUMENT);
    }

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
    }

    val_log_authentication_chain(context, LOG_DEBUG, name_n, class_h, type,
                                 context->q_list, results);

    val_free_result_chain(results);

    if ((ctx == NULL) && context)
        val_free_context(context);

    return retval;

}                               /* val_query() */


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
 */
int
val_res_query(val_context_t * ctx, const char *dname, int class_h,
              int type, u_char * answer, int anslen,
              val_status_t * val_status)
{
    struct val_response *resp;
    int             retval = -1;
    int             bytestocopy = 0;

    if (val_status == NULL) {
        h_errno = NETDB_INTERNAL;
        errno = EINVAL;
        return -1;
    }

    if (VAL_NO_ERROR !=
        (retval =
         val_query(ctx, dname, class_h, type, VAL_QUERY_MERGE_RRSETS,
                   &resp))) {
        h_errno = NETDB_INTERNAL;
        errno = EBADMSG;
        return -1;
    }

    retval = resp->vr_length;
    bytestocopy = (resp->vr_length > anslen)? anslen: resp->vr_length;
    memcpy(answer, resp->vr_response, bytestocopy);
    *val_status = resp->vr_val_status;

    /* only return success if you have some answer */
    if ((*val_status != VAL_SUCCESS ) &&
        (*val_status != VAL_PROVABLY_UNSECURE) && 
        (*val_status != VAL_LOCAL_ANSWER)) {

        switch (*val_status) {
            case VAL_NONEXISTENT_NAME:
                h_errno = HOST_NOT_FOUND;
                return -1;

            case VAL_NONEXISTENT_TYPE:
                h_errno = NO_DATA;
                return -1;

            case VAL_DNS_ERROR_BASE+SR_SERVFAIL:
                h_errno = TRY_AGAIN;
                return -1;

            default:
                h_errno = NO_RECOVERY;
                return -1;
        }
    }

    return retval;
}
