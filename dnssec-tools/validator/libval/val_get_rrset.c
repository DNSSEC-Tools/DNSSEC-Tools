/*
 * Copyright 2005-2008 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 */
/*
 * DESCRIPTION
 * Contains implementation of val_get_rrset() 
 */
#include "validator-config.h"

#include <stdlib.h>
#include <string.h>

#include <validator/validator.h>
#include <validator/resolver.h>

void
val_free_answer_chain(struct val_answer_chain *answers)
{
    struct val_answer_chain *ans = answers;

    if (ans == NULL)
        return;
    
    while (ans) {
        struct val_answer_chain *temp_ans = ans;
        if (temp_ans->val_ans_name) 
            FREE(temp_ans->val_ans_name);
        while (temp_ans->val_ans) {
            /* the answer is actually of type val_rr_rec */
            struct val_rr_rec  *temp_rr = (struct val_rr_rec *)(temp_ans->val_ans);
            if (temp_rr->rr_rdata)
                FREE(temp_rr->rr_rdata);
            temp_ans->val_ans = (struct rr_rec *)(temp_rr->rr_next);
            FREE(temp_rr);
        }
        ans = temp_ans->val_ans_next;
        FREE(temp_ans);
    }
}

int
val_get_rrset(val_context_t *context,
              const char *name,
              u_int16_t class,
              u_int16_t type,
              u_int32_t flags,
              struct val_answer_chain **answers) 
{
    u_int8_t name_n[NS_MAXCDNAME];
    struct val_result_chain *results = NULL;
    struct val_result_chain *res = NULL;
    struct val_answer_chain *ans = NULL;
    struct val_answer_chain *last_ans = NULL;
    int retval = VAL_NO_ERROR;
    int validated = 1;
    int trusted = 1;
    u_int8_t *n = NULL;
    int len;
    char *p;
    u_int8_t *name_alias = NULL;
    val_context_t *ctx = NULL;
    
    if (context == NULL) {
        if (VAL_NO_ERROR != (retval = val_create_context(NULL, &ctx))) {
            return retval;
        } 
    } else {
        ctx = context;
    }
    
    if (name == NULL || answers == NULL) {
        return VAL_BAD_ARGUMENT;
    }

    *answers = NULL;
    last_ans = NULL;
   
    if ((retval = ns_name_pton(name, name_n, sizeof(name_n))) != -1) {

        if ((retval = val_resolve_and_check(ctx, name_n, class, type, 
                                       flags | VAL_QUERY_NO_AC_DETAIL,
                                       &results)) != VAL_NO_ERROR) {
            val_log(ctx, LOG_INFO,
                    "get_addrinfo_from_dns(): val_resolve_and_check failed - %s",
                    p_val_err(retval));
        }
    } else {
        val_log(ctx, LOG_INFO, "val_get_rrset(): Cannot parse name %s", name);
    }

    if (results == NULL) {
        val_log(ctx, LOG_INFO, "val_get_rrset(): returned NULL result");
        /* Construct a single val_answer_chain with the untrusted status */
        ans = (struct val_answer_chain *) MALLOC (sizeof(struct val_answer_chain));
        if (ans == NULL) {
            return VAL_OUT_OF_MEMORY;
        }
        ans->val_ans_name = strdup(name); 
        if (ans->val_ans_name == NULL) {
            FREE(ans);
            ans = NULL;
            return VAL_OUT_OF_MEMORY;
        } 
        ans->val_ans_status = VAL_UNTRUSTED_ANSWER;
        ans->val_ans_class = class;
        ans->val_ans_type = type;
        ans->val_ans = NULL;
        ans->val_ans_next = NULL;
        *answers = ans;
        return VAL_NO_ERROR;
    }

    /* Construct the val_answer_chain linked list for returned results */
    for (res = results; res; res=res->val_rc_next) {

        /* keep track of the "merged" status*/ 
        if (!validated || !val_isvalidated(res->val_rc_status))
            validated = 0;
        if (!trusted || !val_istrusted(res->val_rc_status))
            trusted = 0;

        /* 
         * we don't need cnames/dnames in the answer,
         * we only need the name that is being pointed to.
         */
        if (res->val_rc_alias) {
            name_alias = res->val_rc_alias;
            continue;
        }

        ans = (struct val_answer_chain *) MALLOC (sizeof(struct val_answer_chain));
        if (ans == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }

        /* add to end of chain */
        ans->val_ans_next = NULL;
        if (last_ans) {
            last_ans->val_ans_next = ans;
        } else {
            *answers = ans;
        }
        last_ans = ans;
        
        /* Set merged validation status value */
        if (validated)
           ans->val_ans_status = VAL_VALIDATED_ANSWER;
        else if (trusted)
            ans->val_ans_status = VAL_TRUSTED_ANSWER;
        else
            ans->val_ans_status = VAL_UNTRUSTED_ANSWER;        

        if (name_alias) {
            n = name_alias; /* the last alias target */ 
        } else {
            n = name_n; /* the name being queried for */
        }
        ans->val_ans_class = class; 
        ans->val_ans_type = type; 
        ans->val_ans = NULL;

        if (res->val_rc_rrset) {
            /* use values from the rrset */
            n = res->val_rc_rrset->val_rrset_name_n;
            ans->val_ans_class = res->val_rc_rrset->val_rrset_class_h; 
            ans->val_ans_type = res->val_rc_rrset->val_rrset_type_h; 
            ans->val_ans = (struct rr_rec *) (res->val_rc_rrset->val_rrset_data);
            res->val_rc_rrset->val_rrset_data = NULL;
        } else if (val_does_not_exist(res->val_rc_status)) {
            /* if we have a p.n.e. use the exact value modulus the trusted/validated status */
            if (validated) {
                ans->val_ans_status = res->val_rc_status;
            } else if (trusted) {
                if (res->val_rc_status == VAL_NONEXISTENT_NAME ||
                    res->val_rc_status == VAL_NONEXISTENT_NAME_NOCHAIN) {
                   ans->val_ans_status = VAL_NONEXISTENT_NAME_NOCHAIN; 
                } else {
                   ans->val_ans_status = VAL_NONEXISTENT_TYPE_NOCHAIN; 
                }
            }
        } 

        /* Convert the name to a string */
        ans->val_ans_name = NULL;    
        len = wire_name_length(n);
        p = (char *) MALLOC (len * sizeof (char));
        if (p == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        if (ns_name_ntop(n, p, len) < 0) {
            memset(p, 0, len);
        } 
        ans->val_ans_name = p;    

    } 

    val_free_result_chain(results);
    return VAL_NO_ERROR;

err:
    val_free_answer_chain(*answers);
    *answers = NULL;
    val_free_result_chain(results);
    return retval;
} 
