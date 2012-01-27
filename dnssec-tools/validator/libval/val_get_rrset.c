/*
 * Copyright 2005-2012 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 */
/*
 * DESCRIPTION
 * Contains implementation of val_get_rrset() 
 */
#include "validator/validator-config.h"
#include "validator-internal.h"

#include "val_support.h"
#include "val_context.h"

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
        /* the answer is actually of type val_rr_rec */
        if (temp_ans->val_ans) {
            res_sq_free_rr_recs((struct val_rr_rec **)(&temp_ans->val_ans));
        }
        ans=temp_ans->val_ans_next;
        FREE(temp_ans);
    }
}

int
val_get_answer_from_result(val_context_t *context, const char *name, int class_h,
                           int type_h, struct val_result_chain **results,
                           struct val_answer_chain **answers,
                           unsigned int vgafr_flags)
{
    struct val_result_chain *res = NULL;
    struct val_answer_chain *ans = NULL;
    struct val_answer_chain *last_ans = NULL;
    int retval = VAL_NO_ERROR;
    const char *n = NULL;
    int len;
    char *name_alias = NULL;
    int trusted, validated;
    
    if (name == NULL || answers == NULL || results == NULL || answers == NULL) {
        return VAL_BAD_ARGUMENT;
    }

    *answers = NULL;
    last_ans = NULL;
   
    if (*results == NULL) {
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
        ans->val_ans_class = class_h;
        ans->val_ans_type = type_h;
        ans->val_ans = NULL;
        ans->val_ans_next = NULL;
        *answers = ans;
        return VAL_NO_ERROR;
    }

    trusted = 1;
    validated = 1;

    /* Construct the val_answer_chain linked list for returned results */
    for (res = *results; res; res=res->val_rc_next) {

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
        
        if (res->val_rc_rrset) {
            /* use values from the rrset */
            n = res->val_rc_rrset->val_rrset_name;
            ans->val_ans_class = res->val_rc_rrset->val_rrset_class; 
            ans->val_ans_type = res->val_rc_rrset->val_rrset_type; 
            ans->val_ans = (struct rr_rec *) (res->val_rc_rrset->val_rrset_data);
            res->val_rc_rrset->val_rrset_data = NULL;
        } else {
            if (name_alias) {
                n = name_alias; /* the last alias target */ 
            } else {
                n = name; /* the name being queried for */
            }
            ans->val_ans_class = class_h; 
            ans->val_ans_type = type_h; 
            ans->val_ans = NULL;
        } 

        /* Convert the name to a string */
        ans->val_ans_name = NULL;    
        len = strlen(n) + 1;
        ans->val_ans_name = (char *) MALLOC (len * sizeof (char));
        if (ans->val_ans_name == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        strcpy(ans->val_ans_name, n);

        /* 
         * if the current answer was validated or 
         * if the current answer was trusted use the exact status
         */
        if (validated || 
            (trusted && !val_isvalidated(res->val_rc_status))) {
           ans->val_ans_status = res->val_rc_status;
        } else if (trusted) {
        /*
         * If the combined answer was trusted but the current answer
         * was validated (implied), use the lower bounds of trust 
         */
            if (val_does_not_exist(res->val_rc_status)) {
                if (res->val_rc_status == VAL_NONEXISTENT_NAME)
                   ans->val_ans_status = VAL_NONEXISTENT_NAME_NOCHAIN; 
                else 
                   ans->val_ans_status = VAL_NONEXISTENT_TYPE_NOCHAIN; 
            } else {
                ans->val_ans_status = VAL_TRUSTED_ANSWER;
            }
        } else {
            ans->val_ans_status = VAL_UNTRUSTED_ANSWER;        
        }

        /* 
         * reset the below values so that we are able to handle different 
         * status values for different answers
         */
        validated = 1;
        trusted = 1;
    } 

    val_free_result_chain(*results);
    *results = NULL;
    return VAL_NO_ERROR;

err:
    val_free_answer_chain(*answers);
    *answers = NULL;
    val_free_result_chain(*results);
    *results = NULL;
    return retval;
} 

int
val_get_rrset(val_context_t *context,
              const char *name,
              int class_h,
              int type_h,
              u_int32_t flags,
              struct val_answer_chain **answers) 
{
    struct val_result_chain *results = NULL;
    int retval = VAL_NO_ERROR;
    val_context_t *ctx = NULL;
    
    if (name == NULL || answers == NULL) {
        return VAL_BAD_ARGUMENT;
    }

    ctx = val_create_or_refresh_context(context);/* does CTX_LOCK_POL_SH */
    if (ctx == NULL)
        return VAL_INTERNAL_ERROR;

    if ((retval = val_resolve_and_check(ctx, name, class_h, type_h, 
                                       flags,
                                       &results)) != VAL_NO_ERROR) {
        val_log(ctx, LOG_INFO,
                "get_addrinfo_from_dns(): val_resolve_and_check failed - %s",
                p_val_err(retval));
        goto err; 
    }

    retval = val_get_answer_from_result(ctx, name, class_h, type_h, &results,
                                        answers, 0);

err:
    CTX_UNLOCK_POL(ctx);
    return retval;
} 
