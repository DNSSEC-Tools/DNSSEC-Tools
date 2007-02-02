/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#include "validator-config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <validator/resolver.h>
#include <validator/validator.h>
#include "val_support.h"
#include "val_policy.h"
#include "val_assertion.h"

int
val_create_context_with_conf(char *label, 
                             char *dnsval_conf, 
                             char *resolv_conf, 
                             char *root_conf, 
                             val_context_t ** newcontext)
{
    int             retval;

    if (newcontext == NULL)
        return VAL_BAD_ARGUMENT;

    *newcontext = (val_context_t *) MALLOC(sizeof(val_context_t));
    if (*newcontext == NULL)
        return VAL_OUT_OF_MEMORY;

    if (snprintf
        ((*newcontext)->id, VAL_CTX_IDLEN - 1, "%u",
         (unsigned) (*newcontext)) < 0)
        strcpy((*newcontext)->id, "libval");

    if (label){
        (*newcontext)->label = (char *) MALLOC (strlen(label) + 1);
        if ((*newcontext)->label == NULL) {
            FREE(*newcontext);
            *newcontext = NULL;
            return VAL_OUT_OF_MEMORY;
        }
    } else {
        (*newcontext)->label = NULL;
    }

    /* 
     * Set default configuration files 
     */
    (*newcontext)->dnsval_conf = dnsval_conf? strdup(dnsval_conf) : dnsval_conf_get(); 
    (*newcontext)->resolv_conf = resolv_conf? strdup(resolv_conf) : resolv_conf_get(); 
    (*newcontext)->root_conf = root_conf? strdup(root_conf) : root_hints_get(); 

    memset(&(*newcontext)->r_timestamp, 0, sizeof(struct timespec));
    memset(&(*newcontext)->v_timestamp, 0, sizeof(struct timespec));
    memset(&(*newcontext)->h_timestamp, 0, sizeof(struct timespec));

    (*newcontext)->root_ns = NULL; 

    (*newcontext)->nslist = NULL; 

    (*newcontext)->e_pol =
        (policy_entry_t *) MALLOC(MAX_POL_TOKEN * sizeof(policy_entry_t));
    if ((*newcontext)->e_pol == NULL) {
        FREE(*newcontext);
        *newcontext = NULL;
        return VAL_OUT_OF_MEMORY;
    }
    memset((*newcontext)->e_pol, 0,
           MAX_POL_TOKEN * sizeof(policy_entry_t));
    (*newcontext)->pol_overrides = NULL;
    (*newcontext)->cur_override = NULL;
   
    /*
     * Read the Root Hints file; has to be read before resolver config file 
     */
    if ((retval = read_root_hints_file(*newcontext)) != VAL_NO_ERROR) {
        FREE(*newcontext);
        *newcontext = NULL;
        return retval;
    }

    /*
     * Read the Resolver configuration file 
     */
    if ((retval = read_res_config_file(*newcontext)) != VAL_NO_ERROR) {
        FREE(*newcontext);
        *newcontext = NULL;
        return retval;
    }

    /*
     * Read the validator configuration file 
     */
    if ((retval =
         read_val_config_file(*newcontext, label)) != VAL_NO_ERROR) {
        destroy_respol(*newcontext);
        FREE(*newcontext);
        *newcontext = NULL;
        return retval;
    }
    OVERRIDE_POLICY((*newcontext));

    /* 
     * Initialize caches 
     */
    (*newcontext)->q_list = NULL;
    (*newcontext)->a_list = NULL;

    return VAL_NO_ERROR;
}

int
val_create_context(char *label, 
                   val_context_t ** newcontext)
{
    return val_create_context_with_conf(label, NULL, NULL, NULL, newcontext);
}

void
val_free_context(val_context_t * context)
{
    if ((context == NULL) || (context == the_default_context))
        return;

    if (context->label)
        FREE(context->label);

    if (context->dnsval_conf)
        FREE(context->dnsval_conf);

    if (context->resolv_conf)
        FREE(context->resolv_conf);

    if (context->root_conf)
        FREE(context->root_conf);

    if (context->root_ns)
        free_name_servers(&context->root_ns);
    
    destroy_respol(context);
    destroy_valpol(context);
    FREE(context->e_pol);

    free_query_chain(context->q_list);
    free_authentication_chain(context->a_list);

    FREE(context);
}

void 
val_refresh_resolver_policy(val_context_t * context)
{
    if ((context == NULL) || (context == the_default_context))
        return;

    if (read_res_config_file(context) != VAL_NO_ERROR) {
        context->r_timestamp = -1;
        val_log(context, LOG_WARNING, "Resolver configuration could not be read; using older values");
        return; 
    }
}

void 
val_refresh_validator_policy(val_context_t * context)
{
    if ((context == NULL) || (context == the_default_context))
        return;

    if (read_val_config_file(context, context->label) != VAL_NO_ERROR) {
        val_log(context, LOG_WARNING, "Resolver configuration could not be read; using older values");
        context->v_timestamp = -1;
        return; 
    }
    OVERRIDE_POLICY((context));

    /* 
     * Re-initialize caches 
     */
    free_query_chain(context->q_list);
    free_authentication_chain(context->a_list);

    context->q_list = NULL;
    context->a_list = NULL;
}

void 
val_refresh_root_hints(val_context_t * context)
{
    if ((context == NULL) || (context == the_default_context))
        return;

    if (read_root_hints_file(context) != VAL_NO_ERROR) {
        val_log(context, LOG_WARNING, "Root Hints could not be read; using older values");
        context->h_timestamp = -1;
        return; 
    }
}

