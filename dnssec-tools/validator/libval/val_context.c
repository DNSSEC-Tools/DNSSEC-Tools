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
#ifndef VAL_NO_THREADS
#include <pthread.h>
#endif

#include <validator/resolver.h>
#include <validator/validator.h>
#include "val_support.h"
#include "val_policy.h"
#include "val_assertion.h"
#include "val_context.h"

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
    memset(*newcontext, 0, sizeof(val_context_t));
    
#ifndef VAL_NO_THREADS
    if (0 != pthread_rwlock_init(&(*newcontext)->respol_rwlock, NULL)) {
        FREE(*newcontext);
        *newcontext = NULL;
        return VAL_INTERNAL_ERROR;
    }
    if (0 != pthread_rwlock_init(&(*newcontext)->valpol_rwlock, NULL)) {
        pthread_rwlock_destroy(&(*newcontext)->respol_rwlock);
        FREE(*newcontext);
        *newcontext = NULL;
        return VAL_INTERNAL_ERROR;
    }
    if (0 != pthread_mutex_init(&(*newcontext)->ac_lock, NULL)) {
        pthread_rwlock_destroy(&(*newcontext)->respol_rwlock);
        pthread_rwlock_destroy(&(*newcontext)->valpol_rwlock);
        FREE(*newcontext);
        *newcontext = NULL;
        return VAL_INTERNAL_ERROR;
    }
#endif
        
    if (snprintf
        ((*newcontext)->id, VAL_CTX_IDLEN - 1, "%u",
         (unsigned) (*newcontext)) < 0)
        strcpy((*newcontext)->id, "libval");

    if (label){
        (*newcontext)->label = (char *) MALLOC (strlen(label) + 1);
        if ((*newcontext)->label == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
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
    (*newcontext)->r_timestamp = 0;
    (*newcontext)->v_timestamp = 0;
    (*newcontext)->h_timestamp = 0;

    (*newcontext)->root_ns = NULL; 
    (*newcontext)->nslist = NULL; 

    (*newcontext)->e_pol =
        (policy_entry_t *) MALLOC(MAX_POL_TOKEN * sizeof(policy_entry_t));
    if ((*newcontext)->e_pol == NULL) {
        retval = VAL_OUT_OF_MEMORY;
        goto err;
    }
    memset((*newcontext)->e_pol, 0,
           MAX_POL_TOKEN * sizeof(policy_entry_t));
    (*newcontext)->pol_overrides = NULL;
    (*newcontext)->cur_override = NULL;
   
    /*
     * Read the Root Hints file; has to be read before resolver config file 
     */
    if ((retval = read_root_hints_file(*newcontext)) != VAL_NO_ERROR) {
        goto err;
    }

    /*
     * Read the Resolver configuration file 
     */
    if ((retval = read_res_config_file(*newcontext)) != VAL_NO_ERROR) {
        goto err;
    }

    /*
     * Read the validator configuration file 
     */
    (*newcontext)->q_list = NULL;
    (*newcontext)->a_list = NULL;
    if ((retval =
         read_val_config_file(*newcontext, label)) != VAL_NO_ERROR) {
        goto err;
    }

    val_log(*newcontext, LOG_DEBUG, "Context created with %s %s %s", 
                            (*newcontext)->dnsval_conf,
                            (*newcontext)->resolv_conf,
                            (*newcontext)->root_conf);

    return VAL_NO_ERROR;

err:
    val_free_context(*newcontext);
    *newcontext = NULL;
    val_log(NULL, LOG_ERR, "Could not create context");
    return retval;
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
    if (context == NULL)
        return;

#ifndef VAL_NO_THREADS
    pthread_rwlock_destroy(&context->respol_rwlock);
    pthread_rwlock_destroy(&context->valpol_rwlock);
    pthread_mutex_destroy(&context->ac_lock);
#endif

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
    if (context == NULL) 
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
    if (context == NULL) 
        return;

    if (read_val_config_file(context, context->label) != VAL_NO_ERROR) {
        context->v_timestamp = -1;
        val_log(context, LOG_WARNING, "Validator configuration could not be read; using older values");
        return; 
    }
}

void 
val_refresh_root_hints(val_context_t * context)
{
    if (context == NULL)
        return;

    if (read_root_hints_file(context) != VAL_NO_ERROR) {
        context->h_timestamp = -1;
        val_log(context, LOG_WARNING, "Root Hints could not be read; using older values");
        return; 
    }
}

