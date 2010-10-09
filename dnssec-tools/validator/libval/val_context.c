/*
 * Copyright 2005-2009 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
/*
 * DESCRIPTION
 * Contains routines for context creation/deletion
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
#include <validator/validator-internal.h>
#include "val_support.h"
#include "val_policy.h"
#include "val_cache.h"
#include "val_assertion.h"
#include "val_context.h"

static val_context_t *the_default_context = NULL;

#ifndef VAL_NO_THREADS

pthread_mutex_t ctx_default =  PTHREAD_MUTEX_INITIALIZER;

#define LOCK_DEFAULT_CONTEXT() do {\
    if (0 != pthread_mutex_lock(&ctx_default))\
        return VAL_INTERNAL_ERROR;\
} while (0)

#define UNLOCK_DEFAULT_CONTEXT() do {\
    if (0 != pthread_mutex_unlock(&ctx_default))\
        return VAL_INTERNAL_ERROR;\
} while (0)
#else
#define LOCK_DEFAULT_CONTEXT()
#define UNLOCK_DEFAULT_CONTEXT()
#endif

/*
 * Create a context with given configuration files
 */
int
val_create_context_with_conf(char *label, 
                             char *dnsval_conf, 
                             char *resolv_conf, 
                             char *root_conf, 
                             val_context_t ** newcontext)
{
    int             retval;
    char *base_dnsval_conf = NULL;
    int is_override = 0;

    if (newcontext == NULL)
        return VAL_BAD_ARGUMENT;

    LOCK_DEFAULT_CONTEXT();

    /* Check if the request is for the default context, and we have one available */
    /* 
     *  either label should be NULL, or if label is not NULL, our global policy should
     *  be set so that environment overrides what ever is passed by the app
     */
    if (the_default_context && 
        (label == NULL || 
         (the_default_context->g_opt && 
          (the_default_context->g_opt->env_policy == VAL_POL_GOPT_OVERRIDE || 
           the_default_context->g_opt->app_policy == VAL_POL_GOPT_OVERRIDE)))) {
        *newcontext = the_default_context;
        UNLOCK_DEFAULT_CONTEXT();
        val_log(*newcontext, LOG_INFO, "reusing default context");
        return VAL_NO_ERROR;
    }

    /* we could be constructing a new default context, so hold on to the context lock */

    *newcontext = (val_context_t *) MALLOC(sizeof(val_context_t));
    if (*newcontext == NULL) {
        UNLOCK_DEFAULT_CONTEXT();
        return VAL_OUT_OF_MEMORY;
    }
    memset(*newcontext, 0, sizeof(val_context_t));

#ifndef VAL_NO_THREADS
    if (0 != pthread_rwlock_init(&(*newcontext)->respol_rwlock, NULL)) {
        FREE(*newcontext);
        *newcontext = NULL;
        UNLOCK_DEFAULT_CONTEXT();
        return VAL_INTERNAL_ERROR;
    }
    if (0 != pthread_rwlock_init(&(*newcontext)->valpol_rwlock, NULL)) {
        pthread_rwlock_destroy(&(*newcontext)->respol_rwlock);
        FREE(*newcontext);
        *newcontext = NULL;
        UNLOCK_DEFAULT_CONTEXT();
        return VAL_INTERNAL_ERROR;
    }
    if (0 != pthread_mutex_init(&(*newcontext)->ac_lock, NULL)) {
        pthread_rwlock_destroy(&(*newcontext)->respol_rwlock);
        pthread_rwlock_destroy(&(*newcontext)->valpol_rwlock);
        FREE(*newcontext);
        *newcontext = NULL;
        UNLOCK_DEFAULT_CONTEXT();
        return VAL_INTERNAL_ERROR;
    }
#endif
        
    if (snprintf
        ((*newcontext)->id, VAL_CTX_IDLEN - 1, "%u",
         (unsigned) (*newcontext)) < 0)
        strcpy((*newcontext)->id, "libval");

    /* 
     * Set default configuration files 
     */
    (*newcontext)->resolv_conf = resolv_conf? strdup(resolv_conf) : resolv_conf_get(); 
    (*newcontext)->r_timestamp = 0;
    (*newcontext)->root_conf = root_conf? strdup(root_conf) : root_hints_get(); 
    (*newcontext)->h_timestamp = 0;

    (*newcontext)->root_ns = NULL; 
    (*newcontext)->nslist = NULL; 

    (*newcontext)->e_pol =
        (policy_entry_t **) MALLOC(MAX_POL_TOKEN * sizeof(policy_entry_t *));
    if ((*newcontext)->e_pol == NULL) {
        retval = VAL_OUT_OF_MEMORY;
        goto err;
    }
    memset(((*newcontext)->e_pol), 0,
           MAX_POL_TOKEN * sizeof(policy_entry_t *));
   
    /*
     * Read the Root Hints file; has to be read before resolver config file 
     */
    if ((retval = read_root_hints_file(*newcontext)) != VAL_NO_ERROR) {
        goto err;
    }

    /* set the log targets to NULL */
    (*newcontext)->val_log_targets = NULL;

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
    base_dnsval_conf = dnsval_conf? strdup(dnsval_conf) : dnsval_conf_get();
    if (base_dnsval_conf == NULL) {
        val_log(*newcontext, LOG_ERR, "val_create_context_with_conf(): No dnsval.conf file configured");
        retval = VAL_CONF_NOT_FOUND;
        goto err;
    }

    /* Add a single node in the dnsval_list structure */
    if (NULL == ((*newcontext)->dnsval_l = 
                (struct dnsval_list *) MALLOC (sizeof(struct dnsval_list))))  {
        FREE(base_dnsval_conf);
        retval = VAL_OUT_OF_MEMORY;
        goto err;
    }
    (*newcontext)->dnsval_l->dnsval_conf = base_dnsval_conf; 
    (*newcontext)->dnsval_l->v_timestamp = 0;
    (*newcontext)->dnsval_l->next = NULL;
    
    if ((retval =
         read_val_config_file(*newcontext, label, &is_override)) != VAL_NO_ERROR) {
        goto err;
    }

    val_log(*newcontext, LOG_DEBUG, 
            "val_create_context_with_conf(): Context created with %s %s %s", 
            (*newcontext)->dnsval_l->dnsval_conf,
            (*newcontext)->resolv_conf,
            (*newcontext)->root_conf);

    if (label == NULL || is_override) {
        the_default_context = *newcontext;
    }
    
    UNLOCK_DEFAULT_CONTEXT();
    
    return VAL_NO_ERROR;

err:
    UNLOCK_DEFAULT_CONTEXT();
    val_free_context(*newcontext);
    *newcontext = NULL;
    return retval;
}

/*
 * Create a context with default configuration files
 */
int
val_create_context(char *label, 
                   val_context_t ** newcontext)
{
    return val_create_context_with_conf(label, NULL, NULL, NULL, newcontext);
}

static int 
unlink_if_default_context(val_context_t *context)
{
    LOCK_DEFAULT_CONTEXT();
    if (context == the_default_context)
        the_default_context = NULL;
    UNLOCK_DEFAULT_CONTEXT();

    return VAL_NO_ERROR;
}

/*
 * Release memory associated with context
 */
void
val_free_context(val_context_t * context)
{
    struct val_query_chain *q;

    if (context == NULL)
        return;

    unlink_if_default_context(context);
    
    /*
     * Forget the NULL context if we are going to be freeing it shortly
     */

#ifndef VAL_NO_THREADS
    pthread_rwlock_destroy(&context->respol_rwlock);
    pthread_rwlock_destroy(&context->valpol_rwlock);
    pthread_mutex_destroy(&context->ac_lock);
#endif

    if (context->label)
        FREE(context->label);

    if (context->search)
        FREE(context->search);

    if (context->resolv_conf)
        FREE(context->resolv_conf);

    if (context->root_conf)
        FREE(context->root_conf);

    if (context->root_ns)
        free_name_servers(&context->root_ns);
    
    destroy_respol(context);
    destroy_valpol(context);
    FREE(context->e_pol);

    while (NULL != (q = context->q_list)) {
        context->q_list = q->qc_next;
        free_query_chain_structure(q);
        FREE(q);
    }

    FREE(context);
}

/*
 * Free all internal state associated with the validator
 * Only used when testing if we have memory leaks
 */
int
val_free_validator_state()
{
    val_context_t * saved_ctx = NULL;

    free_validator_cache();

    LOCK_DEFAULT_CONTEXT();
    if (the_default_context != NULL) {
        /*
         * must clear the_default_context to prevent deadlock
         * in val_free_context.
         */
        saved_ctx = the_default_context;
        the_default_context = NULL;
    }
    UNLOCK_DEFAULT_CONTEXT();

    if (saved_ctx)
        val_free_context(saved_ctx);

    return VAL_NO_ERROR;
}

/*
 * re-read resolver policy into the context
 */
int 
val_refresh_resolver_policy(val_context_t * context)
{
    if (context == NULL) 
        return VAL_NO_ERROR;

    if (read_res_config_file(context) != VAL_NO_ERROR) {
        CTX_LOCK_RESPOL_EX(context);
        context->r_timestamp = -1;
        CTX_UNLOCK_RESPOL(context); 
        val_log(context, LOG_WARNING, 
                "val_refresh_resolver_policy(): Resolver configuration could not be read; using older values");
    }
    return VAL_NO_ERROR; 
}


/*
 * re-read validator policy into the context
 */
int 
val_refresh_validator_policy(val_context_t * context)
{
    struct dnsval_list *dnsval_l;
    int is_override = 0;
    if (context == NULL) 
        return VAL_NO_ERROR;

    if (read_val_config_file(context, context->label, &is_override) != VAL_NO_ERROR) {
        CTX_LOCK_VALPOL_EX(context);
        for(dnsval_l = context->dnsval_l; dnsval_l; dnsval_l=dnsval_l->next)
            dnsval_l->v_timestamp = -1;
        CTX_UNLOCK_VALPOL(context); 
        val_log(context, LOG_WARNING, 
                "val_refresh_validator_policy(): Validator configuration could not be read; using older values");
    }

    if (is_override) {
        LOCK_DEFAULT_CONTEXT();
        the_default_context = context;
        UNLOCK_DEFAULT_CONTEXT();
    }
    
    return VAL_NO_ERROR; 
}

/*
 * re-read root.hints policy into the context
 */
int 
val_refresh_root_hints(val_context_t * context)
{
    if (context == NULL)
        return VAL_NO_ERROR;

    if (read_root_hints_file(context) != VAL_NO_ERROR) {
        CTX_LOCK_RESPOL_EX(context);
        context->h_timestamp = -1;
        CTX_UNLOCK_RESPOL(context); 
        val_log(context, LOG_WARNING, 
                "val_refresh_root_hints(): Root Hints could not be read; using older values");
    }

    return VAL_NO_ERROR;
}

