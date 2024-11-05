/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
/*
 * DESCRIPTION
 * Contains routines for context creation/deletion
 */ 
#include "validator-internal.h"

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

#include <openssl/conf.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif /* !defined(OPENSSL_NO_ENGINE) */
#include <openssl/err.h>
#include "val_support.h"
#include "val_policy.h"
#include "val_cache.h"
#include "val_assertion.h"
#include "val_context.h"

#define GET_LATEST_TIMESTAMP(ctx, file, cur_ts, new_ts) do { \
    memset(&new_ts, 0, sizeof(struct stat));\
    if (!file) {\
        if (cur_ts != 0) {\
            val_log(ctx, LOG_WARNING, "val_resolve_and_check(): %s missing; trying to operate without it.", file);\
        }\
    } else {\
        if(0 != stat(file, &new_ts)) {\
            val_log(ctx, LOG_WARNING, "val_resolve_and_check(): %s missing; trying to operate without it.", file);\
        }\
    }\
}while (0)


static val_context_t *the_default_context = NULL;

#ifdef WIN32
static int wsaInitialized = 0;
WSADATA wsaData;
#endif

#ifndef VAL_NO_THREADS

pthread_mutex_t ctx_default =  PTHREAD_MUTEX_INITIALIZER;
#define LOCK_DEFAULT_CONTEXT() \
    pthread_mutex_lock(&ctx_default)
#define UNLOCK_DEFAULT_CONTEXT() \
    pthread_mutex_unlock(&ctx_default)

#else
#define LOCK_DEFAULT_CONTEXT()
#define UNLOCK_DEFAULT_CONTEXT()
#endif


#ifdef VAL_REFCOUNTS
#ifdef HAVE_PTHREAD_H
#  define CTX_LOCK_REFCNT(ctx)    pthread_mutex_lock(&(ctx)->ref_lock)
#  define CTX_UNLOCK_REFCNT(ctx)  pthread_mutex_unlock(&(ctx)->ref_lock)
#else
#  define CTX_LOCK_REFCNT()
#  define CTX_UNLOCK_REFCNT()
#endif /* HAVE_PTHREAD_H */
#endif


/*
 * check if we have ipv4/ipv6 addresses
 */
static void
_have_addrs(int *have4, int *have6) {
#ifndef HAVE_GETIFADDRS
    /* Return availability of both */
    if (have4)
        *have4 = 1;
    if (have6)
        *have6 = 1;
#else
    struct ifaddrs *ifaddr, *ifa;
    in_addr_t addr;
    struct in6_addr addr6;
    int family;

    if (NULL == have4
#ifdef VAL_IPV6
       && NULL == have6
#endif
       ) {
        return;
    }

    val_log(NULL, LOG_INFO, "_have_addrs(): checking for A/AAAA addrs");

    if (have4)
        *have4 = 0;
    if (have6)
        *have6 = 0;

    if (getifaddrs(&ifaddr) == -1) {
        val_log(NULL, LOG_ERR, "getifaddrs failed");
        return;
    }

    /* Walk through linked list, maintaining head pointer so we
       can free list later */

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (have4 && family == AF_INET && *have4 == 0) {
            addr = ((struct sockaddr_in *) (ifa->ifa_addr))->sin_addr.s_addr;
            if ((ifa->ifa_flags & IFF_UP)
#ifdef IFF_RUNNING
                && (ifa->ifa_flags & IFF_RUNNING)
#endif                          /* IFF_RUNNING */
                && !(ifa->ifa_flags & IFF_LOOPBACK)
                && addr != INADDR_LOOPBACK) {
                ++*have4;
                val_log(NULL, LOG_INFO, "have v4 addr!");
            }
        }
#ifdef VAL_IPV6
        else if (have6 && family == AF_INET6 && *have6 == 0) {
            addr6 = ((struct sockaddr_in6 *) (ifa->ifa_addr))->sin6_addr;
            if ((ifa->ifa_flags & IFF_UP)
#ifdef IFF_RUNNING
                && (ifa->ifa_flags & IFF_RUNNING)
#endif                          /* IFF_RUNNING */
                && !(ifa->ifa_flags & IFF_LOOPBACK)
                && !IN6_IS_ADDR_LOOPBACK(&addr6)
                && !IN6_IS_ADDR_LINKLOCAL(&addr6)
                ) {
                ++*have6;
                val_log(NULL, LOG_INFO, "have v6 addr!");
            }
        }
#endif
        else
            continue;
        if ((NULL == have4 || *have4) 
#ifdef VAL_IPV6
             && (NULL == have6 || *have6)
#endif
           )
            break;
    } /* for ifrp */
    goto cleanup;

  cleanup:
    freeifaddrs(ifaddr);
#endif
}

/*
 * re-read resolver policy into the context
 */
static int 
val_refresh_resolver_policy(val_context_t * context)
{
    if (context == NULL) 
        return VAL_NO_ERROR;

    if (read_res_config_file(context) != VAL_NO_ERROR) {
        context->r_timestamp = -1;
        val_log(context, LOG_WARNING, 
                "val_refresh_resolver_policy(): Resolver configuration could not be read; using older values");
    }
    return VAL_NO_ERROR; 
}


/*
 * re-read validator policy into the context
 */
static int 
val_refresh_validator_policy(val_context_t * context)
{
    struct dnsval_list *dnsval_l;

    if (context == NULL) 
        return VAL_NO_ERROR;

    if (read_val_config_file(context, context->label) != VAL_NO_ERROR) {
        for(dnsval_l = context->dnsval_l; dnsval_l; dnsval_l=dnsval_l->next)
            dnsval_l->v_timestamp = -1;
        val_log(context, LOG_WARNING, 
                "val_refresh_validator_policy(): Validator configuration could not be read; using older values");
    }

    return VAL_NO_ERROR; 
}

/*
 * re-read root.hints policy into the context
 */
static int 
val_refresh_root_hints(val_context_t * context)
{
    if (context == NULL)
        return VAL_NO_ERROR;

    if (read_root_hints_file(context) != VAL_NO_ERROR) {
        context->h_timestamp = -1;
        val_log(context, LOG_WARNING, 
                "val_refresh_root_hints(): Root Hints could not be read; using older values");
    }

    return VAL_NO_ERROR;
}
/*
 * Function: val_refresh_context
 *
 * Purpose:   set up context for a query
 *
 * Parameter: results -- results for query
 *            ctx -- user supplied context, if any
 *
 * Returns:   VAL_NO_ERROR or error code to return to user
 *
 */
static int
val_refresh_context(val_context_t *context)
{
    struct stat rsb, vsb, hsb;
    struct dnsval_list *dnsval_l;
    int retval;

    if (NULL == context)
        return VAL_BAD_ARGUMENT;

    /* 
     * Don't refresh the context if someone else is using it
     */
    if (!CTX_LOCK_POL_EX_TRY(context)) {
        return VAL_NO_ERROR;
    }
    CTX_LOCK_COUNT_INC(context,pol_count); /* only needed for EX_TRY */

    GET_LATEST_TIMESTAMP(context, context->resolv_conf, context->r_timestamp,
                         rsb);
    if (rsb.st_mtime != 0 &&  rsb.st_mtime != context->r_timestamp) {
        if (VAL_NO_ERROR != (retval = val_refresh_resolver_policy(context))) {
            goto err;
        }
    }    
    GET_LATEST_TIMESTAMP(context, context->root_conf, context->h_timestamp, hsb);
    if (hsb.st_mtime != 0 &&  hsb.st_mtime != context->h_timestamp){
        if (VAL_NO_ERROR != (retval = val_refresh_root_hints(context))) {
            goto err;
        }
    }

    /* dnsval.conf can point to a list of files */
    for (dnsval_l = context->dnsval_l; dnsval_l; dnsval_l=dnsval_l->next) {
        GET_LATEST_TIMESTAMP(context,  dnsval_l->dnsval_conf, 
                             dnsval_l->v_timestamp, vsb);
        if (vsb.st_mtime != 0 &&  vsb.st_mtime != dnsval_l->v_timestamp) {
            retval = val_refresh_validator_policy(context);
            if (VAL_NO_ERROR != retval) {
                goto err;
            }
            break;
        }
    }

    retval = VAL_NO_ERROR;

err:
    CTX_UNLOCK_POL(context);
    return retval;

}

/*
 * Create a context with given configuration files
 * If the resulting context translates to the default context,
 * then set the global value of default_context, but only if 
 * it was NULL. I.E. don't override a previously set 
 * default_context.
 */
static int
val_create_context_internal( const char *label, 
                             unsigned int flags,
                             unsigned int polflags,
                             char *valpol,
                             char *res_nslist,
                             char *dnsval_conf, 
                             char *resolv_conf, 
                             char *root_conf, 
                             val_global_opt_t *valpolopt,
                             val_context_t ** newcontext)
{
    int             retval;
    struct policy_overrides *dyn_valpol;
    val_global_opt_t *dyn_valpolopt;
    struct name_server *dyn_nslist;
    struct name_server *ns;
    struct name_server *ns_tail;
    char *buf_ptr, *end_ptr;
    int  line_number;
    struct policy_fragment *pol_frag;
    int g_opt_seen;
    int include_seen;
    char *resptr;
    char *resend;
    char *rescur;
    char token[TOKEN_MAX];
    unsigned long ns_options = 0;

#ifdef WIN32 
    if (!wsaInitialized) {
        wsaInitialized = 1;
        if (0 != WSAStartup(0x202, &wsaData)) {
            return VAL_INTERNAL_ERROR;
        }
    }
#endif

    if (newcontext == NULL)
        return VAL_BAD_ARGUMENT;

    *newcontext = NULL;

    /*
     * Process any dynamic policy components
     */ 
    dyn_valpolopt = NULL;
    dyn_valpol = NULL;
    dyn_nslist = NULL;

    if (valpolopt != NULL) {
        if (VAL_NO_ERROR != 
                (retval = update_dynamic_gopt(&dyn_valpolopt,
                                              valpolopt))) {
            goto err;
        }
        if (valpolopt->log_target)
            dyn_valpolopt->log_target = strdup(valpolopt->log_target);
    }
    if (valpol != NULL) {
        buf_ptr = valpol;
        end_ptr = valpol + strlen(valpol) + 1;
        pol_frag = NULL;
        line_number = 1;
        g_opt_seen = 0;
        include_seen = 0;
        while (VAL_NO_ERROR == (retval =
                    get_next_policy_fragment(&buf_ptr, end_ptr,
                                             label,
                                             &pol_frag,
                                             &line_number,
                                             &g_opt_seen,
                                             &include_seen))) {
            if (!g_opt_seen && !include_seen) {
                store_policy_overrides(&dyn_valpol, &pol_frag);
                pol_frag = NULL;
            }
            if (buf_ptr >= end_ptr) {
                /* done reading policy string */
                break;
            }
        }
        if (retval != VAL_NO_ERROR) {
            goto err;
        }
    }
    if (res_nslist != NULL && strcmp(res_nslist, "")) {
        strncpy(token, res_nslist, sizeof(token));
        resptr = token;
        resend = resptr+strlen(token)+1;
        rescur = resptr;
        ns_tail = NULL;

        while (rescur < resend) {
            /* 
             * parse the string of name servers
             * into individual name server structures
             */
            if ((*rescur == ' ') || (*rescur == '\t') || (*rescur == ';')) {
                if (rescur == resptr) {
                    /* read past leading spaces */
                    rescur++;
                    resptr = rescur;
                    continue;
                }
            } else if (*rescur != '\0'){
                rescur++;
                continue;
            }

            *rescur = '\0';
            rescur++;
 
            /* Set RD unless we're asked to disable recursion */
            if (polflags & CTX_DYN_POL_RES_NRD) {
                ns_options = SR_QUERY_NOREC;
            } else {
                ns_options = SR_QUERY_RECURSE;
            }
            ns = parse_name_server(resptr, NULL, ns_options);

            /* Ignore name servers that we don't understand */
            if (ns != NULL) {
                if (ns_tail == NULL) {
                    dyn_nslist = ns;
                    ns_tail = ns;
                } else {
                    ns_tail->ns_next = ns;
                    ns_tail = ns;
                }
            }
            resptr = rescur;
        }
        if (dyn_nslist == NULL) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }
    }

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

        /* Update the dynamic policies */
        if (the_default_context->dyn_valpolopt != NULL) {
            if (the_default_context->dyn_valpolopt->log_target)
                FREE(the_default_context->dyn_valpolopt->log_target);
            FREE(the_default_context->dyn_valpolopt);
        }
        the_default_context->dyn_valpolopt = dyn_valpolopt;
        dyn_valpolopt = NULL;

        if (the_default_context->dyn_valpol != NULL) {
            destroy_valpolovr(&the_default_context->dyn_valpol);
        }
        the_default_context->dyn_valpol = dyn_valpol;
        dyn_valpol = NULL;

        if (the_default_context->dyn_nslist != NULL) {
            free_name_servers(&the_default_context->dyn_nslist);
        }
        the_default_context->dyn_nslist = dyn_nslist;
        dyn_nslist = NULL;

        the_default_context->dyn_polflags = polflags;

        *newcontext = the_default_context;

        /* have configuration files changed? */
        retval = val_refresh_context(the_default_context);

        UNLOCK_DEFAULT_CONTEXT();

        if (VAL_NO_ERROR != retval) {
            goto err;
        }

#ifdef VAL_REFCOUNTS
        CTX_LOCK_REFCNT(*newcontext);
        ++(*newcontext)->refcount;
        CTX_UNLOCK_REFCNT(*newcontext);
#endif

        val_log(*newcontext, LOG_INFO, "reusing default context");
        return retval;
    }
    UNLOCK_DEFAULT_CONTEXT();

    *newcontext = (val_context_t *) MALLOC(sizeof(val_context_t));
    if (*newcontext == NULL) {
        retval = VAL_OUT_OF_MEMORY;
        goto err;
    }
    memset(*newcontext, 0, sizeof(val_context_t));
#ifdef VAL_REFCOUNTS
    ++(*newcontext)->refcount; /* don't need lock, it's a new object */
#endif

#ifndef VAL_NO_THREADS
    if (0 != pthread_rwlock_init(&(*newcontext)->pol_rwlock, NULL)) {
        FREE(*newcontext);
        *newcontext = NULL;
        retval = VAL_INTERNAL_ERROR;
        goto err;
    }
    if (0 != pthread_mutex_init(&(*newcontext)->ac_lock, NULL)) {
        pthread_rwlock_destroy(&(*newcontext)->pol_rwlock);
        FREE(*newcontext);
        *newcontext = NULL;
        retval = VAL_INTERNAL_ERROR;
        goto err;
    }

#ifdef HAVE_PTHREAD_H
    if (0 != pthread_mutex_init(&(*newcontext)->ref_lock, NULL)) {
        pthread_rwlock_destroy(&(*newcontext)->pol_rwlock);
        pthread_mutex_destroy(&(*newcontext)->ac_lock);
        FREE(*newcontext);
        *newcontext = NULL;
        retval = VAL_INTERNAL_ERROR;
        goto err;
    }
#endif
#endif

    if (snprintf
        ((*newcontext)->id, VAL_CTX_IDLEN - 1, "%lu", (u_long)(*newcontext)) < 0)
        strcpy((*newcontext)->id, "libval");

    /* check if we have ipv4 and ipv6 addresses */
    _have_addrs(&(*newcontext)->have_ipv4, &(*newcontext)->have_ipv6);

    /* 
     * Set default configuration files 
     */
    (*newcontext)->resolv_conf = resolv_conf? strdup(resolv_conf) : resolv_conf_get(); 
    (*newcontext)->r_timestamp = 0;
    (*newcontext)->root_conf = root_conf? strdup(root_conf) : root_hints_get(); 
    (*newcontext)->h_timestamp = 0;

    (*newcontext)->root_ns = NULL; 
    (*newcontext)->nslist = NULL; 
    (*newcontext)->search = NULL; 
    (*newcontext)->zone_ns_map = NULL; 
    (*newcontext)->dyn_polflags = polflags;

    (*newcontext)->dyn_valpolopt = dyn_valpolopt;
    (*newcontext)->dyn_valpol = dyn_valpol;
    (*newcontext)->dyn_nslist = dyn_nslist;
    dyn_valpolopt = NULL;
    dyn_valpol = NULL;
    dyn_nslist = NULL;

    (*newcontext)->e_pol =
        (policy_entry_t **) MALLOC(MAX_POL_TOKEN * sizeof(policy_entry_t *));
    if ((*newcontext)->e_pol == NULL) {
        retval = VAL_OUT_OF_MEMORY;
        goto err;
    }
    memset(((*newcontext)->e_pol), 0,
           MAX_POL_TOKEN * sizeof(policy_entry_t *));
   
    (*newcontext)->val_log_targets = NULL;
    (*newcontext)->q_list = NULL;
    (*newcontext)->as_list = NULL;
    (*newcontext)->def_cflags = 0; 
    (*newcontext)->def_uflags = flags & VAL_QFLAGS_USERMASK; 

    /*
     * Read the validator configuration file first. Some of the policy
     * knobs may affect parsing of resolver and root hints files.
     */
    (*newcontext)->base_dnsval_conf = dnsval_conf? strdup(dnsval_conf) : dnsval_conf_get();
    if ((retval =
         read_val_config_file(*newcontext, label)) != VAL_NO_ERROR) {
        goto err;
    }

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

    if ((*newcontext)->val_log_targets != NULL) {
        (*newcontext)->def_cflags |= VAL_QUERY_AC_DETAIL;
    }

    val_log(*newcontext, LOG_DEBUG, 
            "val_create_context_with_conf(): Context created with %s %s %s", 
            (*newcontext)->base_dnsval_conf,
            (*newcontext)->resolv_conf,
            (*newcontext)->root_conf);

    if (label == NULL) {
        /*
         * Set the default context if this was not set earlier.
         * We do not override a previously set default context,
         * since that context might still be in use.
         * We could have checked if the reference count for the
         * previous default context was 0 before freeing it up, 
         * but that would make the behaviour of val_create_context_with_conf()
         * non-deterministic.
         */
        LOCK_DEFAULT_CONTEXT();
        if (the_default_context == NULL)
            the_default_context = *newcontext;
        UNLOCK_DEFAULT_CONTEXT();
    }
    
    return VAL_NO_ERROR;

err:
    if (dyn_valpolopt) {
        if (dyn_valpolopt->log_target)
            FREE(dyn_valpolopt->log_target);
        FREE(dyn_valpolopt);
    }
    if (dyn_valpol)
        destroy_valpolovr(&dyn_valpol);
    if (dyn_nslist)
        free_name_servers(&dyn_nslist);
    if (*newcontext)
        val_free_context(*newcontext);
    *newcontext = NULL;
    return retval;
}

/*
 * Create a context with given configuration files
 */
int
val_create_context_with_conf(const char *label, 
                             char *dnsval_conf, 
                             char *resolv_conf, 
                             char *root_conf, 
                             val_context_t ** newcontext)
{
    return val_create_context_internal(label, 0, 0, NULL, NULL,
                dnsval_conf, resolv_conf, root_conf, NULL, newcontext); 
}

/*
 * Create a context with given configuration files
 * and with the given default query flags
 */
int
val_create_context_ex(const char *label,
                      val_context_opt_t *opt,
                      val_context_t ** newcontext)
{

    if (opt == NULL)
        return VAL_BAD_ARGUMENT;

    return val_create_context_internal(label, 
                opt->vc_qflags, 
                opt->vc_polflags, 
                opt->vc_valpol,
                opt->vc_nslist,
                opt->vc_val_conf, 
                opt->vc_res_conf, 
                opt->vc_root_conf, 
                opt->vc_gopt, 
                newcontext); 
}


/*
 * Create a context with default configuration files
 */
int
val_create_context(const char *label, 
                   val_context_t ** newcontext)
{
    return val_create_context_internal(label, 0, 0, NULL, 
                NULL, NULL, NULL, NULL, NULL, newcontext);
}

/*
 * Function: val_create_or_refresh_context
 *
 * Purpose:   set up context for a query
 *
 *
 * Parameter: results -- results for query
 *            ctx -- user supplied context, if any
 *
 * Returns:   VAL_NO_ERROR or error code to return to user
 *
 * NOTE: This function obtains a shared lock on the context's policy. 
 */
val_context_t *
val_create_or_refresh_context(val_context_t *ctx)
{
    val_context_t *context = NULL;
    int retval;

    if (ctx == NULL) {
        /* return the default context */
        if (VAL_NO_ERROR != (retval = val_create_context(NULL, &context)))
            return NULL;
    } else {
        /* have configuration files changed? */
        context = ctx;
        if (VAL_NO_ERROR != (retval = val_refresh_context(context))) {
            return NULL;
        }
    }

    CTX_LOCK_POL_SH(context);

    return context;
}

/*
 * Release memory associated with context
 */
void
val_free_context(val_context_t * context)
{
    struct val_query_chain *q;
    int has_refs = 0;

    if (context == NULL)
        return;
    
    /*
     * never free context that has multiple users
     */
    LOCK_DEFAULT_CONTEXT();
    if (!CTX_LOCK_POL_EX_TRY(context)) {
        has_refs = 1;
    } else {
        CTX_LOCK_COUNT_INC(context,pol_count); /* only needed for EX_TRY */
        if (context == the_default_context) {
            /* we'll be freeing up the default context */
            the_default_context = NULL;
        }
    }
    UNLOCK_DEFAULT_CONTEXT();

#ifdef VAL_REFCOUNTS
    CTX_LOCK_REFCNT(context);
    if (--context->refcount > 0)
        has_refs = 1;
    CTX_UNLOCK_REFCNT(context);
#endif

    if (has_refs)
        return;

    /* 
     * we have an exclusive policy lock here, but we don't bother
     * unlocking since we're going to destroy it anyway.
     */

#ifndef VAL_NO_ASYNC
    /** cancel uses locks, so this must be before locks are destroyed */
    val_async_cancel_all(context, 0);
#endif

    CTX_UNLOCK_POL(context);
#ifndef VAL_NO_THREADS
    pthread_rwlock_destroy(&context->pol_rwlock);
    pthread_mutex_destroy(&context->ac_lock);
#endif

    if (context->label)
        FREE(context->label);

    if (context->search)
        FREE(context->search);

    if (context->zone_ns_map)
        _val_free_zone_nslist(context->zone_ns_map);

    if (context->resolv_conf)
        FREE(context->resolv_conf);

    if (context->root_conf)
        FREE(context->root_conf);

    if (context->root_ns)
        free_name_servers(&context->root_ns);

    if (context->dyn_valpolopt) {
        if (context->dyn_valpolopt->log_target)
            FREE(context->dyn_valpolopt->log_target);
        FREE(context->dyn_valpolopt);
    }

    if (context->dyn_valpol)
        destroy_valpolovr(&context->dyn_valpol);

    if (context->dyn_nslist)
        free_name_servers(&context->dyn_nslist);

    destroy_respol(context);
    destroy_valpol(context);
    FREE(context->e_pol);

    while (NULL != (q = context->q_list)) {
        context->q_list = q->qc_next;
        free_query_chain_structure(q);
        q = NULL;
    }
    if (context->base_dnsval_conf)
        FREE(context->base_dnsval_conf);
    

    FREE(context);
}

/*
 * Free all internal state associated with the validator
 * There should be no active contexts when this function
 * is invoked.
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

#ifdef WIN32
    WSACleanup();
#endif

    /* Whole bunch of openssl cleanup routines */
    CONF_modules_unload(1); 
    EVP_cleanup(); 
#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup(); 
#endif
    CRYPTO_cleanup_all_ex_data(); 
#if HAVE_ERR_REMOVE_THREAD_STATE
    ERR_remove_thread_state(NULL);
#elif HAVE_ERR_REMOVE_STATE
    ERR_remove_state(0);
#endif /* else we do nothing, because it's no longer needed?? */
    ERR_free_strings(); 

    return VAL_NO_ERROR;
}

int 
val_context_setqflags(val_context_t *context, 
                      unsigned char action, 
                      unsigned int flags)
{
    val_context_t *ctx = NULL;

    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL) { 
        return VAL_INTERNAL_ERROR;
    }
   
    /* Lock exclusively */
    CTX_LOCK_ACACHE(ctx);

    if (action == VAL_CTX_FLAG_SET) {
        ctx->def_uflags |= flags;
        val_log(ctx, LOG_DEBUG, 
                "val_context_setqflags(): default user query flags after SET %x", 
                ctx->def_uflags);
    } else if (action == VAL_CTX_FLAG_RESET) {
        ctx->def_uflags ^= (ctx->def_uflags & flags);
        val_log(ctx, LOG_DEBUG, 
                "val_context_setqflags(): default user query flags after RESET %x", 
                ctx->def_uflags);
    }
    
    CTX_UNLOCK_ACACHE(ctx);

    CTX_UNLOCK_POL(ctx);

    return VAL_NO_ERROR;
}  

int
val_is_local_trusted(val_context_t *context, int *trusted)
{
    val_context_t *ctx = NULL;

    if (trusted == NULL)
        return VAL_BAD_ARGUMENT;

    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL)
        return VAL_INTERNAL_ERROR;

    if (ctx && ctx->g_opt && ctx->g_opt->local_is_trusted)
        *trusted = 1;
    else
        *trusted = 0;

    CTX_UNLOCK_POL(ctx);

    return VAL_NO_ERROR;    
}


int
_val_store_ns_in_map(u_char * zonecut_n, struct name_server *ns, 
                     struct zone_ns_map_t **zone_ns_map)
{
    struct zone_ns_map_t *map_e;

    if (!zonecut_n || !ns || !zone_ns_map)
        return VAL_BAD_ARGUMENT;

    for (map_e = *zone_ns_map; map_e; map_e = map_e->next) {

        if (!namecmp(map_e->zone_n, zonecut_n)) {
            struct name_server *nslist = NULL;
            /*
             * add blindly to the list 
             */
            clone_ns_list(&nslist, ns);
            nslist->ns_next = map_e->nslist;
            map_e->nslist = nslist;
            break;
        }
    }

    if (!map_e) {
        map_e =
            (struct zone_ns_map_t *) MALLOC(sizeof(struct zone_ns_map_t));
        if (map_e == NULL) {
            return VAL_OUT_OF_MEMORY;
        }

        clone_ns_list(&map_e->nslist, ns);
        memcpy(map_e->zone_n, zonecut_n, wire_name_length(zonecut_n));
        map_e->next = NULL;

        if (*zone_ns_map != NULL)
            map_e->next = *zone_ns_map;
        *zone_ns_map = map_e;
    }

    return VAL_NO_ERROR;
}

/*
 * Maintain a mapping between the zone and the name server that answered 
 * data for it 
 */
int
val_context_store_ns_for_zone(val_context_t *context, char * zone, 
                              char *resp_server, int recursive)
{
    struct name_server *ns;
    int retval;
    val_context_t *ctx;
    struct val_query_chain *q;
    u_char zone_n[NS_MAXCDNAME];
    unsigned long options = SR_QUERY_RECURSE;

    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL) { 
        return VAL_INTERNAL_ERROR;
    }

    /* Lock exclusively */
    CTX_LOCK_ACACHE(ctx);

    if (!recursive) {
        options |= SR_QUERY_NOREC;
    }

    if (resp_server && zone&& 
        (-1 != ns_name_pton(zone, zone_n, sizeof(zone_n))) && 
        (NULL != (ns = parse_name_server(resp_server, NULL, 
                                         options)))) {
        retval = _val_store_ns_in_map(zone_n, ns, &ctx->zone_ns_map);
    } else {
        retval = VAL_BAD_ARGUMENT;
    }

    /* Flush queries that match this name */
    for(q=ctx->q_list; q; q=q->qc_next) {
        if (NULL != namename(q->qc_name_n, zone_n)) {
            q->qc_flags |= VAL_QUERY_MARK_FOR_DELETION;
        }
    }

    CTX_UNLOCK_ACACHE(ctx);

    CTX_UNLOCK_POL(ctx);

    return retval;
}

int
_val_free_zone_nslist(struct zone_ns_map_t *zone_ns_map)
{
    struct zone_ns_map_t *map_e;

    while (zone_ns_map) {
        map_e = zone_ns_map;
        zone_ns_map = zone_ns_map->next;

        if (map_e->nslist)
            free_name_servers(&map_e->nslist);
        FREE(map_e);
    }

    return VAL_NO_ERROR;
}

int 
_val_get_mapped_ns(val_context_t *ctx, 
                   u_char *qname_n,
                   u_int16_t qtype,
                   u_char **zonecut_n,
                   struct name_server **ref_ns_list) 
{
    struct zone_ns_map_t *map_e, *saved_map;
    u_char *p = NULL;

    if (ctx == NULL || qname_n == NULL || zonecut_n == NULL || ref_ns_list == NULL)
        return VAL_BAD_ARGUMENT;

    *zonecut_n = NULL;
    *ref_ns_list = NULL;
    saved_map = NULL;

    for (map_e = ctx->zone_ns_map; map_e; map_e = map_e->next) {

        /*
         * check if zone is within query 
         */
        if (NULL != (p = namename(qname_n, map_e->zone_n))) {
            if (p == qname_n && qtype == ns_t_ds) {
                /* 
                 * If we're looking for the DS, we shouldn't return an
                 * exact match 
                 */
                continue;

            }
            if (!saved_map || (namecmp(p, saved_map->zone_n) > 0)) {
                saved_map = map_e;
            }
        }
    }

    if (saved_map) {
        *zonecut_n = (u_char *) MALLOC (wire_name_length(saved_map->zone_n) *
                sizeof (u_char));
        if (*zonecut_n == NULL) {
            return VAL_OUT_OF_MEMORY;
        } 
        clone_ns_list(ref_ns_list, saved_map->nslist);
        memcpy(*zonecut_n, saved_map->zone_n, wire_name_length(saved_map->zone_n));
    }

    return VAL_NO_ERROR;
}

int
_val_context_ip4(val_context_t *ctx)
{
    int retval;

    if (ctx == NULL)
        return 0;

    /* No IPv4 if we're only configured to use IPv6 */
    if (ctx->g_opt && 
        ctx->g_opt->proto == VAL_POL_GOPT_PROTO_IPV6) {
        retval = 0;
    }
    retval = ctx->have_ipv4;

    return retval;
}

int
_val_context_ip6(val_context_t *ctx)
{
    int retval;

    if (ctx == NULL)
        return 0;

    /* No IPv6 if we're only configured to use IPv4 */
    if (ctx->g_opt && 
        ctx->g_opt->proto == VAL_POL_GOPT_PROTO_IPV4) {
        retval = 0;
    }
    retval = ctx->have_ipv6;

    return retval;
}
