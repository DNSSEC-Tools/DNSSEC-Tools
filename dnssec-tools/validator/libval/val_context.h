/*
 * Copyright 2006-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_CONTEXT_H
#define VAL_CONTEXT_H

#ifndef VAL_NO_THREADS

#define CTX_LOCK_RESPOL_SH(ctx) do { \
    if (0 != pthread_rwlock_rdlock(&ctx->respol_rwlock))\
        return VAL_INTERNAL_ERROR;\
} while (0)
#define CTX_LOCK_RESPOL_EX(ctx) do { \
    if (0 != pthread_rwlock_wrlock(&ctx->respol_rwlock))\
        return VAL_INTERNAL_ERROR;\
} while (0)
#define CTX_UNLOCK_RESPOL(ctx) do { \
    if (0 != pthread_rwlock_unlock(&ctx->respol_rwlock))\
        return VAL_INTERNAL_ERROR;\
} while (0)
#define CTX_LOCK_VALPOL_SH(ctx) do { \
    if (0 != pthread_rwlock_rdlock(&ctx->valpol_rwlock))\
        return VAL_INTERNAL_ERROR;\
} while (0)
#define CTX_LOCK_VALPOL_EX(ctx) do { \
    if (0 != pthread_rwlock_wrlock(&ctx->valpol_rwlock))\
        return VAL_INTERNAL_ERROR;\
} while (0)
#define CTX_UNLOCK_VALPOL(ctx) do { \
    if (0 != pthread_rwlock_unlock(&ctx->valpol_rwlock))\
        return VAL_INTERNAL_ERROR;\
} while (0)

#define CTX_LOCK_ACACHE(ctx) do {\
    if (0 != pthread_mutex_lock(&ctx->ac_lock))\
        return VAL_INTERNAL_ERROR;\
} while(0);

#define CTX_UNLOCK_ACACHE(ctx) do {\
    if (0 != pthread_mutex_unlock(&ctx->ac_lock))\
        return VAL_INTERNAL_ERROR;\
} while(0);

#else

#define CTX_LOCK_RESPOL_SH(ctx) 
#define CTX_LOCK_RESPOL_EX(ctx)
#define CTX_UNLOCK_RESPOL(ctx)
#define CTX_LOCK_VALPOL_SH(ctx)
#define CTX_LOCK_VALPOL_EX(ctx)
#define CTX_UNLOCK_VALPOL(ctx)
#define CTX_LOCK_ACACHE(ctx) 
#define CTX_UNLOCK_ACACHE(ctx) 

#endif /*VAL_NO_THREADS*/



int             val_create_context_with_conf(char *label,
                                             char *dnsval_conf,
                                             char *resolv_conf,
                                             char *root_conf,
                                             val_context_t ** newcontext);
int             val_create_context(char *label,
                                   val_context_t ** newcontext);
void            val_free_context(val_context_t * context);
int             val_refresh_resolver_policy(val_context_t * context);
int             val_refresh_validator_policy(val_context_t * context);
int             val_refresh_root_hints(val_context_t * context);
int             val_free_validator_state(void);

#endif
