/*
 * Copyright 2006-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_CONTEXT_H
#define VAL_CONTEXT_H

#ifndef VAL_NO_THREADS

#define CTX_LOCK_POL_SH(ctx) \
    do {\
        pthread_rwlock_rdlock(&ctx->pol_rwlock);\
    } while (0)
#define CTX_LOCK_POL_EX(ctx) \
    do {\
        pthread_rwlock_wrlock(&ctx->pol_rwlock);\
    } while (0)
#define CTX_UNLOCK_POL(ctx) \
    do {\
        pthread_rwlock_unlock(&ctx->pol_rwlock);\
    } while (0)
#define CTX_LOCK_ACACHE(ctx)\
    pthread_mutex_lock(&ctx->ac_lock)
#define CTX_UNLOCK_ACACHE(ctx)\
    pthread_mutex_unlock(&ctx->ac_lock)

#else

#define CTX_LOCK_POL_SH(ctx) 
#define CTX_LOCK_POL_EX(ctx)
#define CTX_UNLOCK_POL(ctx) 
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
val_context_t * val_create_or_refresh_context(val_context_t *ctx);
void            val_free_context(val_context_t * context);
int             val_free_validator_state(void);

#ifndef VAL_NO_ASYNC
/* remove asynchronous status from context async queries list */
int             val_context_as_remove(val_context_t *context,
                                      val_async_status *as);
#endif

#endif
