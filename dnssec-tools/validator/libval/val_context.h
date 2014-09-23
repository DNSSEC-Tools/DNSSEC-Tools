/*
 * Copyright 2006-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_CONTEXT_H
#define VAL_CONTEXT_H

#ifndef VAL_NO_THREADS

#ifdef CTX_LOCK_COUNTS
#define CTX_LOCK_COUNT_INC(ctx,it) ++ctx->it
#define CTX_LOCK_COUNT_DEC(ctx,it) --ctx->it
#include <assert.h>
#define ASSERT_HAVE_AC_LOCK(ctx)                                        \
    do {                                                                \
        if (1 != ctx->ac_count) {                                       \
            val_log(NULL,LOG_WARNING,"FAILED: lock count %d", ctx->ac_count); \
            fflush(NULL);                                               \
        }                                                               \
        assert(ctx->ac_count == 1);                                     \
    } while(0)
#else
#define CTX_LOCK_COUNT_INC(ctx,it)
#define CTX_LOCK_COUNT_DEC(ctx,it)
#define ASSERT_HAVE_AC_LOCK(ctx)
#endif
#define CTX_LOCK_POL_SH(ctx) \
    do {\
        pthread_rwlock_rdlock(&ctx->pol_rwlock);\
        CTX_LOCK_COUNT_INC(ctx,pol_count);\
    } while (0)
#define CTX_LOCK_POL_EX(ctx) \
    do {\
        pthread_rwlock_wrlock(&ctx->pol_rwlock);\
        CTX_LOCK_COUNT_INC(ctx,pol_count);\
    } while (0)
#define CTX_LOCK_POL_EX_TRY(ctx) \
       (0 == pthread_rwlock_trywrlock(&ctx->pol_rwlock)) 
#define CTX_UNLOCK_POL(ctx) \
    do {\
        CTX_LOCK_COUNT_DEC(ctx,pol_count);\
        pthread_rwlock_unlock(&ctx->pol_rwlock);\
    } while (0)
#define CTX_LOCK_ACACHE(ctx) \
    do {                                        \
        pthread_mutex_lock(&ctx->ac_lock);      \
        CTX_LOCK_COUNT_INC(ctx,ac_count);       \
    } while (0)
#define CTX_UNLOCK_ACACHE(ctx) \
    do {                                        \
        CTX_LOCK_COUNT_DEC(ctx,ac_count);       \
        pthread_mutex_unlock(&ctx->ac_lock);    \
    } while (0)

#else

#define CTX_LOCK_POL_SH(ctx) 
#define CTX_LOCK_POL_EX(ctx)
#define CTX_LOCK_POL_EX_TRY(ctx) (1 == 1)
#define CTX_UNLOCK_POL(ctx) 
#define CTX_LOCK_ACACHE(ctx) 
#define CTX_UNLOCK_ACACHE(ctx)

#define CTX_LOCK_COUNT_INC(ctx,it)
#define CTX_LOCK_COUNT_DEC(ctx,it)
#define ASSERT_HAVE_AC_LOCK(ctx)

#endif /*VAL_NO_THREADS*/

int             val_create_context_with_conf(const char *label,
                                             char *dnsval_conf,
                                             char *resolv_conf,
                                             char *root_conf,
                                             val_context_t ** newcontext);
int             val_create_context_ex(const char *label, 
                                      val_context_opt_t *opt,
                                      val_context_t ** newcontext);
int             val_create_context(const char *label,
                                   val_context_t ** newcontext);
val_context_t * val_create_or_refresh_context(val_context_t *ctx);
void            val_free_context(val_context_t * context);
int             val_free_validator_state(void);
int             val_context_setqflags(val_context_t *context,
                                      unsigned char action,
                                      unsigned int flags);
int             val_is_local_trusted(val_context_t *context, int *trusted);
int             val_context_store_ns_for_zone(val_context_t *context, 
                                    char * zone, char *resp_server,
                                    int recursive);
int             _val_free_zone_nslist(struct zone_ns_map_t *zone_ns_map);
int             _val_store_ns_in_map(u_char * zonecut_n, struct name_server *ns, 
                                     struct zone_ns_map_t **zone_ns_map);
int             _val_get_mapped_ns(val_context_t *context,
                              u_char *qname_n,
                              u_int16_t qtype,
                              u_char **zonecut_n,
                              struct name_server **ref_ns_list);
int             _val_context_ip4(val_context_t * context);
int             _val_context_ip6(val_context_t * context);

#ifndef VAL_NO_ASYNC
/* remove asynchronous status from context async queries list */
int             val_context_as_remove(val_context_t *context,
                                      val_async_status *as);
#endif

#endif
