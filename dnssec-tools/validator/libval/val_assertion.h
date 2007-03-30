/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_ASSERTION_H
#define VAL_ASSERTION_H

#ifndef VAL_NO_THREADS
 
#define LOCK_QC_SH(qc) do { \
    if (0 != pthread_rwlock_rdlock(&qc->qc_rwlock))\
        return VAL_INTERNAL_ERROR;\
} while (0)

#define LOCK_QC_TRY_EX(qc) \
    (0 == pthread_rwlock_trywrlock(&qc->qc_rwlock))

#define LOCK_QC_EX(qc) do { \
    if (0 != pthread_rwlock_wrlock(&qc->qc_rwlock))\
        return VAL_INTERNAL_ERROR;\
} while (0)

#define UNLOCK_QC(qc) do { \
    if (0 != pthread_rwlock_unlock(&qc->qc_rwlock))\
        return VAL_INTERNAL_ERROR;\
} while (0)

#else

#define LOCK_QC_SH(qc) 
#define LOCK_QC_TRY_EX(qc)
#define LOCK_QC_EX(qc)
#define UNLOCK_QC(qc)

#endif /*VAL_NO_THREADS*/


int             add_to_query_chain(struct val_query_chain **queries,
                                   u_char * name_n, const u_int16_t type_h,
                                   const u_int16_t class_h, 
                                   const u_int8_t flags,
                                   struct val_query_chain **added_q);
int             add_to_qfq_chain(val_context_t *context,
                                 struct queries_for_query **queries,
                                 u_char * name_n, const u_int16_t type_h,
                                 const u_int16_t class_h, 
                                 const u_int8_t flags,
                                 struct queries_for_query **added_q);
void            free_authentication_chain(struct val_digested_auth_chain
                                          *assertions);
void            free_query_chain(struct val_query_chain *queries);
void            zap_query(val_context_t *context, struct val_query_chain *added_q);
int             val_istrusted(val_status_t val_status);
int             val_isvalidated(val_status_t val_status);
int             get_zse(val_context_t * ctx, u_int8_t * name_n, 
                                u_int16_t *tzonestatus, long *ttl_x);
int             find_trust_point(val_context_t * ctx, u_int8_t * zone_n, 
                                u_int8_t ** matched_zone, long *ttl_x);
void            val_free_result_chain(struct val_result_chain *results);
int             try_chase_query(val_context_t * context,
                                u_char * domain_name_n,
                                const u_int16_t q_class,
                                const u_int16_t type,
                                const u_int8_t flags,
                                struct queries_for_query **queries,
                                struct val_result_chain **results,
                                int *done);
int             val_resolve_and_check(val_context_t * context,
                                      u_char * domain_name,
                                      const u_int16_t class,
                                      const u_int16_t type,
                                      const u_int8_t flags,
                                      struct val_result_chain **results);

#endif
