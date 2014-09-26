/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_RESQUERY_H
#define VAL_RESQUERY_H

/* alias cannot match the following types */
#define ALIAS_MATCH_TYPE(type_h) ((type_h != ns_t_any &&    \
                                   type_h != ns_t_rrsig &&  \
                                   type_h != ns_t_dnskey && \
                                   type_h != ns_t_ds && \
                                   type_h != ns_t_soa) ? 1 : 0)

struct glue_fetch_bucket {
    struct queries_for_query *qfq;
    struct glue_fetch_bucket *next_dep;
    struct glue_fetch_bucket *next_bucket;
};

int             fix_glue(val_context_t * context,
                         struct queries_for_query **queries,
                         int *data_missing);
int             res_zi_unverified_ns_list(val_context_t *context,
                                          struct name_server **ns_list,
                                          u_char * zone_name,
                                          struct rrset_rec
                                          *unchecked_zone_info, struct name_server
                                          **pending_glue);
int             find_nslist_for_query(val_context_t * context,
                                      struct queries_for_query *next_qfq,
                                      struct queries_for_query **queries);
int             bootstrap_referral(val_context_t *context,
                                   u_char * referral_zone_n,
                                   struct rrset_rec *learned_zones,
                                   struct queries_for_query *matched_qfq,
                                   struct queries_for_query **queries,
                                   struct name_server **ref_ns_list);
void            free_referral_members(struct delegation_info *del);
int             process_cname_dname_responses(u_char *name_n, 
                              u_int16_t type_h, 
                              u_char *rdata, 
                              struct val_query_chain *matched_q,
                              struct qname_chain **qnames,
                              int *referral_error);
int             val_resquery_send(val_context_t * context,
                                  struct queries_for_query *matched_qfq);
int             val_resquery_rcv(val_context_t * context,
                                 struct queries_for_query *matched_qfq,
                                 struct domain_info **response,
                                 struct queries_for_query **queries,
                                 fd_set *pending_desc,
                                 struct timeval *closest_event);
void            val_res_cancel(struct val_query_chain *matched_q);
void            val_res_nsfallback(val_context_t *context, 
                                   struct val_query_chain *matched_q,
                                   struct name_server *server,
                                   struct timeval *closest_event);

#ifndef VAL_NO_ASYNC

int             val_resquery_async_send(val_context_t * context,
                                        struct queries_for_query *matched_qfq);
int             val_resquery_async_rcv(val_context_t * context,
                                       struct queries_for_query *matched_qfq,
                                       struct domain_info **response,
                                       struct queries_for_query **queries,
                                       fd_set *pending_desc,
                                       struct timeval *closest_event);
#endif /* VAL_NO_ASYNC */

#endif                          /* VAL_RESQUERY_H */
