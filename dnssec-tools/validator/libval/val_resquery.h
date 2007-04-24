/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_RESQUERY_H
#define VAL_RESQUERY_H

struct glue_fetch_bucket {
    struct queries_for_query *qfq[MAX_GLUE_FETCH_DEPTH];
    int qfq_count;
    struct glue_fetch_bucket *next_bucket;
};

void            free_referral_members(struct delegation_info *del);
int             res_zi_unverified_ns_list(struct name_server **ns_list,
                                          u_int8_t * zone_name,
                                          struct rrset_rec
                                          *unchecked_zone_info, struct name_server
                                          **pending_glue);
int             bootstrap_referral(val_context_t *context,
                                   u_int8_t * referral_zone_n,
                                   struct rrset_rec **learned_zones,
                                   struct queries_for_query *matched_qfq,
                                   struct queries_for_query **queries,
                                   struct name_server **ref_ns_list);
int             process_cname_dname_responses(u_int8_t *name_n, 
                              u_int16_t type_h, 
                              u_int8_t *rdata, 
                              struct val_query_chain *matched_q,
                              struct qname_chain **qnames,
                              int *referral_error);
int             extract_glue_from_rdata(struct rr_rec *addr_rr,
                                        struct name_server **ns);
int             merge_glue_in_referral(val_context_t *context,
                                       struct queries_for_query *qfq_pc,
                                       struct glue_fetch_bucket *bucket,
                                       struct queries_for_query **queries);
int             find_nslist_for_query(val_context_t * context,
                                      struct queries_for_query *next_qfq,
                                      struct queries_for_query **queries);
int             val_resquery_send(val_context_t * context,
                                  struct queries_for_query *matched_qfq);
int             val_resquery_rcv(val_context_t * context,
                                 struct queries_for_query *matched_qfq,
                                 struct domain_info **response,
                                 struct queries_for_query **queries);

#endif                          /* VAL_RESQUERY_H */
