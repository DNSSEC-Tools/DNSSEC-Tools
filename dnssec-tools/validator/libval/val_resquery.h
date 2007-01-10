/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_RESQUERY_H
#define VAL_RESQUERY_H

void            free_referral_members(struct delegation_info *del);
int             res_zi_unverified_ns_list(struct name_server **ns_list,
                                          u_int8_t * zone_name,
                                          struct rrset_rec
                                          *unchecked_zone_info, struct name_server
                                          **pending_glue);
int             bootstrap_referral(u_int8_t * referral_zone_n,
                                   struct rrset_rec **learned_zones,
                                   struct val_query_chain *matched_q,
                                   struct val_query_chain **queries,
                                   struct name_server **ref_ns_list);
int             process_cname_dname_responses(u_int8_t *name_n, 
                              u_int16_t type_h, 
                              u_int8_t *rdata, 
                              struct val_query_chain *matched_q,
                              struct qname_chain **qnames,
                              int *referral_error);
int             extract_glue_from_rdata(struct rr_rec *addr_rr,
                                        struct name_server **ns);
void            merge_glue_in_referral(struct val_query_chain *pc,
                                       struct val_query_chain **queries);
int             find_nslist_for_query(val_context_t * context,
                                      struct val_query_chain *next_q,
                                      struct val_query_chain **queries);
int             val_resquery_send(val_context_t * context,
                                  struct val_query_chain *matched_q);
int             val_resquery_rcv(val_context_t * context,
                                 struct val_query_chain *matched_q,
                                 struct domain_info **response,
                                 struct val_query_chain **queries);

int             find_next_zonecut(val_context_t * context,
                                  struct rrset_rec *rrset,
                                  u_int8_t * curzone_n,
                                  u_int8_t ** name_n);

#endif                          /* VAL_RESQUERY_H */
