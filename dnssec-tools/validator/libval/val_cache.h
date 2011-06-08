/*
 * Copyright 2005-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_CACHE_H
#define VAL_CACHE_H


int             stow_zone_info(struct rrset_rec **new_info, struct val_query_chain *matched_q);
int             stow_key_info(struct rrset_rec **new_info, struct val_query_chain *matched_q);
int             stow_ds_info(struct rrset_rec **new_info, struct val_query_chain *matched_q);
int             stow_answers(struct rrset_rec **new_info, struct val_query_chain *matched_q);
int             stow_negative_answers(struct rrset_rec **new_info, struct val_query_chain *matched_q);
int             get_cached_rrset(struct val_query_chain *matched_q, struct domain_info **response);
int             free_validator_cache(void);
int             store_ns_for_zone(u_char * zonecut_n,
                                  struct name_server *resp_server);
int             get_nslist_from_cache(val_context_t *ctx,
                                      struct queries_for_query *matched_qfq,
                                      struct queries_for_query **queries,
                                      struct name_server **ref_ns_list,
                                      u_char **zonecut_n,
                                      u_char *ns_cred);

#endif
