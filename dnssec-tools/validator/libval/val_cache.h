/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_CACHE_H
#define VAL_CACHE_H


int stow_zone_info(struct rrset_rec *new_info);
int stow_key_info(struct rrset_rec *new_info);
int stow_ds_info(struct rrset_rec *new_info);
int stow_root_info(struct rrset_rec *root_info);
int stow_answer(struct rrset_rec *new_info);
int get_cached_rrset(u_int8_t *name_n, u_int16_t class_h, 
		u_int16_t type_h, struct rrset_rec **cloned_answer);
int free_validator_cache();
int get_root_ns(struct name_server **ns);
int get_matching_nslist(struct val_query_chain  *matched_q, 
					struct val_query_chain **queries,
					struct name_server **ref_ns_list);

#endif
