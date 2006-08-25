/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_RESQUERY_H
#define VAL_RESQUERY_H

void free_referral_members(struct delegation_info *del);
int res_zi_unverified_ns_list(struct name_server **ns_list,
			u_int8_t *zone_name, struct rrset_rec *unchecked_zone_info, 
			struct name_server **pending_glue);
int bootstrap_referral(u_int8_t            *referral_zone_n,
                        struct rrset_rec    **learned_zones,
                        struct val_query_chain  *matched_q,
                        struct val_query_chain **queries,
                        struct name_server **ref_ns_list);
int extract_glue_from_rdata(struct rr_rec *addr_rr, struct name_server **ns);
void merge_glue_in_referral(struct val_query_chain *pc, struct val_query_chain **queries);
int val_resquery_send (	val_context_t           *context,
                        struct val_query_chain      *matched_q);
int val_resquery_rcv ( 	
					val_context_t *context,
					struct val_query_chain *matched_q,
					struct domain_info **response,
					struct val_query_chain **queries);

int find_next_zonecut(struct rrset_rec *rrset, u_int8_t *curzone_n, u_int8_t **name_n);

#define SAVE_RR_TO_LIST(respondent_server, listtype, name_n, type_h, set_type_h,\
				class_h, ttl_h, rdata, rdata_len_h, from_section, authoritive, zonecut_n) \
	do { \
            struct rrset_rec *rr_set;\
            int ret_val;\
            rr_set = find_rr_set (respondent_server, &listtype, name_n, type_h, set_type_h,\
                             class_h, ttl_h, rdata, from_section,authoritive, zonecut_n);\
            if (rr_set==NULL) return VAL_OUT_OF_MEMORY;\
            rr_set->rrs_ans_kind = SR_ANS_STRAIGHT;\
            if (type_h != ns_t_rrsig)\
            {\
                /* Add this record to its chain of rr_rec's. */\
                if ((ret_val = add_to_set(rr_set,rdata_len_h,rdata))!=VAL_NO_ERROR) \
                    return ret_val;\
            }\
            else\
            {\
                /* Add this record to the sig of rrset_rec. */\
                if ((ret_val = add_as_sig(rr_set,rdata_len_h,rdata))!=VAL_NO_ERROR)\
                    return ret_val;\
            }\
	} while (0)

#endif /* VAL_RESQUERY_H */
