
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_ASSERTION_H
#define VAL_ASSERTION_H


int assimilate_answers(val_context_t *context, struct query_chain **queries, 
							struct domain_info *response, struct query_chain *matched_q, 
								struct assertion_chain **assertions);
int add_to_query_chain(struct query_chain **queries, u_char *name_n, 
						const u_int16_t type_h, const u_int16_t class_h);
int add_to_assertion_chain(struct assertion_chain **assertions, struct rrset_rec *response_data);
void free_query_chain(struct query_chain **queries);
void free_assertion_chain(struct assertion_chain **assertions);
void free_result_chain(struct val_result **results);
int resolve_n_check(	val_context_t	*context,
			u_char *domain_name_n,
			const u_int16_t type,
			const u_int16_t class,
			const u_int8_t flags, 
			struct query_chain **queries,
			struct assertion_chain **assertions,
			struct val_result **results);

#endif /* VAL_ASSERTION_H */
