
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_ASSERTION_H
#define VAL_ASSERTION_H

struct val_result {
	struct assertion_chain *as;
	int status;
	int trusted;
	struct val_result *next;
};

int assimilate_answers(val_context_t *context, struct query_chain **queries, 
							struct domain_info *response, struct query_chain *matched_q, 
								struct assertion_chain **assertions);
int add_to_assertion_chain(struct assertion_chain **assertions, struct rrset_rec *response_data);
void free_assertion_chain(struct assertion_chain **assertions);
void free_result_chain(struct val_result **results);

int resolve_n_check(	val_context_t	*context,
			const char *domain_name,
			const u_int16_t type,
			const u_int16_t class,
			const u_int8_t flags, 
			struct query_chain **queries,
			struct assertion_chain **assertions,
			struct val_result **results);

#endif /* VAL_ASSERTION_H */
