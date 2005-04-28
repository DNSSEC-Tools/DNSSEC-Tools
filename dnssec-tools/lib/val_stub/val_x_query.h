
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_QUERY_EX_H
#define VAL_QUERY_EX_H

void lower_name (u_int8_t rdata[], int *index);
int assimilate_answers(val_context_t *context, struct query_chain **queries, 
							struct domain_info *response, struct query_chain *matched_q, 
								struct assertion_chain **assertions);
int val_x_query(val_context_t *ctx,
            const char *domain_name,
            const u_int16_t type,
            const u_int16_t class,
            const u_int16_t flags,
            struct response_t *resp,
            int resp_count);

#endif /* VAL_QUERY_EX_H */
