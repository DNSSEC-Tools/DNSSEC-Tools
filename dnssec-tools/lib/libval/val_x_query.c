
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/nameser.h>

#include <resolver.h>
#include "validator.h"
#include "val_cache.h"


// XXX This routine is provided for compatibility with some programs that 
// XXX depend on this interface. 
// XXX One should normally use getfoobybar() instead
/*
 * This routine makes a query for {domain_name, type, class} and returns the 
 * result in response_t. Memory for the response bytes within 
 * response_t must be sufficient to hold all the answers returned. If not, those 
 * answers are omitted from the result and NO_SPACE is returned. The result of
 * validation for a particular resource record is available in validation_result. 
 * The response_t array passed to val_query, resp, must be large enough to 
 * hold all answers. The size allocated by the user must be passed in the 
 * resp_count parameter. If space is insufficient to hold all answers, those 
 * answers are omitted and NO_SPACE is returned. 
 * 
 * XXX We may need flags later on to specify preferences such as the following:
 * TRY_TCP_ON_DOS		Try connecting to the server using TCP when a DOS 
 *						on the resolver is detected 
 *
 * Return values:
 * NO_ERROR			Operation succeeded
 * BAD_ARGUMENT	The domain name is invalid
 * OUT_OF_MEMORY	Could not allocate enough memory for operation
 * NO_SPACE		Returned when the user allocated memory is not large enough 
 *					to hold all the answers.
 *
 */
int compose_answer( const char *name_n,
			const u_int16_t type_h,
			const u_int16_t class_h,
			struct val_result *results,
			struct response_t *resp,
			int *resp_count,
			u_int8_t flags);

int val_x_query(val_context_t	*ctx,
			const char *domain_name,
			const u_int16_t class,
			const u_int16_t type,
			const u_int8_t flags,
			struct response_t *resp,
			int *resp_count)
{
	struct query_chain *queries = NULL;	
	struct assertion_chain *assertions = NULL;
	struct val_result *results = NULL;
	int retval;
	val_context_t *context;
	u_char name_n[MAXCDNAME];

	if(ctx == NULL) {
		context = get_context(NULL);
		if (context == NULL)
			return CONTEXT_ERROR;
	}
	else	
		context = ctx;

	if (ns_name_pton(domain_name, name_n, MAXCDNAME-1) == -1)
		return (BAD_ARGUMENT);                                                                                                                         
	if(NO_ERROR == (retval = resolve_n_check(context, name_n, type, class, flags, 
											&queries, &assertions, &results))) {
		/* XXX Construct the answer response in response_t */
		retval = compose_answer(name_n, type, class, results, resp, resp_count, flags);

/*
		struct val_result *res = results;

		printf("\nRESULT OF VALIDATION :\n");
		
		for (res = results; res; res=res->next) {
			if(res->as) {
				dump_rrset(res->as->ac_data);
			}
			
			printf ("Validation status = %d\n\n\n", res->status);
		}
*/
	}

	/* XXX De-register pending queries */
	free_query_chain(&queries);
	free_assertion_chain(&assertions);
	free_result_chain(&results);

	if(ctx == NULL)	
		destroy_context(context);

	free_validator_cache();

	return retval;
}

int compose_answer( const char *name_n,
			const u_int16_t type_h,
			const u_int16_t class_h,
			struct val_result *results,
			struct response_t *resp,
			int *resp_count,
			u_int8_t flags)
{

	struct val_result *res = results;
	int res_count = *resp_count;
	int proof = 0;

	if ((resp == NULL) || res_count == 0) 
		return BAD_ARGUMENT;

	*resp_count = 0; /* value-result parameter */
	for (res = results; res; res=res->next) {
		unsigned char *cp, *ep;
		int resplen;

		if ((*resp_count) >= res_count) {

			if (proof)
				return NO_ERROR;

			/* Return the total count in resp_count */ 
			for (;res; res=res->next)
				(*resp_count)++;
			return NO_SPACE;
		}

		resp[*resp_count].validation_result = res->status;
		cp = resp[*resp_count].response;
		resplen = resp[*resp_count].response_length;

		if ((cp == NULL) || ((resplen) == 0))
			return BAD_ARGUMENT;
		ep = cp + resplen;

		if (res->as) {
			/* Construct the message */	

			struct rrset_rec *rrset = res->as->ac_data;
			HEADER *hp = (HEADER *)cp; 
			if (cp + sizeof(HEADER) >= ep) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
			bzero(hp, sizeof(HEADER));
			cp += sizeof(HEADER);


			/*  Question section */
			int len = wire_name_length(name_n);
			if (cp + len >= ep) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
			memcpy (cp, name_n, len);
			cp += len;
			
			if (cp + sizeof(u_int16_t) >= ep) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
			NS_PUT16(type_h, cp);

			if (cp + sizeof(u_int16_t) >= ep) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
			NS_PUT16(class_h, cp);
	
			hp->qdcount = htons(1);

			/* Answer section */
			struct rr_rec *rr;
			int anscount = 0;
			for (rr=res->as->ac_data->rrs_data; rr; rr=rr->rr_next) {
				int len = wire_name_length(rrset->rrs_name_n);

				if (cp + len >= ep) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
				memcpy (cp, rrset->rrs_name_n, len);
				cp += len;
				if (cp + sizeof(u_int16_t) >= ep) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
				NS_PUT16(rrset->rrs_type_h, cp);

				if (cp + sizeof(u_int16_t) >= ep) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
				NS_PUT16(rrset->rrs_class_h, cp);

				if (cp + sizeof(u_int32_t) >= ep) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
				NS_PUT32(rrset->rrs_ttl_h, cp);

				if (cp + sizeof(u_int16_t) >= ep) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
				NS_PUT16(rr->rr_rdata_length_h, cp);

				if (cp + rr->rr_rdata_length_h >= ep) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
				memcpy (cp, rr->rr_rdata, rr->rr_rdata_length_h);
				cp += rr->rr_rdata_length_h;

				anscount++;
			}

			if (res->as->ac_data->rrs_section == SR_FROM_ANSWER)
				hp->ancount = htons(anscount);
			else if (res->as->ac_data->rrs_section == SR_FROM_AUTHORITY) {
				proof = 1;
				hp->nscount = htons(anscount);
			}
		}
		resp[*resp_count].response_length = cp - resp[*resp_count].response;
		(*resp_count)++;
	}

	return NO_ERROR;
}

