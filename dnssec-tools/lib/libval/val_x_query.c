
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <resolv.h>

#include <resolver.h>
#include <validator.h>
#include "val_cache.h"
#include "val_support.h"

/*
 * Function: compose_merged_answer
 *
 * Purpose: Convert the results returned by the validator in the form
 *          of a response similar to res_query.
 *          The scope of this function is limited to this file.
 *
 * Parameters:
 *              name_n -- The domain name.
 *              type_h -- The DNS type.
 *             class_h -- The DNS class.
 *             results -- A linked list of val_result structures returned
 *                        by the validator's resolve_n_check function.
 *            response -- A buffer in which to return the answer.
 *                        This must be pre-allocated by the caller.
 *     response_length -- A pointer to an integer variable that holds the
 *                        length of the 'response' buffer.  On return, this
 *                        will contain the length of 'response' buffer
 *                        that was filled by this function.
 *               flags -- Currently ignored.  This will be used in future to
 *                        influence the evaluation and returned results.
 *
 * Return value: 0 on success, and a non-zero error-code on failure.
 */
static int compose_merged_answer( const u_char *name_n,
				  const u_int16_t type_h,
				  const u_int16_t class_h,
				  struct val_result *results,
				  unsigned char *response,
				  int *response_length,
				  val_status_t *val_status,
				  u_int8_t flags )
{
	int retval = NO_ERROR;
	struct val_result *res = NULL;
	int buflen;
	int proof = 0;
	int ancount = 0; // Answer Count
	int nscount = 0; // Authority Count
	int arcount = 0; // Additional Count
	int anbufindex = 0, nsbufindex = 0, arbufindex = 0;
	char *anbuf = NULL, *nsbuf = NULL, *arbuf = NULL;
	int an_auth = 1;
	int ns_auth = 1;
	unsigned char *rp = NULL;

	if ((response == NULL) || response_length == NULL || (*response_length) <= 0) 
		return BAD_ARGUMENT;

	buflen = *response_length;
	*response_length = 0; /* value-result parameter */
	*val_status = VALIDATE_SUCCESS;

	/**** Construct the message ****/	

	/* Header */
	rp = response;
	HEADER *hp = (HEADER *)rp; 
	if (sizeof(HEADER) > buflen) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
	bzero(hp, sizeof(HEADER));
	*response_length += sizeof(HEADER);
	rp += sizeof(HEADER);
	
	/*  Question section */
	int len = wire_name_length(name_n);
	if (*response_length + len > buflen) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
	memcpy (rp, name_n, len);
	*response_length += len;
	rp += len;
	
	if (*response_length + sizeof(u_int16_t) > buflen) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
	NS_PUT16(type_h, rp);
	*response_length += 2;
	
	if (*response_length + sizeof(u_int16_t) > buflen) {h_errno = NETDB_INTERNAL; return NO_SPACE;}
	NS_PUT16(class_h, rp);
	*response_length += 2;
	
	hp->qdcount = htons(1);
	
	/* Iterate over the results returned by the validator */
	for (res = results; res; res=res->next) {
		int resplen;

		if ((*response_length) >= buflen) {

			if (proof)
				retval = NO_ERROR;
			else
				retval = NO_SPACE;

			goto cleanup;
		}

		if (res->as) {
			struct rrset_rec *rrset = res->as->ac_data;
			unsigned char *cp, *ep;
			int *bufindex = NULL;

			if (rrset->rrs_section == SR_FROM_ANSWER) {
				if (anbuf == NULL) {
					anbuf = (unsigned char *) malloc (buflen * sizeof(unsigned char));
					if (anbuf == NULL) {
						h_errno = NETDB_INTERNAL; retval = NO_SPACE; goto cleanup;
					}
				}
				cp = anbuf + anbufindex;
				ep = anbuf + buflen;
				bufindex = &anbufindex;
			}
			else if (rrset->rrs_section == SR_FROM_AUTHORITY) {
				if (nsbuf == NULL) {
					nsbuf = (unsigned char *) malloc (buflen * sizeof(unsigned char));
					if (nsbuf == NULL) {
						h_errno = NETDB_INTERNAL; retval = NO_SPACE; goto cleanup;
					}
				}
				cp = nsbuf + nsbufindex;
				ep = nsbuf + buflen;
				bufindex = &nsbufindex;
			}
			else if (rrset->rrs_section == SR_FROM_ADDITIONAL) {
				if (arbuf == NULL) {
					arbuf = (unsigned char *) malloc (buflen * sizeof(unsigned char));
					if (arbuf == NULL) {
						h_errno = NETDB_INTERNAL; retval = NO_SPACE; goto cleanup;
					}
				}
				cp = arbuf + arbufindex;
				ep = arbuf + buflen;
				bufindex = &arbufindex;
			}
			else {
				continue;
			}

			if (res->status != VALIDATE_SUCCESS) {
				*val_status = res->status;
			}

			/* Answer/Authority/Additional section */
			struct rr_rec *rr;
			for (rr=rrset->rrs_data; rr; rr=rr->rr_next) {
				int len = wire_name_length(rrset->rrs_name_n);

				if (cp + len >= ep) {h_errno = NETDB_INTERNAL; retval = NO_SPACE; goto cleanup;}
				memcpy (cp, rrset->rrs_name_n, len);
				cp += len;
				*bufindex += len;

				if (cp + sizeof(u_int16_t) >= ep) {h_errno = NETDB_INTERNAL; retval = NO_SPACE; goto cleanup;}
				NS_PUT16(rrset->rrs_type_h, cp);
				*bufindex += 2;

				if (cp + sizeof(u_int16_t) >= ep) {h_errno = NETDB_INTERNAL; retval = NO_SPACE; goto cleanup;}
				NS_PUT16(rrset->rrs_class_h, cp);
				*bufindex += 2;

				if (cp + sizeof(u_int32_t) >= ep) {h_errno = NETDB_INTERNAL; retval = NO_SPACE; goto cleanup;}
				NS_PUT32(rrset->rrs_ttl_h, cp);
				*bufindex += 4;

				if (cp + sizeof(u_int16_t) >= ep) {h_errno = NETDB_INTERNAL; retval = NO_SPACE; goto cleanup;}
				NS_PUT16(rr->rr_rdata_length_h, cp);
				*bufindex += 2;

				if (cp + rr->rr_rdata_length_h >= ep) {h_errno = NETDB_INTERNAL; retval = NO_SPACE; goto cleanup;}
				memcpy (cp, rr->rr_rdata, rr->rr_rdata_length_h);
				cp += rr->rr_rdata_length_h;
				*bufindex += rr->rr_rdata_length_h;


				if (rrset->rrs_section == SR_FROM_ANSWER) {
					ancount++;
					if (!val_isauthentic(res->status)) {
						an_auth = 0;
					}
				}
				else if (rrset->rrs_section == SR_FROM_AUTHORITY) {
					nscount++;
					if (!val_isauthentic(res->status)) {
						ns_auth = 0;
					}
					proof = 1;
				}
				else if (rrset->rrs_section == SR_FROM_ADDITIONAL) {
					arcount++;
				}
			} // end for each rr
		} // end if res->as
	} // end for each res

	if (anbuf) {
		if (*response_length + anbufindex > buflen) {h_errno = NETDB_INTERNAL; retval = NO_SPACE; goto cleanup;}
		memcpy(rp, anbuf, anbufindex);
		rp += anbufindex;
		*response_length += anbufindex;
	}

	if (nsbuf) {
		if (*response_length + nsbufindex > buflen) {h_errno = NETDB_INTERNAL; retval = NO_SPACE; goto cleanup;}
		memcpy(rp, nsbuf, nsbufindex);
		rp += nsbufindex;
		*response_length += nsbufindex;
	}

	if (arbuf) {
		if (*response_length + arbufindex > buflen) {h_errno = NETDB_INTERNAL; retval = NO_SPACE; goto cleanup;}
		memcpy(rp, arbuf, arbufindex);
		rp += arbufindex;
		*response_length += arbufindex;
	}

	hp->ancount = htons(ancount);
	hp->nscount = htons(nscount);
	hp->arcount = htons(arcount);

	/* Set the AD bit if all RRSets in the Answer and Authority sections are authentic */
	if (an_auth && ns_auth && ((ancount != 0) || (nscount != 0)))
		hp->ad = 1;
	else
		hp->ad = 0;

	retval = NO_ERROR;

 cleanup:
	if (anbuf) free(anbuf);
	if (nsbuf) free(nsbuf);
	if (arbuf) free(arbuf);

	return retval;

} /* compose_merged_answer() */


/*
 * Function: compose_answer
 *
 * Purpose: Convert the results returned by the validator in the form
 *          of a linked list of val_result structures into a linked
 *          list of val_response structures, as returned by val_query.
 *          The scope of this function is limited to this file.
 *
 * Parameters:
 *              name_n -- The domain name.
 *              type_h -- The DNS type.
 *             class_h -- The DNS class.
 *             results -- A linked list of val_result structures returned
 *                        by the validator's resolve_n_check function.
 *                resp -- An array of val_response structures in which to
 *                        return the answer.  This must be pre-allocated
 *                        by the caller.
 *          resp_count -- A pointer to an integer variable that holds the
 *                        length of the 'resp' array.  On return, this
 *                        will contain the number of elements in the 'resp'
 *                        array that were filled by this function.
 *               flags -- Handles the VAL_QUERY_MERGE_RRSETS flag.  If
 *                        this flag is set, this function will call the
 *                        compose_merged_answer() function above.
 *                        More flags may be added in future to
 *                        influence the evaluation and returned results.
 *
 * Return value: 0 on success, and a non-zero error-code on failure.
 */
static int compose_answer( const u_char *name_n,
			const u_int16_t type_h,
			const u_int16_t class_h,
			struct val_result *results,
			struct val_response *resp,
			int *resp_count,
			u_int8_t flags)
{

	struct val_result *res = results;
	int res_count = *resp_count;
	int proof = 0;

	if ((resp == NULL) || res_count == 0) 
		return BAD_ARGUMENT;

	if (flags & VAL_QUERY_MERGE_RRSETS) {
		int retval = 0;
		retval = compose_merged_answer(name_n, type_h, class_h, results, resp->response, &(resp->response_length),
					       &(resp->val_status), flags);
		if (retval == NO_ERROR) {
			*resp_count = 1;
		}
		return retval;
	}

	*resp_count = 0; /* value-result parameter */

	/* Iterate over the results returned by the validator */
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

		resp[*resp_count].val_status = res->status;
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
			int anscount  = 0;
			for (rr=rrset->rrs_data; rr; rr=rr->rr_next) {
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

			if (rrset->rrs_section == SR_FROM_ANSWER) {
				hp->ancount = htons(anscount);
			}
			else if (rrset->rrs_section == SR_FROM_AUTHORITY) {
				proof = 1;
				hp->nscount = htons(anscount);
			}

			/* Set the AD bit if all RRSets in the Answer and Authority sections are authentic */
			if (val_isauthentic(res->status)) {
				hp->ad = 1;
			}
			else {
				hp->ad = 0;
			}
		}
		resp[*resp_count].response_length = cp - resp[*resp_count].response;
		(*resp_count)++;
	}

	return NO_ERROR;

} /* compose_answer() */


// XXX This routine is provided for compatibility with programs that 
// XXX depend on the res_query() function. 
// XXX If possible, one should use gethostbyname() or getaddrinfo() functions instead.
/*
 * Function: val_query
 *
 * Purpose: A DNSSEC-aware function intended as a replacement to res_query().
 *          The scope of this function is global.
 *
 * This routine makes a query for {domain_name, type, class} and returns the 
 * result in resp. Memory for the response bytes within each
 * val_response structure must be sufficient to hold all the answers returned.
 * If not, those answers are omitted from the result and NO_SPACE is returned.
 * The result of validation for a particular resource record is available in
 * the val_status field of the val_response structure.
 *
 * Parameters:
 * ctx -- The validation context.  May be NULL for default value.
 * domain_name -- The domain name to be queried.  Must not be NULL.
 * class -- The DNS class (typically IN)
 * type  -- The DNS type  (for example: A, CNAME etc.)
 * flags -- 
 * The parameter may be used in future to specify preferences such as the following:
 * TRY_TCP_ON_DOS	Try connecting to the server using TCP when a DOS 
 *			on the resolver is detected 
 * At present only one flag is implemented VAL_QUERY_MERGE_RRSETS.  When this flag
 * is specified, val_query will merge the RRSETs into a single response message.
 * The validation status in this case will be VALIDATE_SUCCESS only if all the
 * individual RRSETs have the VALIDATE_SUCCESS status.  Otherwise, the status
 * will be one of the other error codes.
 * resp -- An array of val_response structures used to return the result.
 * This val_response array must be large enough to 
 * hold all answers. The size allocated by the user must be passed in the 
 * resp_count parameter. If space is insufficient to hold all answers, those 
 * answers are omitted and NO_SPACE is returned. 
 * resp_count -- Points to a variable of type int that contains the length of the
 *               resp array when this function is called.  On return, this will
 *               contain the number of entries in the 'resp' array that were filled
 *               with answers by this function.  'resp_count' must not be NULL.
 * 
 * Return values:
 * NO_ERROR		Operation succeeded
 * BAD_ARGUMENT	        The domain name or other arguments are invalid
 * OUT_OF_MEMORY	Could not allocate enough memory for operation
 * NO_SPACE		Returned when the user allocated memory is not large enough 
 *			to hold all the answers.
 *
 */
int val_query ( const val_context_t *ctx,
		const char *domain_name,
		const u_int16_t class,
		const u_int16_t type,
		const u_int8_t flags,
		struct val_response *resp,
		int *resp_count )
{
	struct query_chain *queries = NULL;	
	struct assertion_chain *assertions = NULL;
	struct val_result *results = NULL;
	int retval;
	val_context_t *context;
	u_char name_n[MAXCDNAME];

	if(ctx == NULL) {
		if(NO_ERROR !=(retval = get_context(NULL, &context)))
			return retval;
	}
	else	
	    context = (val_context_t *) ctx;

	val_log(context, LOG_DEBUG, "val_query called with dname=%s, class=%s, type=%s",
		domain_name, p_class(class), p_type(type));

	if (ns_name_pton(domain_name, name_n, MAXCDNAME-1) == -1) {
		if((ctx == NULL)&& context)
			destroy_context(context);
		return (BAD_ARGUMENT);
	}

	/* Query the validator */
	if(NO_ERROR == (retval = resolve_n_check(context, name_n, type, class, flags, 
											&queries, &assertions, &results))) {
		/* Construct the answer response in resp */
		retval = compose_answer(name_n, type, class, results, resp, resp_count, flags);

/*
		struct val_result *res = results;

		val_log(context, LOG_DEBUG, "\nRESULT OF VALIDATION :\n");
		
		for (res = results; res; res=res->next) {
			if(res->as) {
				val_log_rrset(context, LOG_DEBUG, res->as->ac_data);
			}
			
			val_log (context, LOG_DEBUG, "Validation status = %d\n\n\n", res->status);
		}
*/
	}

	val_log_assertion_chain(context, LOG_DEBUG, name_n, class, type, queries, results);

	/* XXX De-register pending queries */
	free_query_chain(&queries);
	free_assertion_chain(&assertions);
	free_result_chain(&results);

	if((ctx == NULL)&& context)
		destroy_context(context);

//	free_validator_cache();

	return retval;

} /* val_query() */
