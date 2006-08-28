
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#include "validator-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <resolv.h>

#include <resolver.h>
#include <validator.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#else
#include "arpa/header.h"
#endif

#include "val_cache.h"
#include "val_support.h"
#include "val_x_query.h"
#include "val_log.h"
#include "val_assertion.h"

#define OUTER_HEADER_LEN (sizeof(HEADER) + wire_name_length(name_n) + sizeof(u_int16_t) + sizeof(u_int16_t))

/* Calculate rrset length */
// xxx-audit: unused parameter name_n
//     if it's not needed, why not get rid of it?
static int find_rrset_len(const u_char *name_n, struct rrset_rec *rrset)
{ 
	struct rr_rec *rr;
	int resp_len = 0;
	int rrset_name_n_len;

	if (rrset == NULL)
		return 0;

	rrset_name_n_len = wire_name_length(rrset->rrs.val_rrset_name_n);
	for (rr=rrset->rrs.val_rrset_data; rr; rr=rr->rr_next) {
		resp_len += rrset_name_n_len + sizeof(u_int16_t) + sizeof(u_int16_t) + sizeof(u_int32_t) 
						+ sizeof(u_int16_t) + rr->rr_rdata_length_h; 
	} 
	return resp_len;
}

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
 *             results -- A linked list of val_result_chain structures returned
 *                        by the validator's val_resolve_and_check function.
 *                resp -- A buffer in which to return the answer.
 *
 * Return value: 0 on success, and a non-zero error-code on failure.
 */
static int compose_merged_answer( const u_char *name_n,
				  const u_int16_t type_h,
				  const u_int16_t class_h,
				  struct val_result_chain *results,
				  struct val_response *resp)
{
	struct val_result_chain *res = NULL;
	int proof = 0;
	int ancount = 0; // Answer Count
	int nscount = 0; // Authority Count
	int arcount = 0; // Additional Count
	int anbufindex = 0, nsbufindex = 0, arbufindex = 0;
	unsigned char *anbuf = NULL, *nsbuf = NULL, *arbuf = NULL;
	int an_auth = 1;
	int ns_auth = 1;
	unsigned char *rp = NULL;
	int resp_len = 0; 
	HEADER *hp;
	int len;

	if ((resp == NULL) || (name_n == NULL))
		return VAL_BAD_ARGUMENT;
	resp->vr_val_status = VAL_SUCCESS;
	resp->vr_next = NULL;

	/* Calculate the length of the response buffer */
	for (res = results; res; res=res->val_rc_next) {
		if (res->val_rc_trust && res->val_rc_trust->_as.ac_data) {
			resp_len += find_rrset_len(name_n, res->val_rc_trust->_as.ac_data);	
		}
	}
	if (resp_len == 0)
	    return VAL_INTERNAL_ERROR;

	resp->vr_response = (unsigned char *)MALLOC ((resp_len + OUTER_HEADER_LEN) * sizeof (unsigned char));
	if (resp->vr_response == NULL)
		return VAL_OUT_OF_MEMORY;
	resp->vr_length = (resp_len + OUTER_HEADER_LEN);

	/* temporary buffers for different sections */
	anbuf = (unsigned char *) MALLOC (resp_len * sizeof(unsigned char));
	nsbuf = (unsigned char *) MALLOC (resp_len * sizeof(unsigned char));
	arbuf = (unsigned char *) MALLOC (resp_len * sizeof(unsigned char));
	if ((anbuf == NULL) || (nsbuf == NULL) || (arbuf == NULL)) {
		if(anbuf != NULL)
			FREE(anbuf);
		if(nsbuf != NULL)
			FREE(nsbuf);
		if(arbuf != NULL)
			FREE(arbuf);
		FREE(resp->vr_response);
		resp->vr_response = NULL;
		resp->vr_length = 0;
		return VAL_OUT_OF_MEMORY;
	}

	/* Header */
	rp = resp->vr_response;
	hp = (HEADER *)rp; 
	bzero(hp, sizeof(HEADER));
	rp += sizeof(HEADER);
	
	/*  Question section */
	len = wire_name_length(name_n);
	memcpy (rp, name_n, len);
	rp += len;
	NS_PUT16(type_h, rp);
	NS_PUT16(class_h, rp);
	hp->qdcount = htons(1);

	/**** Construct the message ****/	
	
	/* Iterate over the results returned by the validator */
	for (res = results; res; res=res->val_rc_next) {
		struct rrset_rec *rrset;
		unsigned char *cp;
		int *bufindex = NULL;
		struct rr_rec *rr;
		int rrset_name_n_len;

		if (!res->val_rc_trust || !res->val_rc_trust->_as.ac_data)
			continue;

		rrset = res->val_rc_trust->_as.ac_data;
		if (rrset->rrs.val_rrset_section == VAL_FROM_ANSWER) {
			cp = anbuf + anbufindex;
			bufindex = &anbufindex;
			ancount++;
			if (!val_isauthentic(res->val_rc_status)) {
				an_auth = 0;
			}
		}
		else if (rrset->rrs.val_rrset_section == VAL_FROM_AUTHORITY) {
			cp = nsbuf + nsbufindex;
			bufindex = &nsbufindex;
			nscount++;
			if (!val_isauthentic(res->val_rc_status)) {
				ns_auth = 0;
			}
			proof = 1;
		}
		else if (rrset->rrs.val_rrset_section == VAL_FROM_ADDITIONAL) {
			cp = arbuf + arbufindex;
			bufindex = &arbufindex;
			arcount++;
		}
		else {
			continue;
		}

		if (res->val_rc_status != VAL_SUCCESS) {
			resp->vr_val_status = res->val_rc_status;
		}

		/* Answer/Authority/Additional section */
		rrset_name_n_len = wire_name_length(rrset->rrs.val_rrset_name_n);
		for (rr=rrset->rrs.val_rrset_data; rr; rr=rr->rr_next) {

			if ((*bufindex + rrset_name_n_len + 10 + rr->rr_rdata_length_h) > resp_len) {
				/* log error message? */
				goto err;
			}
			
			memcpy (cp, rrset->rrs.val_rrset_name_n, rrset_name_n_len);
			cp += rrset_name_n_len;
			NS_PUT16(rrset->rrs.val_rrset_type_h, cp);
			NS_PUT16(rrset->rrs.val_rrset_class_h, cp);
			NS_PUT32(rrset->rrs.val_rrset_ttl_h, cp);
			NS_PUT16(rr->rr_rdata_length_h, cp);
			memcpy (cp, rr->rr_rdata, rr->rr_rdata_length_h);
			cp += rr->rr_rdata_length_h;

		} // end for each rr

		*bufindex += find_rrset_len(name_n, rrset); 
		if (*bufindex > resp_len) {
			/* log error message? */
			goto err;
		}

	} // end for each res

	if (anbuf) {
		memcpy(rp, anbuf, anbufindex);
		rp += anbufindex;
	}

	if (nsbuf) {
		memcpy(rp, nsbuf, nsbufindex);
		rp += nsbufindex;
	}

	if (arbuf) {
		memcpy(rp, arbuf, arbufindex);
		rp += arbufindex;
	}

	hp->ancount = htons(ancount);
	hp->nscount = htons(nscount);
	hp->arcount = htons(arcount);

	/* Set the AD bit if all RRSets in the Answer and Authority sections are authentic */
	if (an_auth && ns_auth && ((ancount != 0) || (nscount != 0)))
		hp->ad = 1;
	else
		hp->ad = 0;

	FREE(anbuf);
	FREE(nsbuf);
	FREE(arbuf);

	return VAL_NO_ERROR;

  err:
	FREE(anbuf);
	FREE(nsbuf);
	FREE(arbuf);
	FREE(resp->vr_response);
	resp->vr_response = NULL;
	resp->vr_length = 0;
	return VAL_INTERNAL_ERROR;

} /* compose_merged_answer() */


/*
 * Function: compose_answer
 *
 * Purpose: Convert the results returned by the validator in the form
 *          of a linked list of val_result_chain structures into a linked
 *          list of val_response structures, as returned by val_query.
 *          The scope of this function is limited to this file.
 *
 * Parameters:
 *              name_n -- The domain name.
 *              type_h -- The DNS type.
 *             class_h -- The DNS class.
 *             results -- A linked list of val_result_chain structures returned
 *                        by the validator's val_resolve_and_check function.
 *                resp -- The structures within which answers are to be returned 
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
			struct val_result_chain *results,
			struct val_response **resp,
			u_int8_t flags)
{

	struct val_result_chain *res = results;
	struct val_response *new_resp, *last_resp;
	int proof = 0;

	if (resp == NULL)
		return VAL_BAD_ARGUMENT;

	if (flags & VAL_QUERY_MERGE_RRSETS) {
		int retval = 0;
		/* Allocate a single element of the val_response array to hold the result */
		*resp = (struct val_response *) MALLOC (sizeof (struct val_response));
		if (*resp == NULL)
			return VAL_OUT_OF_MEMORY;
		(*resp)->vr_response = NULL;
		(*resp)->vr_length = 0;
		retval = compose_merged_answer(name_n, type_h, class_h, results, *resp);
		return retval;
	}

	last_resp = NULL;

	/* Iterate over the results returned by the validator */
	for (res = results; 
			res && res->val_rc_trust && res->val_rc_trust->_as.ac_data; 
				res=res->val_rc_next) {

		unsigned char *cp;
		struct rr_rec *rr;
		struct rrset_rec *rrset = res->val_rc_trust->_as.ac_data;
		HEADER *hp;
		int len, anscount, rrset_name_n_len;
		
		new_resp = (struct val_response *) MALLOC (sizeof (struct val_response));
		if (new_resp == NULL)
			return VAL_OUT_OF_MEMORY;
		/* add this to the response linked-list */
		if (last_resp != NULL) {
			last_resp->vr_next = new_resp;
		}
		else {
			*resp = new_resp;
		}
		last_resp = new_resp;
		new_resp->vr_response = NULL;
		new_resp->vr_length = 0;
		new_resp->vr_val_status = res->val_rc_status;
		new_resp->vr_next = NULL;

		/* The response size has to be allocated to the following size:
		 * sizeof(HEADER) + 
		 * 
		 * wire_name_length(name_n) +
		 * 	sizeof(u_int16_t) +
		 *	sizeof(u_int16_t) +
		 *	
		 * [wire_name_length(rrset->rrs.val_rrset_name_n) +
		 *		sizeof(u_int16_t) + sizeof(u_int16_t) + sizeof(u_int32_t) +		
		 *		sizeof(u_int16_t) + rr->rr_rdata_length_h] for each rr
		 */
		/* Calculate length of response */
		new_resp->vr_length = find_rrset_len(name_n, rrset) + OUTER_HEADER_LEN;
		new_resp->vr_response = (unsigned char *) MALLOC (new_resp->vr_length * sizeof(unsigned char));
		if (new_resp->vr_response == NULL)
			return VAL_OUT_OF_MEMORY; 

		/* fill in response contents */
		cp = new_resp->vr_response;

		hp = (HEADER *)cp; 
		bzero(hp, sizeof(HEADER));
		cp += sizeof(HEADER);

		/*  Question section */
		len = wire_name_length(name_n);
		if ((len + sizeof(HEADER)) > new_resp->vr_length)
		    return VAL_INTERNAL_ERROR;
		memcpy (cp, name_n, len);
		cp += len;
		len += sizeof(HEADER);
			
		if ((len + 4) > new_resp->vr_length)
		    return VAL_INTERNAL_ERROR;
		NS_PUT16(type_h, cp);
		NS_PUT16(class_h, cp);
		hp->qdcount = htons(1);
		len += 4;

		/* Answer section */
		anscount  = 0;
		rrset_name_n_len = wire_name_length(rrset->rrs.val_rrset_name_n);
		for (rr=rrset->rrs.val_rrset_data; rr; rr=rr->rr_next) {

			if ((len + rrset_name_n_len + 10 + rr->rr_rdata_length_h) > new_resp->vr_length)
				return VAL_INTERNAL_ERROR;
			memcpy (cp, rrset->rrs.val_rrset_name_n, rrset_name_n_len);
			cp += rrset_name_n_len;
			len += rrset_name_n_len;
			NS_PUT16(rrset->rrs.val_rrset_type_h, cp);
			NS_PUT16(rrset->rrs.val_rrset_class_h, cp);
			NS_PUT32(rrset->rrs.val_rrset_ttl_h, cp);
			NS_PUT16(rr->rr_rdata_length_h, cp);
			len += 10;
			memcpy (cp, rr->rr_rdata, rr->rr_rdata_length_h);
			cp += rr->rr_rdata_length_h;
			len += rr->rr_rdata_length_h;
			anscount++;
		}

		if (rrset->rrs.val_rrset_section == VAL_FROM_ANSWER) {
			hp->ancount = htons(anscount);
		}
		else if (rrset->rrs.val_rrset_section == VAL_FROM_AUTHORITY) {
			proof = 1;
			hp->nscount = htons(anscount);
		}

		/* Set the AD bit if all RRSets in the Answer and Authority sections are authentic */
		if (val_isauthentic(res->val_rc_status)) {
			hp->ad = 1;
		}
		else {
			hp->ad = 0;
		}
	}

	return VAL_NO_ERROR;

} /* compose_answer() */


/* This routine is provided for compatibility with programs that 
 * depend on the res_query() function. 
 * If possible, one should use gethostbyname() or getaddrinfo() functions instead.
 */
/*
 * Function: val_query
 *
 * Purpose: A DNSSEC-aware function intended as a replacement to res_query().
 *          The scope of this function is global.
 *
 * This routine makes a query for {domain_name, type, class} and returns the 
 * result in resp. 
 * The result of validation for a particular resource record is available in
 * the val_status field of the val_response structure.
 *
 * Parameters:
 * ctx -- The validation context.  May be NULL for default value.
 * domain_name -- The domain name to be queried.  Must not be NULL.
 * class -- The DNS class (typically IN)
 * type  -- The DNS type  (for example: A, CNAME etc.)
 * flags -- 
 * At present only one flag is implemented VAL_QUERY_MERGE_RRSETS.  When this flag
 * is specified, val_query will merge the RRSETs into a single response message.
 * The validation status in this case will be VAL_SUCCESS only if all the
 * individual RRSETs have the VAL_SUCCESS status.  Otherwise, the status
 * will be one of the other error codes.
 * resp -- An array of val_response structures used to return the result.
 * 
 * Return values:
 * VAL_NO_ERROR		Operation succeeded
 * VAL_BAD_ARGUMENT	        The domain name or other arguments are invalid
 * VAL_OUT_OF_MEMORY	Could not allocate enough memory for operation
 *
 */
int val_query ( const val_context_t *ctx,
		const char *domain_name,
		const u_int16_t class_h,
		const u_int16_t type,
		const u_int8_t flags,
		struct val_response **resp)
{
	struct val_result_chain *results = NULL;
	int retval;
	val_context_t *context;
	u_char name_n[NS_MAXCDNAME];

	if ((resp == NULL) || (domain_name == NULL))
		return VAL_BAD_ARGUMENT;
	*resp = NULL;

	if(ctx == NULL) {
		if(VAL_NO_ERROR !=(retval = val_create_context(NULL, &context)))
			return retval;
	}
	else	
	    context = (val_context_t *) ctx;

	val_log(context, LOG_DEBUG, "val_query called with dname=%s, class=%s, type=%s",
		domain_name, p_class(class_h), p_type(type));

	if (ns_name_pton(domain_name, name_n, NS_MAXCDNAME-1) == -1) {
		if((ctx == NULL)&& context)
			val_free_context(context);
		return (VAL_BAD_ARGUMENT);
	}

	/* Query the validator */
	if(VAL_NO_ERROR == (retval = val_resolve_and_check(context, name_n, class_h, type, flags, 
											&results))) {
		/* Construct the answer response in resp */
		retval = compose_answer(name_n, type, class_h, results, resp, flags);
	}

	val_log_authentication_chain(context, LOG_DEBUG, name_n, class_h, type, context->q_list, results);

	val_free_result_chain(results);

	if((ctx == NULL)&& context)
		val_free_context(context);

	return retval;

} /* val_query() */


/* Release memory allocated by the val_query() function */
int val_free_response(struct val_response *resp)
{
	struct val_response *prev, *cur; 
	cur = resp;

	while (cur) {
		prev = cur;
		cur = cur->vr_next;

		if (prev->vr_response != NULL)
			FREE(prev->vr_response);
		FREE(prev);
	}	

	return VAL_NO_ERROR;
}

/* wrapper around val_query() that is closer to res_query() */
int val_res_query(const val_context_t *ctx, const char *dname, int class_h, int type, 
					u_char *answer, int anslen, val_status_t *val_status) 
{
	struct val_response *resp;
	int retval = -1;

	if (val_status == NULL)
		return -1;

	if(VAL_NO_ERROR != (retval = val_query(ctx, dname, class_h, type, VAL_QUERY_MERGE_RRSETS, &resp))) {
		return -1;
	}

	if (resp->vr_length > anslen) 
		goto err;

	memcpy(answer, resp->vr_response, resp->vr_length);
	*val_status = resp->vr_val_status;
	retval = resp->vr_length;

err:	
	if(VAL_NO_ERROR != (retval = val_free_response(resp))) {
		return -1;
	}
	return retval;
}
