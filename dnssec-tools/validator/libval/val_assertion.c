
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#include "validator-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <resolver.h>
#include <validator.h>
#include "val_resquery.h"
#include "val_support.h"
#include "val_cache.h"
#include "val_verify.h"
#include "val_policy.h"
#include "val_log.h"

#define ISSET(field,bit)        (field[bit/8]&(1<<(7-(bit%8))))

/*
 * Create a "result" list whose elements point to assertions and also have their
 * validated result 
 */

void val_free_result_chain(struct val_result_chain *results)
{
	struct val_result_chain *prev;

	while(NULL != (prev = results)) {
		results = results->val_rc_next;
		FREE(prev);
	}

}


/*
 * Add {domain_name, type, class} to the list of queries currently active
 * for validating a response. 
 *
 * Returns:
 * VAL_NO_ERROR			Operation succeeded
 * VAL_OUT_OF_MEMORY	Could not allocate enough memory for operation
 */
int add_to_query_chain(struct val_query_chain **queries, u_char *name_n, 
						const u_int16_t type_h, const u_int16_t class_h)
{
	struct val_query_chain *temp, *prev;

	/* Check if query already exists */
	temp = *queries;
	prev = temp;
	while(temp) {
		if ((namecmp(temp->qc_name_n, name_n)==0)
				&& (temp->qc_type_h == type_h)
				&& (temp->qc_class_h == class_h))
			break;
		prev = temp;
		temp = temp->qc_next;
	}

	/* If query already exists, bring it to the front of the list */
	if(temp != NULL) {
		if(prev != temp) {
			prev->qc_next = temp->qc_next;
			temp->qc_next = *queries;
			*queries = temp;
		}
		return VAL_NO_ERROR;
	}

	temp = (struct val_query_chain *) MALLOC (sizeof (struct val_query_chain));
	if (temp==NULL) return VAL_OUT_OF_MEMORY;
                                                                                                                          
	memcpy (temp->qc_name_n, name_n, wire_name_length(name_n));
	temp->qc_type_h = type_h; 
	temp->qc_class_h = class_h; 
	temp->qc_state = Q_INIT;    
	temp->qc_as = NULL;   
	temp->qc_glue_request = 0;
	temp->qc_ns_list = NULL;
	temp->qc_respondent_server = NULL;
	temp->qc_trans_id = -1;
	temp->qc_referral = NULL;
	temp->qc_next = *queries;
	*queries = temp;
                                                                                                                          
	return VAL_NO_ERROR;
}

/*
 * Free up the query chain.
 */
void free_query_chain(struct val_query_chain *queries)
{
	if (queries==NULL) return;
                                                                                                                          
	if (queries->qc_next)
		free_query_chain (queries->qc_next);

	if (queries->qc_referral != NULL) {
		free_referral_members(queries->qc_referral);
		FREE(queries->qc_referral);
	}
	queries->qc_referral = NULL;	

	if(queries->qc_ns_list != NULL)
		free_name_servers(&(queries->qc_ns_list));
	queries->qc_ns_list = NULL;

	if(queries->qc_respondent_server != NULL)
		free_name_server(&(queries->qc_respondent_server));
	queries->qc_respondent_server = NULL;

	FREE (queries);

}

static u_int16_t is_trusted_zone(val_context_t *ctx, u_int8_t *name_n)
{
	struct zone_se_policy *zse_pol, *zse_cur;
	int name_len;
	u_int8_t *p, *q;
	
	name_len = wire_name_length(name_n);

	/* Check if the zone is trusted */
	zse_pol = RETRIEVE_POLICY(ctx, P_ZONE_SECURITY_EXPECTATION, struct zone_se_policy *);
	if (zse_pol != NULL) {
		for (zse_cur = zse_pol; 
		  zse_cur && (wire_name_length(zse_cur->zone_n) > name_len); 
		  zse_cur=zse_cur->next);	

		/* for all zones which are shorter or as long, do a strstr */ 
		// XXX We will probably need to use namecmp() instead so that
		// XXX casing and endien order are accounted for 
		/* Because of the ordering, the longest match is found first */
		for (; zse_cur; zse_cur=zse_cur->next) {
			int root_zone = 0;
			if(!namecmp(zse_cur->zone_n, ""))
				root_zone = 1;
			else {
				/* Find the last occurrence of zse_cur->zone_n in name_n */
				p = name_n;
				q = (u_int8_t*)strstr((char*)p, (char*)zse_cur->zone_n);
				while(q != NULL) {
					p = q;
					q = (u_int8_t*)strstr((char*)q+1, (char*)zse_cur->zone_n);
				}
			}

			if (root_zone || (!strcmp((char*)p, (char*)zse_cur->zone_n))) {
				if (zse_cur->trusted == ZONE_SE_UNTRUSTED) {
					val_log(ctx, LOG_DEBUG, "zone %s is not trusted", name_n);
					return VAL_A_UNTRUSTED_ZONE;
				}
				else if (zse_cur->trusted == ZONE_SE_DO_VAL) {
					val_log(ctx, LOG_DEBUG, "Doing validation for zone %s", name_n);
					return VAL_A_WAIT_FOR_TRUST;
				}
				else { 
					/* ZONE_SE_IGNORE */
					val_log(ctx, LOG_DEBUG, "Ignoring DNSSEC for zone %s", name_n);
					return VAL_A_TRUST_ZONE;
				}
			}
		}
	}
	val_log(ctx, LOG_DEBUG, "Doing validation for zone %s", name_n);
	return VAL_A_WAIT_FOR_TRUST;
}


static u_int16_t is_trusted_key(val_context_t *ctx, u_int8_t *zone_n, struct rr_rec *key)
{
	struct trust_anchor_policy *ta_pol, *ta_cur, *ta_tmphead;
	int name_len;
	u_int8_t *zp = zone_n;
	val_dnskey_rdata_t dnskey;
	struct rr_rec *curkey;

	name_len = wire_name_length(zp);
	ta_pol = RETRIEVE_POLICY(ctx, P_TRUST_ANCHOR, struct trust_anchor_policy *);	
	if (ta_pol == NULL)
		return VAL_A_NO_TRUST_ANCHOR;

	/* skip longer names */
	for (ta_cur = ta_pol; 
		  ta_cur && (wire_name_length(ta_cur->zone_n) > name_len); 
		   ta_cur=ta_cur->next); 

	/* 
	 * for the remaining nodes, if the length of the zones are 
	 * the same, look for an exact match 
	 */
	for (; ta_cur && 
		(wire_name_length(ta_cur->zone_n) == name_len);  
		ta_cur=ta_cur->next) {

		if (!namecmp(ta_cur->zone_n, zp)) { 

			for (curkey = key; curkey; curkey=curkey->rr_next) {
				val_parse_dnskey_rdata (curkey->rr_rdata, curkey->rr_rdata_length_h, &dnskey);	
				if(!dnskey_compare(&dnskey, ta_cur->publickey)) {
					if (dnskey.public_key != NULL)
						FREE (dnskey.public_key);
					val_log(ctx, LOG_DEBUG, "key %s is trusted", zp);
					return VAL_A_TRUST_KEY;
				}
				if (dnskey.public_key != NULL)
					FREE (dnskey.public_key);
			}
		}
	}


	/* for the remaining nodes, see if there is any hope */
	ta_tmphead = ta_cur;
	while (zp[0]) {
		/* trim the top label from our candidate zone */
		zp += (int)zp[0] + 1;
		for (ta_cur=ta_tmphead; ta_cur; ta_cur=ta_cur->next) {
			if(wire_name_length(zp) < wire_name_length(ta_cur->zone_n))
				/* next time look from this point */
				ta_tmphead = ta_cur->next;

			if (namecmp(ta_cur->zone_n, zp) == 0) {
				/* We have hope */
				return VAL_A_WAIT_FOR_TRUST;
			}
		}
	}

	val_log(ctx, LOG_DEBUG, "Cannot find a good trust anchor for the chain of trust above %s", zp);
	return VAL_A_NO_TRUST_ANCHOR;	
}


static int set_ans_kind (    u_int8_t    *qc_name_n,
                      const u_int16_t     q_type_h,
                      const u_int16_t     q_class_h,
                      struct rrset_rec    *the_set,
					  u_int16_t			*status)
{
    /* Answer is a Referral if... */
                                                                                                                          
        /* Referals won't make it this far, therr handled in digest_response */
                                                                                                                          
    /* Answer is a NACK_NXT if... */
	if((the_set->rrs->val_rrset_data == NULL) && (the_set->rrs->val_rrset_sig != NULL)) {
		the_set->rrs_ans_kind = SR_ANS_BARE_RRSIG;
		return VAL_NO_ERROR;
	}
                                                                                                                          
    if (the_set->rrs->val_rrset_type_h == ns_t_nsec)
    {
        if (namecmp(the_set->rrs->val_rrset_name_n, qc_name_n)==0 &&
                            (q_type_h == ns_t_any || q_type_h == ns_t_nsec))
            /* We asked for it */
            the_set->rrs_ans_kind = SR_ANS_STRAIGHT;
        else
            the_set->rrs_ans_kind = SR_ANS_NACK_NXT;
                                                                                                                          
        return VAL_NO_ERROR;
    }
                                                                                                                          
    /* Answer is a NACK_SOA if... */
                                                                                                                          
    if (the_set->rrs->val_rrset_type_h == ns_t_soa)
    {
        if (namecmp(the_set->rrs->val_rrset_name_n, qc_name_n)==0 &&
                            (q_type_h == ns_t_any || q_type_h == ns_t_soa))
            /* We asked for it */
            the_set->rrs_ans_kind = SR_ANS_STRAIGHT;
        else
            the_set->rrs_ans_kind = SR_ANS_NACK_SOA;
                                                                                                                          
        return VAL_NO_ERROR;
    }
                                                                                                                          
    /* Answer is a CNAME if... */
                                                                                                                          
    if (the_set->rrs->val_rrset_type_h == ns_t_cname)
    {
        if (namecmp(the_set->rrs->val_rrset_name_n, qc_name_n)==0 &&
                            (q_type_h == ns_t_any || q_type_h == ns_t_cname))
            /* We asked for it */
            the_set->rrs_ans_kind = SR_ANS_STRAIGHT;
        else
            the_set->rrs_ans_kind = SR_ANS_CNAME;
                                                                                                                          
        return VAL_NO_ERROR;
    }
                                                                                                                          
    /* Answer is an ANSWER if... */
    if (namecmp(the_set->rrs->val_rrset_name_n, qc_name_n)==0 &&
                    (q_type_h==ns_t_any || q_type_h==the_set->rrs->val_rrset_type_h))
    {
        /* We asked for it */
        the_set->rrs_ans_kind = SR_ANS_STRAIGHT;
        return VAL_NO_ERROR;
    }
                                                                                                                          
    the_set->rrs_ans_kind = SR_ANS_UNSET;
	*status = VAL_A_DNS_ERROR_BASE + SR_WRONG_ANSWER; 
                                                                                                                          
    return VAL_ERROR;
}

#define TOP_OF_QNAMES   0
#define MID_OF_QNAMES   1
#define NOT_IN_QNAMES   2
                                                                                                                          
static int name_in_q_names (
                      struct qname_chain  *q_names_n,
                      struct rrset_rec    *the_set)
{
    struct qname_chain *temp_qc;
                                                                                                                          
    if (q_names_n==NULL) return NOT_IN_QNAMES;
                                                                                                                          
    if (namecmp(the_set->rrs->val_rrset_name_n, q_names_n->qnc_name_n)==0)
        return TOP_OF_QNAMES;
                                                                                                                          
    temp_qc = q_names_n->qnc_next;
                                                                                                                          
    while (temp_qc)
    {
        if (namecmp(the_set->rrs->val_rrset_name_n, temp_qc->qnc_name_n)==0)
            return MID_OF_QNAMES;
        temp_qc = temp_qc->qnc_next;
    }
                                                                                                                          
    return NOT_IN_QNAMES;
}

int fails_to_answer_query(
                      struct qname_chain  *q_names_n,
                      const u_int16_t     q_type_h,
                      const u_int16_t     q_class_h,
                      struct rrset_rec    *the_set,
					  u_int16_t			*status)
{
    int name_present = name_in_q_names (q_names_n, the_set);
    int type_match = the_set->rrs->val_rrset_type_h==q_type_h || q_type_h==ns_t_any;
    int class_match = the_set->rrs->val_rrset_class_h==q_class_h || q_class_h==ns_c_any;
    int data_present = the_set->rrs->val_rrset_data != NULL;
                                                                                                                          
    if (!data_present) return FALSE;
                                                                                                                          
    if (
        !class_match ||
        (!type_match && the_set->rrs_ans_kind == SR_ANS_STRAIGHT) ||
        (type_match && the_set->rrs_ans_kind != SR_ANS_STRAIGHT) ||
        (name_present!=TOP_OF_QNAMES && type_match &&
                        the_set->rrs_ans_kind == SR_ANS_STRAIGHT) ||
        (name_present!=MID_OF_QNAMES && !type_match &&
                        the_set->rrs_ans_kind == SR_ANS_CNAME) ||
        (name_present==MID_OF_QNAMES && !type_match &&
            (the_set->rrs_ans_kind == SR_ANS_NACK_NXT ||
                the_set->rrs_ans_kind == SR_ANS_NACK_SOA))
        )
        {
            *status = VAL_A_DNS_ERROR_BASE + SR_WRONG_ANSWER;
            return TRUE;
        }
                                                                                                                          
    return FALSE;
}


static int NSEC_is_wrong_answer (
                      u_int8_t    *qc_name_n,
                      const u_int16_t     q_type_h,
                      const u_int16_t     q_class_h,
                      struct rrset_rec    *the_set,
					  u_int16_t			*status)
{
    int                 nsec_bit_field;
                                                                                                                          
    if (the_set->rrs_ans_kind != SR_ANS_NACK_NXT) return FALSE;
                                                                                                                          
    /*
        Signer name doesn't matter here, incorrectly signed ones will caught
        later (in "the matrix").
    */
                                                                                                                          
    if (namecmp(the_set->rrs->val_rrset_name_n, qc_name_n)==0)
    {
        /* NXT owner = query name & q_type not in list */
        nsec_bit_field = wire_name_length (the_set->rrs->val_rrset_data->rr_rdata);
                                                                                                                          
        if (ISSET((&(the_set->rrs->val_rrset_data->rr_rdata[nsec_bit_field])), q_type_h))
        {
			*status = VAL_A_IRRELEVANT_PROOF; 
            return TRUE;
        }
        else
            return FALSE;
    }
    else
    {
		/* query name comes after the NXT owner */
		/* It can be less than the owner if this is a wildcard proof, 
		 * or if it is the SOA but that logic is handled in 
		 * prove_nonexistence()
		 */
        if (namecmp(the_set->rrs->val_rrset_name_n, qc_name_n) > 0)
        {
			*status = VAL_A_IRRELEVANT_PROOF;	
            return TRUE;
        }
        
        return FALSE;
    }
}

/*
 * Add a new assertion for the response data 
 *
 * Returns:
 * VAL_NO_ERROR			Operation succeeded
 * VAL_OUT_OF_MEMORY	Could not allocate enough memory for operation
 */
static int add_to_assertion_chain(struct val_assertion_chain **assertions, struct domain_info *response)
{
	struct val_assertion_chain *new_as, *first_as, *prev_as;
	struct rrset_rec *next_rr;

	if (response == NULL)
		return VAL_NO_ERROR;

	first_as = NULL;
	prev_as = NULL;
	next_rr = response->di_rrset;
	while(next_rr) {

		new_as = (struct val_assertion_chain *) MALLOC (sizeof (struct val_assertion_chain)); 
		if (new_as==NULL) return VAL_OUT_OF_MEMORY;

		new_as->_as = (struct val_rrset_digested *) MALLOC (sizeof (struct val_rrset_digested));
		if (new_as->_as == NULL)
			return VAL_OUT_OF_MEMORY;
		new_as->_as->ac_data = copy_rrset_rec(next_rr);
		new_as->val_ac_trust = NULL;        
		new_as->val_ac_rrset_next = NULL;        
		new_as->val_ac_next = NULL;        
		new_as->_as->ac_pending_query = NULL; 
		new_as->val_ac_status = VAL_A_INIT;
		if(first_as != NULL) { 
			/* keep the first assertion constant */
			new_as->val_ac_next = first_as->val_ac_next;
			first_as->val_ac_next = new_as;
			prev_as->val_ac_rrset_next = new_as;	
			
		}
		else {
			first_as = new_as;
			new_as->val_ac_next = *assertions;
			*assertions = new_as;
		}
		prev_as = new_as;
		next_rr = next_rr->rrs_next;
	}
                                                                                                                  
	return VAL_NO_ERROR;
}

/*
 * Free up the assertion chain.
 */
void free_assertion_chain(struct val_assertion_chain *assertions)
{
	if (assertions==NULL) return;
                                                                                                                          
	if (assertions->val_ac_next)
		free_assertion_chain (assertions->val_ac_next);

	if (assertions->_as->ac_data)
		res_sq_free_rrset_recs(&(assertions->_as->ac_data));

	FREE(assertions->_as);
	FREE (assertions);
}

/*
 * For a given assertion identify its pending queries
 */
static int build_pending_query(val_context_t *context, 
		struct val_query_chain **queries, struct val_assertion_chain *as)
{
	u_int8_t *signby_name_n;
	int retval;

	if(as->_as->ac_data == NULL) {
		as->val_ac_status = VAL_A_DATA_MISSING;
		return VAL_NO_ERROR;
	}

	if(as->_as->ac_data->rrs_ans_kind == SR_ANS_BARE_RRSIG) { 
		as->val_ac_status = VAL_A_BARE_RRSIG;
		return VAL_NO_ERROR;
	}

	if(as->_as->ac_data->rrs->val_rrset_data == NULL) {
		as->val_ac_status = VAL_A_DATA_MISSING;
		return VAL_NO_ERROR;
	}

	/* Check if this zone is locally trusted/untrusted */
	u_int16_t tzonestatus = is_trusted_zone(context, as->_as->ac_data->rrs->val_rrset_name_n);
	if (tzonestatus != VAL_A_WAIT_FOR_TRUST) {
		as->val_ac_status = tzonestatus;
		return VAL_NO_ERROR;
	}

	if(as->_as->ac_data->rrs->val_rrset_sig == NULL) {
		as->val_ac_status = VAL_A_WAIT_FOR_RRSIG;
		/* create a query and link it as the pending query for this assertion */
		if(VAL_NO_ERROR != (retval = add_to_query_chain(queries, 
						as->_as->ac_data->rrs->val_rrset_name_n, ns_t_rrsig, as->_as->ac_data->rrs->val_rrset_class_h)))
			return retval;
		as->_as->ac_pending_query = *queries;/* The first value in the list is the most recent element */
		return VAL_NO_ERROR;
	}

	/* 
	 * Identify the DNSKEY that created the RRSIG:
	 */

	/* First identify the signer name from the RRSIG */
	signby_name_n = &as->_as->ac_data->rrs->val_rrset_sig->rr_rdata[SIGNBY];
	//XXX The signer name has to be within the zone

	/* Then look for  {signby_name_n, DNSKEY/DS, type} */
	if(as->_as->ac_data->rrs->val_rrset_type_h == ns_t_dnskey) {

		u_int16_t tkeystatus = is_trusted_key(context, signby_name_n, as->_as->ac_data->rrs->val_rrset_data);
		as->val_ac_status = tkeystatus;
		if (as->val_ac_status != VAL_A_WAIT_FOR_TRUST)
			return VAL_NO_ERROR;

		/* Create a query for missing data */
		if(VAL_NO_ERROR != (retval = add_to_query_chain(queries, signby_name_n, 
					ns_t_ds, as->_as->ac_data->rrs->val_rrset_class_h)))
			return retval;

	}
	else { 
		/* look for DNSKEY records */
		if(VAL_NO_ERROR != (retval = add_to_query_chain(queries, signby_name_n, 
						ns_t_dnskey, as->_as->ac_data->rrs->val_rrset_class_h)))
			return retval;
		as->val_ac_status = VAL_A_WAIT_FOR_TRUST;
	}

	as->_as->ac_pending_query = *queries; /* The first value in the list is the most recent element */
	return VAL_NO_ERROR;
}


/*
 * Read the response that came in and create assertions from it. Set the state
 * of the assertion based on what data is available and whether validation
 * can proceed.
 * 
 * Returns:
 * VAL_NO_ERROR			Operation completed successfully
 * SR_CALL_ERROR	If the name could not be converted from host to network format
 *
 */ 
static int assimilate_answers(val_context_t *context, struct val_query_chain **queries, 
							struct domain_info *response, struct val_query_chain *matched_q, 
								struct val_assertion_chain **assertions)
{
	int retval;
	struct val_assertion_chain *as = NULL;
	u_int16_t type_h = response->di_requested_type_h;
    u_int16_t class_h = response->di_requested_class_h;	
	u_int8_t kind = SR_ANS_UNSET;

	if (matched_q == NULL)
		return VAL_NO_ERROR;

	if(matched_q->qc_as != NULL) {
		/* We already had an assertion for this query */
		// XXX What about FLOOD_ATTACKS ?
		return VAL_NO_ERROR; 
	}

	/* Create an assertion for the response data */
	if(VAL_NO_ERROR != (retval = add_to_assertion_chain(assertions, response))) 
		return retval;

	if (response->di_rrset == NULL) {
		matched_q->qc_state = Q_ERROR_BASE + SR_NO_ANSWER;
		return VAL_NO_ERROR;
	}

	as = *assertions; /* The first value in the list is the most recent element */
	/* Link the original query to the above assertion */
	matched_q->qc_as = as;

	/* Identify the state for each of the assertions obtained */
	for (; as; as = as->val_ac_rrset_next) {
	
		/* Cover error conditions first */
		/* SOA checks will appear during sanity checks later on */
		if((	set_ans_kind(response->di_qnames->qnc_name_n, type_h, class_h, 
					as->_as->ac_data, &as->val_ac_status) == VAL_ERROR)
				|| fails_to_answer_query(response->di_qnames, type_h, class_h, as->_as->ac_data, &as->val_ac_status)
				|| NSEC_is_wrong_answer (response->di_qnames->qnc_name_n, type_h, class_h, 
					as->_as->ac_data, &as->val_ac_status)) {
			continue;
		}

		if (kind == SR_ANS_UNSET)
			kind = as->_as->ac_data->rrs_ans_kind;
		else {
			switch(kind) {
				/* STRAIGHT and CNAME are OK */
				case SR_ANS_STRAIGHT:
					if ((as->_as->ac_data->rrs_ans_kind != SR_ANS_STRAIGHT) &&
						(as->_as->ac_data->rrs_ans_kind != SR_ANS_CNAME)) {
						matched_q->qc_state = Q_ERROR_BASE + SR_CONFLICTING_ANSWERS;
					}
					break;

				case SR_ANS_CNAME:
					if ((as->_as->ac_data->rrs_ans_kind != SR_ANS_STRAIGHT) &&
						(as->_as->ac_data->rrs_ans_kind != SR_ANS_CNAME) && 
						(as->_as->ac_data->rrs_ans_kind != SR_ANS_NACK_SOA) &&
						(as->_as->ac_data->rrs_ans_kind != SR_ANS_NACK_NXT)) {
						matched_q->qc_state = Q_ERROR_BASE + SR_CONFLICTING_ANSWERS;
					}
					break;

				/* Only bare RRSIGs together */
				case SR_ANS_BARE_RRSIG:
					if (as->_as->ac_data->rrs_ans_kind != SR_ANS_BARE_RRSIG) {
						matched_q->qc_state = Q_ERROR_BASE + SR_CONFLICTING_ANSWERS;
					}
					break;

				/* NACK_NXT and NACK_SOA are OK */
				case SR_ANS_NACK_NXT:
					if ((as->_as->ac_data->rrs_ans_kind != SR_ANS_NACK_NXT) &&
						(as->_as->ac_data->rrs_ans_kind != SR_ANS_NACK_SOA) && 
						(as->_as->ac_data->rrs_ans_kind != SR_ANS_CNAME)) {
						matched_q->qc_state = Q_ERROR_BASE + SR_CONFLICTING_ANSWERS;
					}
					break;

				case SR_ANS_NACK_SOA:
					if ((as->_as->ac_data->rrs_ans_kind != SR_ANS_NACK_NXT) &&
						(as->_as->ac_data->rrs_ans_kind != SR_ANS_NACK_SOA) && 
						(as->_as->ac_data->rrs_ans_kind != SR_ANS_CNAME)) {
						matched_q->qc_state = Q_ERROR_BASE + SR_CONFLICTING_ANSWERS;
					}
					break;

				/* Never Reached */
				default:
					matched_q->qc_state = Q_ERROR_BASE + SR_CONFLICTING_ANSWERS;
			}
		}

		if (!matched_q->qc_glue_request) { 
			if (VAL_NO_ERROR != (retval = build_pending_query(context, queries, as)))
				return retval;
		}
	}
	return VAL_NO_ERROR;
}

static void  prove_nonexistence (val_context_t *ctx, struct val_query_chain *top_q, struct
val_result_chain *results) 
{
	struct val_result_chain *res;
	int wcard_chk = 0;
	int span_chk = 0;
	int status = VAL_NONEXISTENT_NAME; 
	u_int8_t *soa_name_n = NULL;	
	u_int8_t *closest_encounter = NULL;	
	struct rrset_rec *wcard_proof = NULL;

	val_log(ctx, LOG_DEBUG, "proving non-existence for {%s, %d, %d}", 
		top_q->qc_name_n, top_q->qc_class_h, top_q->qc_type_h);
		 
	/* 
	 * Check if this is the whole proof and nothing but the proof
	 * At this point these records should already be in the TRUSTED state.
	 */

	/* inspect the SOA record first */
	// XXX Can we assume that the SOA record is always present?
	for(res = results; res; res = res->val_rc_next) {
		struct rrset_rec *the_set = res->val_rc_trust->_as->ac_data;
		if (the_set->rrs_ans_kind == SR_ANS_NACK_SOA) {
			soa_name_n = the_set->rrs->val_rrset_name_n;
			break;
		}
	}

	if (soa_name_n == NULL)
		status = VAL_R_INCOMPLETE_PROOF;
	else {
		/* for every NSEC */
		for(res = results; res; res = res->val_rc_next) {
			struct rrset_rec *the_set = res->val_rc_trust->_as->ac_data;
			if (the_set->rrs_ans_kind == SR_ANS_NACK_NXT) { 
				if (!namecmp(the_set->rrs->val_rrset_name_n, top_q->qc_name_n)) {
					/* we already made sure that the type was missing in
					 * NSEC_is_wrong_answer()
					 */
					span_chk = 1;
					status = VAL_NONEXISTENT_TYPE;
					/* if the label count in the RRSIG equals the labels
					 * in the nsec owner name, wildcard absence is also proved
					 * Be sure to check the label count in an RRSIG that was 
					 * verified
					 */
					struct rr_rec *sig;
					int wcard;
					for (sig = the_set->rrs->val_rrset_sig; sig; sig = sig->rr_next) {
						if ((sig->rr_status == VAL_A_RRSIG_VERIFIED) && 
							(VAL_NO_ERROR == check_label_count(the_set, sig, &wcard))) {
							if (wcard == 0)
								wcard_chk = 1;
							break;
						}
					}
				}
				else {
					/* Find the next name */
					u_int8_t *nxtname =	the_set->rrs->val_rrset_data->rr_rdata;

					/* 
					 * We've already checked within NSEC_is_wrong_answer() 
					 * that the NSEC owner name is less than the query name. 
					 * Now check if the next name in the NSEC record comes 
					 * after the query name
					 */
					if (namecmp(top_q->qc_name_n, nxtname) > 0) {
						/* if no, check if the next name wraps around */
						if (namecmp(nxtname, soa_name_n) != 0) {
							/* if no, check if this is the proof for no wild-card present */
							/* i.e the proof must tell us that "*" does not exist */
							wcard_proof = the_set;
							break;
						}
					}
					span_chk = 1;
					/* The same NSEC may prove wildcard absence also */
					if (wcard_proof == NULL)
						wcard_proof = the_set;

					/* The closest encounter is the longest label match between 
					 * this NSEC's owner name and the query name
					 */
					int maxoffset = wire_name_length(top_q->qc_name_n);
					int offset = top_q->qc_name_n[0] + 1;
					while (offset < maxoffset) {
						u_int8_t *cur_name_n = &top_q->qc_name_n[offset];
						int cmp;
						if ((cmp = namecmp(cur_name_n, the_set->rrs->val_rrset_name_n)) == 0) {
							closest_encounter = cur_name_n;
							break;
						}
						else if (cmp < 0) {
							/* strip off one label from the NSEC owner name */
							closest_encounter = &the_set->rrs->val_rrset_name_n[the_set->rrs->val_rrset_name_n[0] + 1];
							break; 
						}
						offset += cur_name_n[0] + 1;
					}
				}
			}
		}
		if (!span_chk)
			status = VAL_R_INCOMPLETE_PROOF;
		else if (!wcard_chk) {
			if (!closest_encounter)
				status = VAL_R_INCOMPLETE_PROOF;	
			else {
				/* Check the wild card proof */
				/* prefix "*" to the closest encounter, and check if that 
				 * name falls within the range given in wcard_proof
				 */	
				u_int8_t *nxtname =	wcard_proof->rrs->val_rrset_data->rr_rdata;
				u_char domain_name_n[NS_MAXCDNAME];
				domain_name_n[0] = 0x01;
				domain_name_n[1] = 0x2a; /* for the '*' character */
				memcpy(&domain_name_n[2], closest_encounter, wire_name_length(closest_encounter));
				if ((namecmp(domain_name_n, wcard_proof->rrs->val_rrset_name_n) <= 0) ||  
					(namecmp(nxtname, domain_name_n) <= 0))
					status = VAL_R_INCOMPLETE_PROOF;	
			}
		}
	}	

	/* set the error condition in all elements of the proof */
	for(res = results; res; res = res->val_rc_next) 
		res->val_rc_status = status;

}


/*
 * Verify an assertion if possible. Complete assertions are those for which 
 * you have data, rrsigs and key information. 
 * Returns:
 * VAL_NO_ERROR			Operation completed successfully
 * Other return values from add_to_query_chain()
 */
static int try_verify_assertion(val_context_t *context, struct val_query_chain **queries, 
				struct val_assertion_chain *next_as)
{
	struct val_query_chain *pc;
	struct val_assertion_chain *pending_as;
	int retval;
	struct rrset_rec *pending_rrset; 

	/* Sanity check */
	if(next_as == NULL)
		return VAL_NO_ERROR;

	pc = next_as->_as->ac_pending_query;
	if (!pc)
		/* 
		 * If there is no pending query, we've already 
		 * reached some end-state.
		 */
		return VAL_NO_ERROR;

	if (pc->qc_state == Q_WAIT_FOR_GLUE) {
		merge_glue_in_referral(pc, queries);
	}

	if (pc->qc_state > Q_ERROR_BASE) {
		if(next_as->val_ac_status == VAL_A_WAIT_FOR_RRSIG) 
			next_as->val_ac_status = VAL_A_RRSIG_MISSING; 
		else if (next_as->val_ac_status == VAL_A_WAIT_FOR_TRUST) {
			/* We're either waiting for DNSKEY or DS */
			if(pc->qc_type_h == ns_t_ds)
				next_as->val_ac_status = VAL_A_DS_MISSING;
			else if (pc->qc_type_h == ns_t_dnskey)
				next_as->val_ac_status = VAL_A_DNSKEY_MISSING;
		}
		else
			next_as->val_ac_status = VAL_A_DNS_ERROR_BASE + pc->qc_state - Q_ERROR_BASE;
	}

	if (pc->qc_state == Q_ANSWERED) {

		if(next_as->val_ac_status == VAL_A_WAIT_FOR_RRSIG) {
		
			for(pending_as = pc->qc_as; pending_as; pending_as = pending_as->val_ac_rrset_next) {
				/* We were waiting for the RRSIG */
				pending_rrset = pending_as->_as->ac_data;

				/* 
				 * Check if what we got was an RRSIG 
				 */
				if (pending_as->val_ac_status == VAL_A_BARE_RRSIG) {
					/* Find the RRSIG that matches the type */
					/* Check if type is in the RRSIG */
					u_int16_t rrsig_type_n;
					memcpy(&rrsig_type_n, pending_rrset->rrs->val_rrset_sig->rr_rdata, sizeof(u_int16_t));
					if (next_as->_as->ac_data->rrs->val_rrset_type_h == ntohs(rrsig_type_n)) {
						/* store the RRSIG in the assertion */
						next_as->_as->ac_data->rrs->val_rrset_sig = 
							copy_rr_rec(pending_rrset->rrs->val_rrset_type_h, pending_rrset->rrs->val_rrset_sig, 0);
						next_as->val_ac_status = VAL_A_WAIT_FOR_TRUST; 
						/* create a pending query for the trust portion */
						if (VAL_NO_ERROR != (retval = build_pending_query(context, queries, next_as)))
							return retval;
						break;
					}
				}
			}
			if(pending_as == NULL) {
				/* Could not find any RRSIG matching query type*/
				next_as->val_ac_status = VAL_A_RRSIG_MISSING; 
			}
		}
		else if (next_as->val_ac_status == VAL_A_WAIT_FOR_TRUST) {
			pending_as = pc->qc_as;
			next_as->val_ac_trust = pending_as;
			next_as->_as->ac_pending_query = NULL;

			if((pending_as->_as->ac_data->rrs_ans_kind == SR_ANS_NACK_NXT)
                  || (pending_as->_as->ac_data->rrs_ans_kind == SR_ANS_NACK_SOA)) { 

				/* proof of non-existence should follow */
				next_as->val_ac_status = VAL_A_NEGATIVE_PROOF;
			}
			else { 
				/* XXX what if this is an SR_ANS_CNAME? Can DS or DNSKEY return a CNAME? */
				/* 
				 * if the pending assertion contains a straight answer, 
			   	 * trust is useful for verification 
				 */
				next_as->val_ac_status = VAL_A_CAN_VERIFY;
			}
		}
	}

	if(next_as->val_ac_status == VAL_A_CAN_VERIFY) {
		val_log(context, LOG_DEBUG, "verifying next assertion"); 
		verify_next_assertion(context, next_as);
	}

	return VAL_NO_ERROR;
}

/*
 * Try and verify each assertion. Update results as and when they are available.
 * Do not try and validate assertions that have already been validated.
 */
static int  verify_and_validate(val_context_t *context, struct val_query_chain **queries, 
								struct val_assertion_chain *top_as, u_int8_t flags, 
								struct val_result_chain **results, int *done)
{
	struct val_assertion_chain *next_as;
	int retval;
	struct val_assertion_chain *as_more;
	struct val_result_chain *res;
	
	*done = 1;

	/* Look at every answer that was returned */
	for(as_more= top_as; as_more; as_more=as_more->val_ac_rrset_next) {

		/* 
		 * If this assertion is already in the results list with a completed status
		 * no need for repeating the validation process
		 */
		for (res=*results; res; res=res->val_rc_next) 
			if (res->val_rc_trust == as_more) 
				break;
		if (res) {
			if (!CHECK_MASKED_STATUS(res->val_rc_status, VAL_R_DONT_KNOW))
				/* we've already dealt with this one */
				continue;
		}
		else {
			/* Add this result to the list */
			res= (struct val_result_chain *) MALLOC (sizeof (struct val_result_chain));
			if(res== NULL)
				return VAL_OUT_OF_MEMORY;
			res->val_rc_trust = as_more;
			res->val_rc_status = VAL_R_DONT_KNOW;
			res->val_rc_next = *results;
			*results = res;
		}

		/* 
		 * as_more is the next answer that we obtained; next_as is the 
		 * next assertion in the chain of trust
		 */
		int thisdone = 1;
		for (next_as=as_more; next_as; next_as=next_as->val_ac_trust) {

			if (next_as->val_ac_status <= VAL_A_INIT) {
				/* Go up the chain of trust */
				if(VAL_NO_ERROR != (retval = try_verify_assertion(context, queries, next_as))) 
					return retval;
			}

			/*  
			 * break out of infinite loop -- trying to verify the proof of non-existence
			 * for a DS record; but the DNSKEY that signs the proof is also in the 
			 * chain of trust (not-validated)
			 */
			if((next_as->_as->ac_data != NULL) &&
				(next_as->_as->ac_data->rrs->val_rrset_type_h == ns_t_dnskey) &&
				(next_as->val_ac_trust) && 
				(next_as == next_as->val_ac_trust->val_ac_trust)) {
				res->val_rc_status = VAL_R_INDETERMINATE_DS;
				break;
			}
			/* Check initial states */
			if(next_as->val_ac_status <= VAL_A_INIT) {
				/* still need more data to validate this assertion */
				*done = 0;
				thisdone = 0;
			}
			else if ((next_as->val_ac_status == VAL_A_TRUST_KEY) || 
						(next_as->val_ac_status == VAL_A_TRUST_ZONE)) {
				SET_RESULT_TRUSTED(res->val_rc_status); 
				break;
			}
			else if (next_as->val_ac_status == VAL_A_NEGATIVE_PROOF) {
				if((next_as->_as->ac_pending_query != NULL) &&
					(next_as->_as->ac_pending_query->qc_referral == NULL) && 
					(next_as->_as->ac_pending_query->qc_type_h == ns_t_ds)) {

					/* 
					 * If this is a query for DS, we may have asked the child,
					 * Try again starting from root; state will be WAIT_FOR_TRUST 
					 * Note that we don't wait to verify that the negative proof 
					 * is trusted
					 */

					struct name_server *root_ns = NULL;
					get_root_ns(&root_ns);
					if(root_ns == NULL) {
						/* No root hints configured */
						res->val_rc_status = VAL_R_INDETERMINATE_PROOF;
						break;
					}
					else {
						/* send query to root */
						next_as->val_ac_status = VAL_A_WAIT_FOR_TRUST;
						if (VAL_NO_ERROR != (retval = build_pending_query(context, queries, next_as)))
							return retval;
						(*queries)->qc_ns_list = root_ns;
						*done = 0;
						thisdone = 0;
					}
				}
				else {
					/*
					 * if we are able to prove non existence, we have 
					 * shown that a component of the chain-of-trust is provably 
					 * absent (provably unsecure).
					 * On the other hand if we cannot prove this we cannot believe 
					 * the original answer either, since we still haven't reached 
					 * a trust anchor. 
					 * Dont see any use for separating these conditions, so treat them
					 * as INDETERMINATE always
					 */
					res->val_rc_status = VAL_R_INDETERMINATE_PROOF;
					break;
				}
			}
			/* Check error conditions */
			else if (next_as->val_ac_status <= VAL_A_LAST_ERROR) {
				
				res->val_rc_status = VAL_ERROR; 
				break;
			}
			else if (next_as->val_ac_status <= VAL_A_LAST_FAILURE){
				SET_MASKED_STATUS(res->val_rc_status, VAL_R_BOGUS_UNPROVABLE);
				continue;
			}
			else  if (CHECK_MASKED_STATUS(res->val_rc_status, VAL_R_VERIFIED_CHAIN)
					|| (res->val_rc_status == VAL_R_DONT_KNOW)) {

				/* Success condition */
				if (next_as->val_ac_status == VAL_A_VERIFIED) {
					SET_MASKED_STATUS(res->val_rc_status, VAL_R_VERIFIED_CHAIN);
					continue;
				}
				else if ((next_as->val_ac_status == VAL_A_LOCAL_ANSWER)	
						|| (next_as->val_ac_status == VAL_A_TRUST_KEY)
						|| (next_as->val_ac_status == VAL_A_TRUST_ZONE)) {
					res->val_rc_status = VAL_LOCAL_ANSWER;
					break;
				}
				else if (next_as->val_ac_status == VAL_A_BARE_RRSIG) {
					res->val_rc_status = VAL_BARE_RRSIG;
					break;
				}	
			}
		}
		if (!thisdone)
			/* more work required */
			SET_MASKED_STATUS(res->val_rc_status, VAL_R_DONT_KNOW);
	}
	
	return VAL_NO_ERROR;
}


// XXX Needs blocking/non-blocking logic so that the validator can operate in
// XXX the stealth mode
static int ask_cache(val_context_t *context, struct val_query_chain *end_q, 
				struct val_query_chain **queries, 
				struct val_assertion_chain **assertions,
				int *data_received)
{
	struct val_query_chain *next_q, *top_q;
	struct rrset_rec *next_answer;
	int retval;

	top_q = *queries;

	for(next_q = *queries; next_q && next_q != end_q; next_q=next_q->qc_next) {
		if(next_q->qc_state == Q_INIT) {

			val_log(context, LOG_DEBUG, "ask_cache(): looking for {%s %d %d}", 
						next_q->qc_name_n, next_q->qc_class_h, next_q->qc_type_h);
			if(VAL_NO_ERROR != (retval = get_cached_rrset(next_q->qc_name_n, 
								next_q->qc_class_h, next_q->qc_type_h, &next_answer)))
				return retval; 

			if(next_answer) {
				struct domain_info *response;
				char name[NS_MAXDNAME];

				val_log(context, LOG_DEBUG, "ask_cache(): found data for {%s %d %d}", 
						next_q->qc_name_n, next_q->qc_class_h, next_q->qc_type_h);
				*data_received = 1;

				next_q->qc_state = Q_ANSWERED;
				/* Construct a dummy response */
				response = (struct domain_info *) MALLOC (sizeof(struct domain_info));
				if(response == NULL)
					return VAL_OUT_OF_MEMORY;

				response->di_rrset = next_answer;
			    response->di_qnames = (struct qname_chain *) MALLOC (sizeof(struct qname_chain));
				if (response->di_qnames == NULL) 
					return VAL_OUT_OF_MEMORY;
				memcpy (response->di_qnames->qnc_name_n, next_q->qc_name_n, wire_name_length(next_q->qc_name_n));
				response->di_qnames->qnc_next = NULL;

				if(ns_name_ntop(next_q->qc_name_n, name, NS_MAXDNAME-1) == -1) {
					next_q->qc_state = Q_ERROR_BASE+SR_CALL_ERROR;
					FREE(response->di_qnames);
					FREE (response);
					continue;
				}
			    response->di_requested_name_h = name; 
			    response->di_requested_type_h = next_q->qc_type_h;
			    response->di_requested_class_h = next_q->qc_class_h;
				response->di_res_error = SR_UNSET;

				if(VAL_NO_ERROR != (retval = 
						assimilate_answers(context, queries, 
							response, next_q, assertions))) {
					FREE(response->di_rrset);
					FREE(response->di_qnames);
					FREE (response);
					return retval;
				}

				FREE(response->di_rrset);
				FREE(response->di_qnames);
				FREE (response);

				break;
			}
		}
	}

	if(top_q != *queries) 
		/* more qureies have been added, do this again */
		return ask_cache(context, top_q, queries, assertions, data_received);


	return VAL_NO_ERROR;
}

static int ask_resolver(val_context_t *context, struct val_query_chain **queries, int block, 
					struct val_assertion_chain **assertions, int *data_received)
{
	struct val_query_chain *next_q;
	struct domain_info *response;
	int retval;
	int need_data = 0;

	response = NULL;

	int answered = 0;
	while (!answered) {

		for(next_q = *queries; next_q ; next_q = next_q->qc_next) {
			if(next_q->qc_state == Q_INIT) {
				need_data = 1;
				next_q = next_q;
				next_q->qc_state = Q_SENT;
				val_log(context, LOG_DEBUG, "ask_resolver(): sending query for {%s %d %d}", 
						next_q->qc_name_n, next_q->qc_class_h, next_q->qc_type_h);

				/* Only set the CD and EDS0 options if we feel the server 
				 * is capable of handling DNSSEC
				 */
				if(is_trusted_zone(context, next_q->qc_name_n) ==  VAL_A_WAIT_FOR_TRUST) {
					struct name_server *ns;
					if(next_q->qc_ns_list == NULL) 
						clone_ns_list(&(next_q->qc_ns_list), context->nslist);

					for(ns=next_q->qc_ns_list; ns; ns=ns->ns_next)
						ns->ns_options |= RES_USE_DNSSEC;
				}

				if ((retval = val_resquery_send (context, next_q)) != VAL_NO_ERROR)
					return retval;
			}
			else if (next_q->qc_state < Q_ANSWERED)
				need_data = 1;
		}

		/* wait until we get at least one complete answer */
		if ((block) && need_data) {

			for(next_q = *queries; next_q ; next_q = next_q->qc_next) {
				if(next_q->qc_state < Q_ANSWERED) {
					if( (retval = val_resquery_rcv (context, next_q, &response, queries)) != VAL_NO_ERROR)	
						return retval;

					if ((next_q->qc_state == Q_ANSWERED) && (response != NULL)) {
						val_log(context, LOG_DEBUG, "ask_resolver(): found data for {%s %d %d}", 
							next_q->qc_name_n, next_q->qc_class_h, next_q->qc_type_h);
						if(VAL_NO_ERROR != (retval = 
								assimilate_answers(context, queries, 
									response, next_q, assertions))) {
							free_domain_info_ptrs(response);
							FREE(response);
							return retval;
						}

						/* Save new responses in the cache */
						if(VAL_NO_ERROR != (retval = stow_answer(response->di_rrset))) {
							free_domain_info_ptrs(response);
							FREE(response);
							return retval;
						}

						response->di_rrset = NULL;
						free_domain_info_ptrs(response);
						FREE(response);
						answered = 1;
						break;
					}
					if (response != NULL) {
						free_domain_info_ptrs(response);
						FREE(response);
					}
					if((next_q->qc_state == Q_WAIT_FOR_GLUE) ||
						(next_q->qc_referral != NULL)) {
						answered = 1;
						break;
					}
					if (next_q->qc_state >= Q_ANSWERED) {
						answered = 1;
						*data_received = 1;
						break;
					}
				}
			}
		}
		else
			break;	
	}

	return VAL_NO_ERROR;
}

/*
 * Look inside the cache, ask the resolver for missing data.
 * Then try and validate what ever is possible.
 * Return when we are ready with some useful answer (error condition is 
 * a useful answer)
 */
int val_resolve_and_check(	val_context_t	*context,
			u_char *domain_name_n,
			const u_int16_t class,
			const u_int16_t type,
			const u_int8_t flags, 
			struct val_result_chain **results)
{

	int retval;
	struct val_query_chain *top_q;
	struct val_result_chain *res;
	char block = 1; /* block until at least some data is returned */

	int done = 0;
	int data_received = 0;

	val_log(context, LOG_DEBUG, "val_resolve_and_check(): looking for {%s %d %d}", 
						domain_name_n, class, type);

	if (VAL_NO_ERROR != (retval = add_to_query_chain(&(context->q_list), domain_name_n, type, class)))
		return retval;

	top_q = context->q_list;

	while(!done) {

		struct val_query_chain *last_q;

		/* keep track of the last entry added to the query chain */
		last_q = context->q_list;

		/* Data might already be present in the cache */
		/* XXX by-pass this functionality through flags if needed */
		if(VAL_NO_ERROR != (retval = ask_cache(context, NULL, &(context->q_list), &(context->a_list), &data_received)))
			return retval;
		if(data_received)
			block = 0;

		/* Send un-sent queries */
		if(VAL_NO_ERROR != (retval = ask_resolver(context, &(context->q_list), block, &(context->a_list), &data_received)))
			return retval;

		/* check if more queries have been added */
		if(last_q != context->q_list) {
			/* There are new queries to send out -- do this first; 
			 * we may also find this data in the cache 
			 */
			block = 0;
			continue;
		}

		/* Henceforth we will need some data before we can continue */
		block = 1;

		if(top_q->qc_state == Q_WAIT_FOR_GLUE) 
			merge_glue_in_referral(top_q, &(context->q_list));

		if((!data_received) && (top_q->qc_state < Q_ANSWERED))
			continue;

		/* No point going ahead if our original query had error conditions */
		if (top_q->qc_state > Q_ERROR_BASE) {
			/* the original query had some error */
			*results= (struct val_result_chain *) MALLOC (sizeof (struct val_result_chain));
			if((*results) == NULL) {
				return VAL_OUT_OF_MEMORY;
			}
			(*results)->val_rc_trust = top_q->qc_as;
			(*results)->val_rc_status = VAL_DNS_ERROR_BASE + top_q->qc_state - Q_ERROR_BASE;
			(*results)->val_rc_next = NULL;
		
			break;
		}

		/* Answer will be digested */
		data_received = 0;

		if(top_q->qc_as != NULL) {
			/* 
			 * We have sufficient data to at least perform some validation --
			 * validate what ever is possible. 
			 */
			if(VAL_NO_ERROR != (retval = verify_and_validate(context, &(context->q_list), 
								top_q->qc_as, flags, results, &done))) 
				return retval;
		}
	}

	/* Results are available */
	int partially_wrong = 0;
	int negative_proof = 0;

	for (res=*results; res && res->val_rc_trust && res->val_rc_trust->_as->ac_data; res=res->val_rc_next) {
		int success = 0;

		/* Fix validation results */
		/* Some error most likely, reflected in the val_query_chain */
		if (res->val_rc_trust == NULL) 
			res->val_rc_status = VAL_ERROR;
		if (res->val_rc_status == (VAL_R_DONT_KNOW|VAL_R_TRUST_FLAG))
			res->val_rc_status = VAL_SUCCESS;	
		if (res->val_rc_status == VAL_SUCCESS)
			success = 1;
		val_log(context, LOG_DEBUG, "validate result set to %s[%d]", p_val_error(res->val_rc_status), res->val_rc_status);

		if (!success) 
			partially_wrong = 1;
		if((res->val_rc_trust->_as->ac_data->rrs_ans_kind == SR_ANS_NACK_NXT) || 
			(res->val_rc_trust->_as->ac_data->rrs_ans_kind == SR_ANS_NACK_SOA))
			negative_proof = 1;
	}
			
	if (negative_proof) {
		if (partially_wrong) { 
			/* mark all answers as bogus - 
			 * all answers are related in the proof 
			 */
			for (res=*results; res; res=res->val_rc_next) 
				res->val_rc_status = VAL_R_BOGUS_PROOF;
		}
		else 
			prove_nonexistence (context, top_q, *results);
	}


	return VAL_NO_ERROR;
}

/*
 * Function: val_isauthentic
 *
 * Purpose:   Tells whether the given validation status code represents an
 *            authentic response from the validator
 *
 * Parameter: val_status -- a validation status code returned by the validator
 *
 * Returns:   1 if the validation status represents an authentic response
 *            0 if the validation status does not represent an authentic response
 *
 * See also: val_istrusted()
 */
int val_isauthentic( val_status_t val_status )
{
	switch (val_status) {
	case VAL_SUCCESS:
	case VAL_NONEXISTENT_NAME:
	case VAL_NONEXISTENT_TYPE:
		return 1;

	default:
		return 0;
	}
}

/*
 * Function: val_istrusted
 *
 * Purpose:   Tells whether the given validation status code represents an
 *            answer that can be trusted.  An answer can be trusted if it
 *	      has been obtained locally (for example from /etc/hosts) or if
 *            it was an authentic response from the validator.
 *
 * Parameter: val_status -- a validation status code returned by the validator
 *
 * Returns:   1 if the validation status represents a trusted response
 *            0 if the validation status does not represent a trusted response
 *
 * See also: val_isauthentic()
 */
int val_istrusted( val_status_t val_status )
{
    if ((val_status == VAL_LOCAL_ANSWER) ||
	val_isauthentic(val_status)) {
	return 1;
    }
    else {
	return 0;
    }
}
