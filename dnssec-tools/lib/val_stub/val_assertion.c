
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
#include <res_errors.h>
#include <support.h>
#include <res_query.h>

#include "val_support.h"
#include "val_zone.h"
#include "res_squery.h"
#include "val_cache.h"
#include "val_errors.h"
#include "val_assertion.h"
#include "val_verify.h"
#include "val_context.h"
#include "val_log.h"
#include "val_api.h"
#include "val_policy.h"
#include "val_parse.h"

#include "validator.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define ISSET(field,bit)        (field[bit/8]&(1<<(7-(bit%8))))
#define NONSENSE_RESULT_SEQUENCE(status) ((status <= FAIL_BASE) || (status > LAST_SUCCESS))

/*
 * Create a "result" list whose elements point to assertions and also have their
 * validated result 
 */

void free_result_chain(struct val_result **results)
{
	struct val_result *prev;

	while(NULL != (prev = *results)) {
		*results = (*results)->next;
		FREE(prev);
	}

}


u_int16_t is_trusted_key(val_context_t *ctx, u_int8_t *zone_n, struct rr_rec *key)
{
	struct trust_anchor_policy *ta_pol, *ta_cur;
	int name_len;
	u_int8_t *zp = zone_n;
	val_dnskey_rdata_t dnskey;
	struct rr_rec *curkey;

	ta_pol = RETRIEVE_POLICY(ctx, P_TRUST_ANCHOR, struct trust_anchor_policy *);	
	if (ta_pol == NULL)
		return NO_MORE;
	

	name_len = wire_name_length(zp);

	/* skip longer names */
	for (ta_cur = ta_pol; 
		  ta_cur && (wire_name_length(ta_cur->zone_n) > name_len); 
		   ta_cur=ta_cur->next);	

	/* for the remaining nodes */
	for (; ta_cur; ta_cur=ta_cur->next) {
		if (wire_name_length(ta_cur->zone_n) == name_len) {
			if (!namecmp(ta_cur->zone_n, zp)) {
				for (curkey = key; curkey; curkey=curkey->rr_next) {
					val_parse_dnskey_rdata (curkey->rr_rdata, curkey->rr_rdata_length_h, &dnskey);	
					if(!dnskey_compare(&dnskey, ta_cur->publickey))
						return EXACT;
				}
			}
		}
		else {
			/* trim the top label from our candidate zone */
			if (!zp[0])
				return NO_MORE;
			zp += (int)zp[0] + 1;

			if (namecmp(ta_cur->zone_n, zp) == 0) {
				/* We have hope */
				return NOT_YET;
			}
		} 
	}

	return NO_MORE;	
}


// XXX What about CNAMES ???

// XXX What about DNAMES ???

// XXX What about stealth mode ???

// XXX Call-back interfaces ???

// XXX Maintaining status of every signature (as opposed to signature status of the complete RRSet)

// XXX All kinds of sanitization -- wildcards, CNAMEs, cache poisoning etc

// XXX Cached data has to be replaced by authentic data (what about credibility values?)

// XXX cache timeout

// XXX Preventing cache poisoning attacks (can end up with a scenario where rolled over keys are never used)

// XXX non-existence proofs, states etc

// XXX DS problem: 
//		-- if DS is proved to not exist in the child zone, try the parent zone working down from the root
// 		-- in res_squery ask the learned zones first before sending to other name servers

// XXX hints have to be saved in a separate list (root.hints)
// XXX should not be overwritten by responses

// XXX Sharing cache, assertions, queries

// XXX policies

// XXX validation flags

// XXX Composing results

/////////////////////////////////////////////////////////////////

void lower_name (u_int8_t rdata[], int *index)
{
                                                                                                                          
    /* Convert the upper case characters in a domain name to lower case */
                                                                                                                          
    int length = wire_name_length(&rdata[(*index)]);
                                                                                                                          
    while ((*index) < length)
    {
        rdata[(*index)] = tolower(rdata[(*index)]);
        (*index)++;
    }
}


void lower (u_int16_t type_h, u_int8_t *rdata, int len)
{
    /* Convert the case of any domain name to lower in the RDATA section */
                                                                                                                          
    int index = 0;
                                                                                                                          
    switch (type_h)
    {
        /* These RR's have no domain name in them */
                                                                                                                          
        case ns_t_nsap: case ns_t_eid:      case ns_t_nimloc:   case ns_t_dnskey:
        case ns_t_aaaa: case ns_t_loc:      case ns_t_atma:     case ns_t_a:
        case ns_t_wks:  case ns_t_hinfo:    case ns_t_txt:      case ns_t_x25:
        case ns_t_isdn: case ns_t_ds:       default:
                                                                                                                          
            return;
                                                                                                                          
        /* These RR's have two domain names at the start */
                                                                                                                          
        case ns_t_soa:  case ns_t_minfo:    case ns_t_rp:
                                                                                                                          
            lower_name (rdata, &index);
            /* fall through */
                                                                                                                          
                                                                                                                          
        /* These have one name (and are joined by the code above) */
                                                                                                                          
        case ns_t_ns:   case ns_t_cname:    case ns_t_mb:       case ns_t_mg:
        case ns_t_mr:   case ns_t_ptr:      case ns_t_nsec:
                                                                                                                          
            lower_name (rdata, &index);
                                                                                                                          
            return;
                                                                                                                          
        /* These RR's end in one or two domain names */
                                                                                                                          
        case ns_t_srv:
                                                                                                                          
            index = 4; /* SRV has three preceeding 16 bit quantities */
                                                                                                                          
        case ns_t_rt: case ns_t_mx: case ns_t_afsdb: case ns_t_px:
                                                                                                                          
            index += 2; /* Pass the 16 bit quatity prior to the name */
                                                                                                                          
            lower_name (rdata, &index);
                                                                                                                          
            /* Get the second tail name (only in PX records) */
            if (type_h == ns_t_px) lower_name (rdata, &index);
                                                                                                                          
            return;
                                                                                                                          
        /* The last case is RR's with names in the middle. */
        /*
            Note: this code is never used as SIG's are the only record in
            this case.  SIG's are not signed, so they never are run through
            this code.  This is left here in case other RR's are defined in
            this unfortunate (for them) manner.
        */
        case ns_t_rrsig:
                                                                                                                          
            index = SIGNBY;
                                                                                                                          
            lower_name (rdata, &index);
                                                                                                                          
            return;
    }
}


struct rr_rec *copy_rr_rec (u_int16_t type_h, struct rr_rec *r, int dolower)
{
    /*
        Make a copy of an RR, lowering the case of any contained
        domain name in the RR section.
    */
    struct rr_rec *the_copy;
                                                                                                                          
    the_copy = (struct rr_rec *) MALLOC (sizeof(struct rr_rec));
                                                                                                                          
    if (the_copy==NULL) return NULL;
                                                                                                                          
    the_copy->rr_rdata_length_h = r->rr_rdata_length_h;
    the_copy->rr_rdata = (u_int8_t *) MALLOC (the_copy->rr_rdata_length_h);
                                                                                                                          
    if (the_copy->rr_rdata==NULL) return NULL;
                                                                                                                          
    memcpy (the_copy->rr_rdata, r->rr_rdata, r->rr_rdata_length_h);
                                                                                                                          
	if(dolower)
	    lower (type_h, the_copy->rr_rdata, the_copy->rr_rdata_length_h);
                                                                                                                          
    the_copy->rr_next = NULL;
    return the_copy;
}

#define INSERTED    1
#define DUPLICATE   -1
int link_rr (struct rr_rec **cs, struct rr_rec *cr)
{
    /*
        Insert a copied RR into the set being prepared for signing.  This
        is an implementation of an insertoin sort.
    */
    int             ret_val;
    int             length;
    struct rr_rec   *temp_rr;
                                                                                                                          
    if (*cs == NULL)
    {
        *cs = cr;
        return INSERTED;
    }
    else
    {
        length =(*cs)->rr_rdata_length_h<cr->rr_rdata_length_h?
                (*cs)->rr_rdata_length_h:cr->rr_rdata_length_h;
                                                                                                                          
        ret_val = memcmp ((*cs)->rr_rdata, cr->rr_rdata, length);
                                                                                                                          
        if (ret_val==0&&(*cs)->rr_rdata_length_h==cr->rr_rdata_length_h)
        {
            /* cr is a copy of an existing record, forget it... */
            FREE (cr->rr_rdata);
            FREE (cr);
            return DUPLICATE;
        }
        else if (ret_val > 0 || (ret_val==0 && length==cr->rr_rdata_length_h))
        {
            cr->rr_next = *cs;
            *cs = cr;
            return INSERTED;
        }
        else
        {
            temp_rr = *cs;
                                                                                                                          
            if (temp_rr->rr_next == NULL)
            {
                temp_rr->rr_next = cr;
                cr->rr_next = NULL;
                return INSERTED;
            }
                                                                                                                          
            while (temp_rr->rr_next)
            {
                length = temp_rr->rr_next->rr_rdata_length_h <
                                                cr->rr_rdata_length_h ?
                         temp_rr->rr_next->rr_rdata_length_h :
                                                cr->rr_rdata_length_h;
                                                                                                                          
                ret_val = memcmp (temp_rr->rr_next->rr_rdata, cr->rr_rdata,
                                    length);
                if (ret_val==0 &&
                    temp_rr->rr_next->rr_rdata_length_h==cr->rr_rdata_length_h)
                {
                    /* cr is a copy of an existing record, forget it... */
                    FREE (cr->rr_rdata);
                    FREE (cr);
                    return DUPLICATE;
                }
                else if (ret_val>0||(ret_val==0&&length==cr->rr_rdata_length_h))
                {
                    /* We've found a home for the record */
                    cr->rr_next = temp_rr->rr_next;
                    temp_rr->rr_next = cr;
                    return INSERTED;
                }
                temp_rr = temp_rr->rr_next;
            }
                                                                                                                          
            /* If we've gone this far, add the record to the end of the list */
                                                                                                                          
            temp_rr->rr_next = cr;
            cr->rr_next = NULL;
            return INSERTED;
        }
    }
}

struct rrset_rec *copy_rrset_rec (struct rrset_rec *rr_set)
{
    struct rrset_rec    *copy_set;
    struct rr_rec       *orig_rr;
    struct rr_rec       *copy_rr;
    size_t              o_length;
                                                                              
    copy_set = (struct rrset_rec *) MALLOC (sizeof(struct rrset_rec));
                                                                                                                          
    if (copy_set == NULL) return NULL;
                                                                                                                          
    o_length = wire_name_length (rr_set->rrs_name_n);

    memcpy (copy_set, rr_set, sizeof(struct rrset_rec));
    copy_set->rrs_data = NULL;
    copy_set->rrs_next = NULL;
    copy_set->rrs_sig = NULL;
    copy_set->rrs_name_n = NULL;
	copy_set->rrs_name_n = (u_int8_t *) MALLOC (o_length);
	if (copy_set->rrs_name_n == NULL) {
		FREE(copy_set);
		return NULL;
	}
	memcpy(copy_set->rrs_name_n, rr_set->rrs_name_n, o_length); 
                                                                                                                     
    /*
        Do an insertion sort of the records in rr_set.  As records are
        copied, convert the domain names to lower case.
    */
                                                                                                                          
    for (orig_rr = rr_set->rrs_data; orig_rr; orig_rr = orig_rr->rr_next)
    {
        /* Copy it into the right form for verification */
        copy_rr = copy_rr_rec (rr_set->rrs_type_h, orig_rr, 1);
                                                                                                                          
        if (copy_rr==NULL) return NULL;
                                                                                                                          
        /* Now, find a place for it */
                                                                                                                          
        link_rr (&copy_set->rrs_data, copy_rr);
    }

	/* Copy the rrsigs also */

    for (orig_rr = rr_set->rrs_sig; orig_rr; orig_rr = orig_rr->rr_next)
    {
        /* Copy it into the right form for verification */
        copy_rr = copy_rr_rec (rr_set->rrs_type_h, orig_rr, 0);
                                                                                                                          
        if (copy_rr==NULL) return NULL;
                                                                                                                          
        /* Now, find a place for it */
                                                                                                                          
        link_rr (&copy_set->rrs_sig, copy_rr);
    }

    return copy_set;
}




/*
 * Add {domain_name, type, class} to the list of queries currently active
 * for validating a response. 
 *
 * Returns:
 * NO_ERROR			Operation succeeded
 * SR_CALL_ERROR	The domain name is invalid
 * OUT_OF_MEMORY	Could not allocate enough memory for operation
 */
int add_to_query_chain(struct query_chain **queries, u_char *name_n, 
						const u_int16_t type_h, const u_int16_t class_h)
{
	struct query_chain *temp, *prev;

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
		return NO_ERROR;
	}


	temp = (struct query_chain *) MALLOC (sizeof (struct query_chain));
	if (temp==NULL) return OUT_OF_MEMORY;
                                                                                                                          
	memcpy (temp->qc_name_n, name_n, wire_name_length(name_n));
	temp->qc_type_h = type_h; 
	temp->qc_class_h = class_h; 
	temp->qc_state = Q_INIT;    
	temp->qc_as = NULL;   
	temp->qc_next = *queries;
	*queries = temp;
                                                                                                                          
	return NO_ERROR;
}


/*
 * Free up the query chain.
 */
void free_query_chain(struct query_chain **queries)
{
	if (queries==NULL || (*queries)==NULL) return;
                                                                                                                          
	if ((*queries)->qc_next)
		free_query_chain (&((*queries)->qc_next));
                                                                                                                          
	FREE (*queries);
	(*queries) = NULL;
}


int ask_cache(val_context_t *context, struct query_chain *end_q, 
				struct query_chain **queries, struct assertion_chain **assertions)
{
	struct query_chain *next_q, *top_q;
	struct rrset_rec *next_answer;
	int retval;

	top_q = *queries;

	for(next_q = *queries; next_q && next_q != end_q; next_q=next_q->qc_next) {
		if(next_q->qc_state == Q_INIT) {

			switch(next_q->qc_type_h) {

				case ns_t_ds:
					next_answer = get_cached_ds(); 
					break;	
				
				case ns_t_dnskey:
					next_answer = get_cached_keys(); 
					break;	

				default:
					next_answer = get_cached_answers(); 
					break;	
			}

			while(next_answer)	{ 
				if ((next_answer->rrs_type_h == next_q->qc_type_h) 
					&& (next_answer->rrs_class_h == next_q->qc_class_h) 
					&& (namecmp(next_answer->rrs_name_n, next_q->qc_name_n) == 0)) 
					break;
				next_answer = next_answer->rrs_next;
			}

			if(next_answer != NULL) {
				struct domain_info *response;
				char name[MAXDNAME];

				/* Construct a dummy response */
				response = (struct domain_info *) MALLOC (sizeof(struct domain_info));
				if(response == NULL)
					return OUT_OF_MEMORY;

				response->di_rrset = next_answer;
			    response->di_qnames = (struct qname_chain *) MALLOC (sizeof(struct qname_chain));
				if (response->di_qnames == NULL) 
					return OUT_OF_MEMORY;
				memcpy (response->di_qnames->qc_name_n, next_q->qc_name_n, wire_name_length(next_q->qc_name_n));
				response->di_qnames->qc_next = NULL;
			    response->di_error_message = NULL;

				if(ns_name_ntop(next_q->qc_name_n, name, MAXDNAME-1) == -1) {
					next_q->qc_state = Q_ERROR;
					FREE(response->di_qnames);
					FREE (response);
					continue;
				}
			    response->di_requested_name_h = name; 
			    response->di_requested_type_h = next_q->qc_type_h;
			    response->di_requested_class_h = next_q->qc_class_h;

				if(NO_ERROR != (retval = assimilate_answers(context, queries, response, next_q, assertions))) {
					FREE(response->di_qnames);
					FREE (response);
					return retval;
				}

				FREE(response->di_qnames);
				FREE (response);

				break;
			}
		}
	}

	if(top_q != *queries) 
		/* more qureies have been added, do this again */
		return ask_cache(context, top_q, queries, assertions);


	return NO_ERROR;
}

int ask_resolver(val_context_t *context, struct query_chain **queries, int block, struct assertion_chain **assertions)
{
	// XXX Send multiple queries in parallel 

	struct query_chain *matched_q;
	struct query_chain *next_q;
	struct domain_info *response;
	int retval;

	matched_q = NULL;
	response = NULL;

	for(next_q = *queries; next_q ; next_q = next_q->qc_next) {

		if(next_q->qc_state == Q_INIT) {
			char name[MAXDNAME];
		
			matched_q = next_q;

			if(ns_name_ntop(matched_q->qc_name_n, name, MAXDNAME-1) == -1) {
				matched_q->qc_state = Q_ERROR;
				continue;
			}

			matched_q->qc_state = Q_SENT;

			response = (struct domain_info *) MALLOC (sizeof(struct domain_info));
			if (response == NULL) 
				return OUT_OF_MEMORY;
 
		    retval = res_squery ( NULL, name, 
						matched_q->qc_type_h, 
						matched_q->qc_class_h, 
						context->resolver_policy, 
						response);

			break;
		}
	}

	if(response != NULL) {
		if(NO_ERROR != (retval = assimilate_answers(context, queries, response, matched_q, assertions))) {
			free_domain_info_ptrs(response);
			return retval;
		}

		/* Save new responses in the cache */
		stow_answer(response->di_rrset);
		response->di_rrset = NULL;
		free_domain_info_ptrs(response);
	}
	return NO_ERROR;
}


int set_ans_kind (    u_int8_t    *qc_name_n,
                      const u_int16_t     q_type_h,
                      const u_int16_t     q_class_h,
                      struct rrset_rec    *the_set,
					  u_int16_t			*status)
{
    /* Answer is a Referral if... */
                                                                                                                          
        /* Referals won't make it this far, therr handled in digest_response */
                                                                                                                          
    /* Answer is a NACK_NXT if... */
                                                                                                                          
    if (the_set->rrs_type_h == ns_t_nsec)
    {
        if (namecmp(the_set->rrs_name_n, qc_name_n)==0 &&
                            (q_type_h == ns_t_any || q_type_h == ns_t_nsec))
            /* We asked for it */
            the_set->rrs_ans_kind = SR_ANS_STRAIGHT;
        else
            the_set->rrs_ans_kind = SR_ANS_NACK_NXT;

        return SR_UNSET;
    }
                                                                                                                          
    /* Answer is a NACK_SOA if... */
                                                                                                                          
    if (the_set->rrs_type_h == ns_t_soa)
    {
        if (namecmp(the_set->rrs_name_n, qc_name_n)==0 &&
                            (q_type_h == ns_t_any || q_type_h == ns_t_soa))
            /* We asked for it */
            the_set->rrs_ans_kind = SR_ANS_STRAIGHT;
        else
            the_set->rrs_ans_kind = SR_ANS_NACK_SOA;
                                                                                                                          
        return SR_UNSET;
    }
                                                                                                                          
    /* Answer is a CNAME if... */
                                                                                                                          
    if (the_set->rrs_type_h == ns_t_cname)
    {
        if (namecmp(the_set->rrs_name_n, qc_name_n)==0 &&
                            (q_type_h == ns_t_any || q_type_h == ns_t_cname))
            /* We asked for it */
            the_set->rrs_ans_kind = SR_ANS_STRAIGHT;
        else
            the_set->rrs_ans_kind = SR_ANS_CNAME;
                                                                                                                          
        return SR_UNSET;
    }
                                                                                                                          
    /* Answer is an ANSWER if... */
    if (namecmp(the_set->rrs_name_n, qc_name_n)==0 &&
                    (q_type_h==ns_t_any || q_type_h==the_set->rrs_type_h))
    {
        /* We asked for it */
        the_set->rrs_ans_kind = SR_ANS_STRAIGHT;
        return SR_UNSET;
    }
                                                                                                                          
    the_set->rrs_ans_kind = SR_ANS_UNSET;
	*status = IRRELEVANT_DATA;
                                                                                                                          
    return SR_PROCESS_ERROR;
}

#define TOP_OF_QNAMES   0
#define MID_OF_QNAMES   1
#define NOT_IN_QNAMES   2
                                                                                                                          
int name_in_q_names (
                      struct qname_chain  *q_names_n,
                      struct rrset_rec    *the_set)
{
    struct qname_chain *temp_qc;
                                                                                                                          
    if (q_names_n==NULL) return NOT_IN_QNAMES;
                                                                                                                          
    if (namecmp(the_set->rrs_name_n, q_names_n->qc_name_n)==0)
        return TOP_OF_QNAMES;
                                                                                                                          
    temp_qc = q_names_n->qc_next;
                                                                                                                          
    while (temp_qc)
    {
        if (namecmp(the_set->rrs_name_n, temp_qc->qc_name_n)==0)
            return MID_OF_QNAMES;
        temp_qc = temp_qc->qc_next;
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
    int type_match = the_set->rrs_type_h==q_type_h || q_type_h==ns_t_any;
    int class_match = the_set->rrs_class_h==q_class_h || q_class_h==ns_c_any;
    int data_present = the_set->rrs_data != NULL;
                                                                                                                          
    if (the_set->rrs_status != SR_DATA_UNCHECKED) return FALSE;
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
            the_set->rrs_status = SR_WRONG;
			*status = IRRELEVANT_DATA;
            return TRUE;
        }
                                                                                                                          
    return FALSE;
}


int NSEC_is_wrong_answer (
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
                                                                                                                          
    if (namecmp(the_set->rrs_name_n, qc_name_n)==0)
    {
        /* NXT owner = query name & q_type not in list */
        nsec_bit_field = wire_name_length (the_set->rrs_data->rr_rdata);
                                                                                                                          
        if (ISSET((&(the_set->rrs_data->rr_rdata[nsec_bit_field])), q_type_h))
        {
            the_set->rrs_status = SR_WRONG;
			*status = IRRELEVANT_PROOF;	
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
        if (namecmp(the_set->rrs_name_n, qc_name_n) > 0)
        {
            the_set->rrs_status = SR_WRONG;
			*status = IRRELEVANT_PROOF;	
            return TRUE;
        }
        
        return FALSE;
    }
}

/*
 * Add a new assertion for the response data 
 *
 * Returns:
 * NO_ERROR			Operation succeeded
 * OUT_OF_MEMORY	Could not allocate enough memory for operation
 */
int add_to_assertion_chain(struct assertion_chain **assertions, struct rrset_rec *response_data)
{
	struct assertion_chain *new_as, *first_as, *prev_as;
	struct rrset_rec *next_rr;

	first_as = NULL;
	prev_as = NULL;
	next_rr = response_data;
	while(next_rr) {

		new_as = (struct assertion_chain *) MALLOC (sizeof (struct assertion_chain)); 
		if (new_as==NULL) return OUT_OF_MEMORY;
                      
		new_as->ac_data = copy_rrset_rec(next_rr);
		new_as->ac_trust = NULL;        
		new_as->ac_more_data = NULL;        
		new_as->ac_next = NULL;        
		new_as->ac_pending_query = NULL; 
		new_as->ac_state = A_INIT;
		if(first_as != NULL) { 
			/* keep the first assertion constant */
			new_as->ac_next = first_as->ac_next;
			first_as->ac_next = new_as;
			prev_as->ac_more_data = new_as;	
			
		}
		else {
			first_as = new_as;
			new_as->ac_next = *assertions;
			*assertions = new_as;
		}
		prev_as = new_as;
		next_rr = next_rr->rrs_next;
	}
                                                                                                                  
	return NO_ERROR;
}

/*
 * Free up the assertion chain.
 */
void free_assertion_chain(struct assertion_chain **assertions)
{
	if (assertions==NULL || (*assertions)==NULL) return;
                                                                                                                          
	if ((*assertions)->ac_next)
		free_assertion_chain (&((*assertions)->ac_next));
                                                                                                                         
	res_sq_free_rrset_recs(&((*assertions)->ac_data));
	FREE (*assertions);
	(*assertions) = NULL;
}

/*
 * For a given assertion identify its pending queries
 */
int build_pending_query(val_context_t *context, 
		struct query_chain **queries, struct assertion_chain *as)
{
	u_int8_t *signby_name_n;
	int retval;

	if(as->ac_data->rrs_data == NULL) {
		as->ac_state = A_NO_DATA;
		return NO_ERROR;
	}

	if(as->ac_data->rrs_type_h == ns_t_rrsig) { 
		as->ac_state = BARE_RRSIG;
		return NO_ERROR;
	}

	if(as->ac_data->rrs_sig == NULL) {
		as->ac_state = A_WAIT_FOR_RRSIG;
		/* create a query and link it as the pending query for this assertion */
		if(NO_ERROR != (retval = add_to_query_chain(queries, 
						as->ac_data->rrs_name_n, ns_t_rrsig, as->ac_data->rrs_class_h)))
			return retval;
		as->ac_pending_query = *queries;/* The first value in the list is the most recent element */
		return NO_ERROR;
	}

	/* 
	 * Identify the DNSKEY that created the RRSIG:
	 */

	/* First identify the signer name from the RRSIG */
	signby_name_n = &as->ac_data->rrs_sig->rr_rdata[SIGNBY];

	//XXX The signer name has to be within the zone

	/* Then look for  {signby_name_n, DNSKEY/DS, type} */

	if(as->ac_data->rrs_type_h == ns_t_dnskey) {

		u_int16_t tkeystatus = is_trusted_key(context, signby_name_n, as->ac_data->rrs_data);
		switch (tkeystatus) {
			case EXACT: 	
				as->ac_state = A_TRUSTED; 
				return NO_ERROR;

			case NO_MORE: 	
				as->ac_state = NO_TRUST_ANCHOR; 
				return NO_ERROR;

			default:
				as->ac_state = A_WAIT_FOR_TRUST;
				break;
		}

		/* State has to be A_WAIT_FOR_TRUST here */

		/* Create a query for missing data */
		if(NO_ERROR != (retval = add_to_query_chain(queries, signby_name_n, 
					ns_t_ds, as->ac_data->rrs_class_h)))
			return retval;

	}
	else { 
		/* look for DNSKEY records */
		if(NO_ERROR != (retval = add_to_query_chain(queries, signby_name_n, 
						ns_t_dnskey, as->ac_data->rrs_class_h)))
			return retval;
	}

	as->ac_pending_query = *queries; /* The first value in the list is the most recent element */
	as->ac_state = A_WAIT_FOR_TRUST;
	return NO_ERROR;
}


/*
 * Read the response that came in and create assertions from it. Set the state
 * of the assertion based on what data is available and whether validation
 * can proceed.
 * 
 * Returns:
 * NO_ERROR			Operation completed successfully
 * SR_CALL_ERROR	If the name could not be converted from host to network format
 *
 */ 
int assimilate_answers(val_context_t *context, struct query_chain **queries, 
							struct domain_info *response, struct query_chain *matched_q, 
								struct assertion_chain **assertions)
{
	int retval;
	struct assertion_chain *as = NULL;
	u_int16_t type_h = response->di_requested_type_h;
    u_int16_t class_h = response->di_requested_class_h;	
	u_int8_t kind = SR_ANS_UNSET;

	if (matched_q == NULL)
		return NO_ERROR;

	if(matched_q->qc_as != NULL) {
		/* We already had an assertion for this query */
		// XXX What about FLOOD_ATTACKS ?
		return NO_ERROR; 
	}

	/* Create an assertion for the response data */
	if (response->di_rrset == NULL) {
		matched_q->qc_state = Q_ERROR;
		return NO_ERROR;
	}

	if(NO_ERROR != (retval = add_to_assertion_chain(assertions, response->di_rrset))) 
		return retval;

	as = *assertions; /* The first value in the list is the most recent element */
	/* Link the original query to the above assertion */
	matched_q->qc_as = as;
	matched_q->qc_state = Q_ANSWERED;

	/* Identify the state for each of the assertions obtained */
	for (; as; as = as->ac_more_data) {
	
		/* Cover error conditions first */
		/* SOA checks will appear during sanity checks later on */
		if((	set_ans_kind(response->di_qnames->qc_name_n, type_h, class_h, 
					as->ac_data, &as->ac_state) == SR_PROCESS_ERROR)
				|| fails_to_answer_query(response->di_qnames, type_h, class_h, as->ac_data, &as->ac_state)
				|| NSEC_is_wrong_answer (response->di_qnames->qc_name_n, type_h, class_h, 
					as->ac_data, &as->ac_state)) {
			continue;
		}

		if (kind == SR_ANS_UNSET)
			kind = as->ac_data->rrs_ans_kind;
		else {
			/* STRAIGHT and CNAME are OK */
			if ((kind == SR_ANS_STRAIGHT) || (kind == SR_ANS_CNAME)) {
				if ((as->ac_data->rrs_ans_kind != SR_ANS_STRAIGHT) &&
					(as->ac_data->rrs_ans_kind != SR_ANS_CNAME)) {
					matched_q->qc_state = Q_CONFLICTING_ANSWERS;
				}
			}
			/* NACK_NXT and NACK_SOA */
			else if ((as->ac_data->rrs_ans_kind != SR_ANS_NACK_NXT) &&
				(as->ac_data->rrs_ans_kind != SR_ANS_NACK_SOA)) {
				matched_q->qc_state = Q_CONFLICTING_ANSWERS;
			}
		}

		if (NO_ERROR != (retval = build_pending_query(context, queries, as)))
			return retval;
	}
	return NO_ERROR;
}

void  prove_nonexistence (struct query_chain *top_q, struct val_result *results) 
{
	struct val_result *res;
	int wcard_chk = 0;
	int span_chk = 0;
	int status = NONEXISTENT; 
	u_int8_t *soa_name_n = NULL;	
	u_int8_t *closest_encounter = NULL;	
	struct rrset_rec *wcard_proof = NULL;

	/* 
	 * Check if this is the whole proof and nothing but the proof
	 * At this point these records should already be in the TRUSTED state.
	 */

	/* inspect the SOA record first */
	// XXX Can we assume that the SOA record is always present?
	for(res = results; res; res = res->next) {
		struct rrset_rec *the_set = res->as->ac_data;
		if (the_set->rrs_ans_kind == SR_ANS_NACK_SOA) {
			soa_name_n = the_set->rrs_name_n;
			break;
		}
	}

	if (soa_name_n == NULL)
		status = INCOMPLETE_PROOF;
	else {
		/* for every NSEC */
		for(res = results; res; res = res->next) {
			struct rrset_rec *the_set = res->as->ac_data;
			if (the_set->rrs_ans_kind == SR_ANS_NACK_NXT) { 
				if (!namecmp(the_set->rrs_name_n, top_q->qc_name_n)) {
					/* we already made sure that the type was missing in
					 * NSEC_is_wrong_answer()
					 */
					span_chk = 1;
					/* if the label count in the RRSIG equals the labels
					 * in the nsec owner name, wildcard absence is also proved
					 * Be sure to check the label count in an RRSIG that was 
					 * verified
					 */
					struct rr_rec *sig;
					int wcard;
					for (sig = the_set->rrs_sig; sig; sig = sig->rr_next) {
						if ((sig->status == RRSIG_VERIFIED) && 
							(SR_UNSET == check_label_count(the_set, sig, &wcard))) {
							if (wcard == 0)
								wcard_chk = 1;
							break;
						}
					}
				}
				else {
					/* Find the next name */
					u_int8_t *nxtname =	the_set->rrs_data->rr_rdata;

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
						if ((cmp = namecmp(cur_name_n, the_set->rrs_name_n)) == 0) {
							closest_encounter = cur_name_n;
							break;
						}
						else if (cmp < 0) {
							/* strip off one label from the NSEC owner name */
							closest_encounter = &the_set->rrs_name_n[the_set->rrs_name_n[0] + 1];
							break; 
						}
						offset += cur_name_n[0] + 1;
					}
				}
			}
		}
		if (!span_chk)
			status = INCOMPLETE_PROOF;
		else if (!wcard_chk) {
			if (!closest_encounter)
				status = INCOMPLETE_PROOF;	
			else {
				/* Check the wild card proof */
				/* prefix "*" to the closest encounter, and check if that 
				 * name falls within the range given in wcard_proof
				 */	
				u_int8_t *nxtname =	wcard_proof->rrs_data->rr_rdata;
				u_char domain_name_n[MAXCDNAME];
				domain_name_n[0] = 0x01;
				domain_name_n[1] = 0x2a; /* for the '*' character */
				memcpy(&domain_name_n[2], closest_encounter, wire_name_length(closest_encounter));
				if ((namecmp(domain_name_n, wcard_proof->rrs_name_n) <= 0) ||  
					(namecmp(nxtname, domain_name_n) <= 0))
					status = INCOMPLETE_PROOF;	
			}
		}
	}	

	/* set the error condition in all elements of the proof */
	for(res = results; res; res = res->next) 
		res->status = status;

}

/*
 * Verify an assertion if possible. Complete assertions are those for which 
 * you have data, rrsigs and key information. 
 * Returns:
 * NO_ERROR			Operation completed successfully
 * Other return values from add_to_query_chain()
 */
int try_verify_assertion(val_context_t *context, struct query_chain **queries, 
				struct assertion_chain *next_as)
{
	struct query_chain *pc;
	struct assertion_chain *pending_as;
	int retval;
	u_int16_t type_h, class_h;
	struct rrset_rec *pending_rrset; 
	u_int8_t *signby_name_n;

	/* Sanity check */
	if(next_as == NULL)
		return NO_ERROR;

	pc = next_as->ac_pending_query;
	if (!pc)
		/* 
		 * If there is no pending query, we've already 
		 * reached some end-state.
		 */
		return NO_ERROR;

	switch (pc->qc_state) {

		case Q_ERROR: /* fall-through */
		case Q_CONFLICTING_ANSWERS:
					next_as->ac_state = A_ERROR;
					break;

		case Q_ANSWERED:
					pending_as = pc->qc_as;
					if(next_as->ac_state == A_WAIT_FOR_RRSIG) {
						/* We were waiting for the RRSIG */
						pending_rrset = pending_as->ac_data;
			
						/* 
						 * Check if what we got was an RRSIG 
						 */
						if (pending_rrset->rrs_type_h != ns_t_rrsig) {
							/* Could not find any RRSIG */
							next_as->ac_state = RRSIG_MISSING; 
							break;
						}
						/* Find the RRSIG that matches the type */
						for(;pending_rrset;pending_rrset=pending_rrset->rrs_next) { 
							/* Check if type is in the RRSIG */
							u_int16_t rrsig_type_h;
							memcpy(&rrsig_type_h, pending_rrset->rrs_sig, sizeof(u_int16_t));
							if (rrsig_type_h == next_as->ac_data->rrs_type_h)				
								break;
						}
						if(pending_rrset == NULL) {
							/* Could not find any RRSIG matching query type*/
							next_as->ac_state = RRSIG_MISSING; 
							break;
						}

						/* store the RRSIG in the assertion */
						next_as->ac_data->rrs_sig = 
						copy_rr_rec(pending_rrset->rrs_type_h, pending_rrset->rrs_sig, 0);
						next_as->ac_state = A_WAIT_FOR_TRUST; 
						/* create a pending query for the trust portion */
   						signby_name_n = &next_as->ac_data->rrs_sig->rr_rdata[SIGNBY];
						class_h = next_as->ac_data->rrs_class_h;			
						if(next_as->ac_data->rrs_type_h == ns_t_dnskey)
							type_h = ns_t_ds;
						else 
							type_h = ns_t_dnskey;

						if(NO_ERROR != (retval = 
								add_to_query_chain(queries, signby_name_n, type_h, class_h)))
							return retval;
						next_as->ac_pending_query = *queries;
					}
					else if (next_as->ac_state == A_WAIT_FOR_TRUST) {
						next_as->ac_trust = pending_as;
						next_as->ac_pending_query = NULL;

						if((pending_as->ac_data->rrs_ans_kind == SR_ANS_NACK_NXT)
		                   || (pending_as->ac_data->rrs_ans_kind == SR_ANS_NACK_SOA)) { 

							/* proof of non-existence should follow */
							next_as->ac_state = A_NEGATIVE_PROOF;
						}
						else { 
							/* XXX what if this is an SR_ANS_CNAME? Can DS or DNSKEY return a CNAME? */
							/* 
							 * if the pending assertion contains a straight answer, 
						   	 * trust is useful for verification 
							 */
							next_as->ac_state = A_CAN_VERIFY;
						}
					}
					break;

		default:
					break;
						
	}

	if(next_as->ac_state == A_CAN_VERIFY) 
		verify_next_assertion(next_as);

	return NO_ERROR;
}

/*
 * Try and verify each assertion. Update results as and when they are available.
 * Do not try and validate assertions that have already been validated.
 */
int  verify_n_validate(val_context_t *context, struct query_chain **queries, 
								struct assertion_chain *top_as, u_int8_t flags, 
								struct val_result **results, int *done)
{
	struct assertion_chain *next_as;
	int retval;
	struct assertion_chain *as_more;
	struct val_result *res;
	
	*done = 1;

	/* Look at every answer that was returned */
	for(as_more= top_as; as_more; as_more=as_more->ac_more_data) {

		/* 
		 * If this assertion is already in the results list with a completed status
		 * no need for repeating the validation process
		 */
		for (res=*results; res; res=res->next) 
			if (res->as == as_more) 
				break;
		if (res) {
			if (res->status != A_DONT_KNOW)
				/* we've already dealt with this one */
				continue;
		}
		else {
			/* Add this result to the list */
			res= (struct val_result *) MALLOC (sizeof (struct val_result));
			if(res== NULL)
				return OUT_OF_MEMORY;
			res->as = as_more;
			res->status = A_DONT_KNOW;
			res->trusted = 0;
			res->next = *results;
			*results = res;
		}

		/* 
		 * as_more is the next answer that we obtained; next_as is the 
		 * next assertion in the chain of trust
		 */
		for (next_as=as_more; next_as; next_as=next_as->ac_trust) {

			/* Go up the chain of trust */
			if(NO_ERROR != (retval = try_verify_assertion(context, queries, next_as))) 
				return retval;

			/*  
			 * break out of infinite loop -- trying to verify the proof of non-existence
			 * for a DS record; but the DNSKEY that signs the proof is also in the 
			 * chain of trust (not-validated)
			 */
			if((next_as->ac_data->rrs_type_h == ns_t_dnskey) &&
					(next_as->ac_trust) && 
					(next_as == next_as->ac_trust->ac_trust)) {
				res->status = INDETERMINATE_DS; 
				break;
			}
			/* Check initial states */
			if(next_as->ac_state <= A_INIT) {
				/* still need more data to validate this assertion */
				*done = 0;
			}
			else if (next_as->ac_state == A_TRUSTED) {
				res->trusted = 1; 
				break;
			}
			else if (next_as->ac_state == A_NEGATIVE_PROOF) {

				/*
				 * if we are able to prove non existence, we have 
				 * shown that a component of the chain-of-trust is provably 
				 * absent (provably unsecure).
				 * If we cannot prove this later on (!trusted) we cannot believe 
				 * the original answer either, since we still haven't reached 
				 * a trust anchor. 
				 * Dont see any use for separating these conditions, so treat them
				 * as INDETERMINATE always
				 */
				res->status = INDETERMINATE_PROOF;
				break;
			}
			/* Check error conditions */
			else if (next_as->ac_state <= LAST_ERROR) {
				if (NONSENSE_RESULT_SEQUENCE(res->status)) {
					/* 
					 * Some obfuscated attempt to confuse us 
					 * give up early.
					 */
					res->status = INDETERMINATE_ERROR; 
					break;
				}
				else {
					res->status = next_as->ac_state; 
					continue;
				}
			}
			else
				res->status = next_as->ac_state;
		}
	}
	
	return NO_ERROR;
}


void fix_validation_results(struct query_chain *top_q, struct val_result *res, int *success)
{
	*success = 0;

	/* Some error most likely, reflected in the query_chain */
	if (res->as == NULL) 
		res->status = top_q->qc_state;
	/* 
	 * If there was no missing data, and the result status is
	 * not known, this is indeterminate if we did not see a trust
	 * anchor, else this is validated. 
	 */
	if ((res->status == A_DONT_KNOW) || (res->status == VERIFIED)) {
		if (res->trusted == 1)
			res->status = VALIDATE_SUCCESS;
		else
			res->status = INDETERMINATE_TRUST;
	}

	/* Could not build a chain of trust for the signature that failed */
	if ((res->status > FAIL_BASE) && (res->status <= LAST_FAILURE) && (res->trusted != 1)) 
		res->status = BOGUS;	


	// XXX Do CNAME sanity etc


	if (res->status == VALIDATE_SUCCESS)
		*success = 1;
}

/*
 * Look inside the cache, ask the resolver for missing data.
 * Then try and validate what ever is possible.
 * Return when we are ready with some useful answer (error condition is 
 * a useful answer)
 */
int resolve_n_check(	val_context_t	*context,
			const char *domain_name,
			const u_int16_t type,
			const u_int16_t class,
			const u_int8_t flags, 
			struct query_chain **queries,
			struct assertion_chain **assertions,
			struct val_result **results)
{

	int retval;
	struct query_chain *top_q;
	struct val_result *res;
	char block = 1; /* block until at least some data is returned */

	top_q = *queries;
	int done = 0;

	while(!done) {

		struct query_chain *last_q;

		/* keep track of the last entry added to the query chain */
		last_q = *queries;

		/* Data might already be present in the cache */
		/* XXX by-pass this functionality through flags if needed */
		if(NO_ERROR != (retval = ask_cache(context, NULL, queries, assertions)))
			return retval;

		/* Send un-sent queries */
		if(NO_ERROR != (retval = ask_resolver(context, queries, block, assertions)))
			return retval;

		/* check if more queries have been added */
		if(last_q != *queries) {
			/* There are new queries to send out -- do this first; 
			 * we may also find this data in the cache 
			 */
			block = 0;
			continue;
		}

		/* Henceforth we will need some data before we can continue */
		block = 1;

		/* No point going ahead if our original query had error conditions */
		if (top_q->qc_state != Q_ANSWERED) {
			/* the original query had some error */
			res= (struct val_result *) MALLOC (sizeof (struct val_result));
			if(res== NULL)
				return OUT_OF_MEMORY;
			res->as = top_q->qc_as;
			res->status = A_ERROR;
			res->trusted = 0;
			res->next = NULL;
		
			return NO_ERROR;
		}
		/* 
		 * We have sufficient data to at least perform some validation --
		 * validate what ever is possible. 
		 */
		if(NO_ERROR != (retval = verify_n_validate(context, queries, 
							top_q->qc_as, flags, results, &done))) 
			return retval;
	}

	/* Results are available */
	int partially_correct = 0;
	int negative_proof = 0;
	for (res=*results; res; res=res->next) {
		int success = 0;
		fix_validation_results(top_q, res, &success);
		if (!success) 
			partially_correct = 1;
		if((res->as->ac_data->rrs_ans_kind == SR_ANS_NACK_NXT) || 
			(res->as->ac_data->rrs_ans_kind == SR_ANS_NACK_SOA))
			negative_proof = 1;
	}
			
	if (negative_proof) {
		if (partially_correct) { 
			/* mark all answers as bogus - 
			 * all answers are related in the proof 
			 */
			for (res=*results; res; res=res->next) 
				res->status = BOGUS_PROOF;
		}
		else 
			prove_nonexistence (top_q, *results);
	}

	return NO_ERROR;
}

