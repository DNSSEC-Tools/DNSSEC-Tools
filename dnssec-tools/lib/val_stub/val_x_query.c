
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
#include "val_x_query.h"
#include "val_verify.h"
#include "val_context.h"
#include "validator.h"
#include "val_log.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif


#define DONE	0
#define NOT_DONE	1

#define ISSET(field,bit)        (field[bit/8]&(1<<(7-(bit%8))))

/////////////////////////////////////////////////////////////////

u_int16_t is_trusted_key(val_context_t *ctx, struct rr_rec *key)
{
//	return EXACT;
	return NOT_YET;
}

/////////////////////////////////////////////////////////////////

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

int ask_resolver(val_context_t *context, struct query_chain **queries, int wait, struct assertion_chain **assertions)
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
                      struct rrset_rec    *the_set)
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
                      struct rrset_rec    *the_set)
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
            return TRUE;
        }
                                                                                                                          
    return FALSE;
}

int NSEC_is_wrong_answer (
                      u_int8_t    *qc_name_n,
                      const u_int16_t     q_type_h,
                      const u_int16_t     q_class_h,
                      struct rrset_rec    *the_set)
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
            return TRUE;
        }
        else
            return FALSE;
    }
    else
    {
        /*  query name is between NXT owner and next name or
            query name is after NXT owner and next name is the zone */
    

		/* SOA flag should not be set */
        if (ISSET((&(the_set->rrs_data->rr_rdata[nsec_bit_field])), ns_t_soa))
        {
            the_set->rrs_status = SR_WRONG;
            return TRUE;
        }
                                                                                                                      
        if (namecmp(the_set->rrs_name_n, qc_name_n) > 0)
        {
            the_set->rrs_status = SR_WRONG;
            return TRUE;
        }
        
		/* XXX If the next name is lesser than qc_name_n then this is not relevant */



		/* or next name could be the soa; this should be present 
		   in the authority section also. we'll make those sanity 
		   checks later */

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
	u_int8_t *signby_name_n;
	int retval;
	struct assertion_chain *as = NULL;
	u_int16_t type_h = response->di_requested_type_h;
    u_int16_t class_h = response->di_requested_class_h;	
	u_char name_n[MAXCDNAME];

	if (matched_q == NULL)
		return NO_ERROR;

	if (ns_name_pton(response->di_requested_name_h, name_n, MAXCDNAME-1) == -1)
		return (SR_CALL_ERROR);                                                                                                                         
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
		if((	set_ans_kind(name_n, type_h, class_h, as->ac_data) == SR_PROCESS_ERROR)
			|| fails_to_answer_query(response->di_qnames, type_h, class_h, as->ac_data)
			|| NSEC_is_wrong_answer (name_n, type_h, class_h, as->ac_data)) {

			as->ac_state = A_NONSENSE_ANSWER;
			continue;
		}

		if(as->ac_data->rrs_data == NULL) {
			as->ac_state = A_NO_DATA;
			continue;
		}

		if(type_h == ns_t_rrsig) { 
			as->ac_state = A_BARE_RRSIG;
			continue;
		}

		if(as->ac_data->rrs_sig == NULL) {
			as->ac_state = A_WAIT_FOR_RRSIG;
			/* create a query and link it as the pending query for this assertion */
			if(NO_ERROR != (retval = add_to_query_chain(queries, 
							as->ac_data->rrs_name_n, ns_t_rrsig, as->ac_data->rrs_class_h)))
				return retval;
			as->ac_pending_query = *queries;/* The first value in the list is the most recent element */
			continue;
		}
	

		/* 
		 * Identify the DNSKEY that created the RRSIG:
		 */

		/* First identify the signer name from the RRSIG */
	    signby_name_n = &as->ac_data->rrs_sig->rr_rdata[SIGNBY];

		/* Then check if {signby_name_n, DNSKEY/DS, type} is already in the cache */

		if(type_h == ns_t_dnskey) {
			u_int16_t tkeystatus = is_trusted_key(context, as->ac_data->rrs_data);
			switch (tkeystatus) {
				case EXACT: 	
					as->ac_state = A_TRUSTED; 
					continue;

				case NO_MORE: 	
					as->ac_state = A_NO_TRUST_ANCHOR; 
					continue;

				default:
					as->ac_state = A_WAIT_FOR_TRUST;
					break;
			}

			/* State has to be A_WAIT_FOR_TRUST here */

			/* Create a query for missing data */
			if(NO_ERROR != (retval = add_to_query_chain(queries, signby_name_n, 
						ns_t_ds, class_h)))
				return retval;

		}
		else { 
			/* look for DNSKEY records */
			if(NO_ERROR != (retval = add_to_query_chain(queries, signby_name_n, 
							ns_t_dnskey, class_h)))
				return retval;

		}

		as->ac_pending_query = *queries; /* The first value in the list is the most recent element */
		as->ac_state = A_WAIT_FOR_TRUST;
	}

	return NO_ERROR;
}

/*
 * Verify all complete assertions. Complete assertions are those for which 
 * you have data, rrsigs and key information. Use flags to control when we
 * are allowed to return.
 * Returns:
 * NO_ERROR			Operation completed successfully
 * Other return values from add_to_query_chain()
 */
int verify_assertions(val_context_t *context, struct query_chain **queries, 
				struct assertion_chain *assertions)
{
	int retval;
	struct assertion_chain *next_as;
	u_int16_t type_h, class_h;
	u_int8_t *signby_name_n;
	struct rrset_rec *pending_rrset; 

	for(next_as = assertions; next_as; next_as = next_as->ac_next){
		/* Check if pending queries have been answered */
		if (next_as->ac_pending_query != NULL) {

			if(next_as->ac_pending_query->qc_state == Q_ERROR) {
				next_as->ac_state = A_INCOMPLETE;
				continue;
			}

			if(next_as->ac_pending_query->qc_as != NULL) {
				if(next_as->ac_state == A_WAIT_FOR_RRSIG) {
					/* We were waiting for the RRSIG */
					pending_rrset = next_as->ac_pending_query->qc_as->ac_data;
				
					/* 
					 * Check if what we got was an RRSIG and if 
					 */
					if (pending_rrset->rrs_type_h != ns_t_rrsig) {
						/* Could not find any RRSIG */
						next_as->ac_state = A_NO_RRSIG; 
						continue;
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
						next_as->ac_state = A_NO_RRSIG; 
						continue;
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
					next_as->ac_trust = next_as->ac_pending_query->qc_as;
					next_as->ac_pending_query = NULL;
					next_as->ac_state = A_CAN_VERIFY;
				}
			}
		}

		if(next_as->ac_state == A_CAN_VERIFY) {
			verify_next_assertion(next_as);
		}


	}

	return NO_ERROR;
}



void validate_assertions(struct assertion_chain *top_as, u_int16_t flags, int *status)
{
	struct assertion_chain *next_as;
	int incomplete_seen = 0;

	*status = NOT_DONE;

	/* XXX Apply flags here and return if possible */
	/* Only the top query is relevant */
	if(top_as == NULL) {
		/* XXX Assertion status is query status */
		return; 
	}

	next_as = top_as;
	for (next_as=top_as; next_as; next_as=next_as->ac_trust) {
		/* Go up the chain of trust */
		/* XXX Check what the final result is */

		if(next_as->ac_data->rrs_type_h == ns_t_dnskey) {
			/*  DS or proof of non-existence followed by another DNSKEY */
			if ((next_as->ac_trust) && (next_as == next_as->ac_trust->ac_next))
				break;
		}

		//XXX This will change when flags is implemented

		if(next_as->ac_state < A_VERIFY_FAILED) 
			incomplete_seen = 1;
	}

	/* XXX Perform sanity checks here */

	if(!incomplete_seen)
		*status = DONE;
}


/*
 * Internal routine called by val_query. Look at val_query for details.
 */
int _val_x_query(	val_context_t	*context,
			const char *domain_name,
			const u_int16_t type,
			const u_int16_t class,
			const u_int16_t flags, 
			struct query_chain **queries,
			struct assertion_chain **assertions)
{

	char wait = 1;
	int retval;
	int status;
	struct query_chain *top_q;

	top_q = *queries;

	status = NOT_DONE;
	while(status != DONE) {

		struct query_chain *last_q;

		/* watch the last entry added to the query chain */
		last_q = *queries;

		/* Data might already be present in the cache */
		/* XXX We can by-pass this functionality through flags */
		if(NO_ERROR != (retval = ask_cache(context, NULL, queries, assertions)))
			return retval;

		/* Send un-sent queries */
		if(NO_ERROR != (retval = ask_resolver(context, queries, wait, assertions)))
			return retval;

		/* check if more queries have been added */
		if(last_q != *queries) {
			/* There are new queries to send out */
			wait = 0;
			continue;
		}

		/* Henceforth we will need some data before we can continue */
		wait = 1;

		/* 
		 * We have sufficient data to at least perform some validation --
		 * validate what ever is possible. 
		 * This includes verifying the proofs, CNAME sanity, 
		 * signature verification etc. 
		 */
		// XXX Optimize later to make this verify_and_validate()
		if(NO_ERROR != (retval = verify_assertions(context, queries, *assertions))) 
			return retval;
		validate_assertions(top_q->qc_as, flags, &status);
	}

	/* Results are available */

	/* XXX De-register pending queries */


	return NO_ERROR;
}

/*
 * This routine makes a query for {domain_name, type, class} and returns the 
 * result in response_t. Memory for the response bytes within 
 * response_t must be sufficient to hold all the answers returned. If not, those 
 * answers are omitted from the result and MORE_ANSWERS is returned. The result of
 * validation for a particular resource record is available in validation_result. 
 * The response_t array passed to val_query, resp, must be large enough to 
 * hold all answers. The size allocated by the user must be passed in the 
 * resp_count parameter. If space is insufficient to hold all answers, those 
 * answers are omitted and MORE_ANSWERS is returned. 
 * 
 * The flags parameter allows val_query to be called with 
 * different preferences as listed below:
 * ALL_ANSWERS			Returns validated as well as non-validated responses
 * VALIDATED_ONLY		Returns only the validated responses
 * NON_VALIDATED_ONLY	Returns only the non-validated responses
 * FIRST_VALIDATED		Returns the first validated response satisfying the 
 *						lookup criteria
 * FIRST_UNVALIDATED	Returns the first unvalidated response
 * TRY_TCP_ON_DOS		Try connecting to the server using TCP when a DOS 
 *						on the resolver is detected 
 *
 * Return values:
 * NO_ERROR			Operation succeeded
 * SR_CALL_ERROR	The domain name is invalid
 * OUT_OF_MEMORY	Could not allocate enough memory for operation
 * MORE_ANSWERS		Returned when the user allocated memory is not large enough 
 *					to hold all the answers.
 *
 */
int val_x_query(val_context_t	*ctx,
			const char *domain_name,
			const u_int16_t type,
			const u_int16_t class,
			const u_int16_t flags, 
			struct response_t *resp,
			int resp_count)
{
	struct query_chain *queries = NULL;	
	struct assertion_chain *assertions = NULL;
	int retval;
	val_context_t *context;
	struct query_chain *top_q;
	u_char name_n[MAXCDNAME];

	if(ctx == NULL)
		context = get_default_context();
	else	
		context = ctx;

	if (ns_name_pton(domain_name, name_n, MAXCDNAME-1) == -1)
		return (SR_CALL_ERROR);                                                                                                                         
	/* Add the main query to the qname_chain list */
	if(NO_ERROR != (retval = add_to_query_chain(&queries, name_n, type, class)))
		return retval;

	top_q = queries;
	if(NO_ERROR != (retval = _val_x_query(context, domain_name, type, class, flags, &queries, &assertions))) {
		/* Form the error response: DOS, gave up, etc */

		free_query_chain(&queries);
		free_assertion_chain(&assertions);

		return retval;
	}

	/* XXX Construct the answer response in response_t */







	free_query_chain(&queries);
	free_assertion_chain(&assertions);

	if(ctx == NULL)	
		destroy_context(context);

	return NO_ERROR;
}

