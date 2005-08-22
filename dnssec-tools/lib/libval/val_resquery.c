/*
 * Portions Copyright (c) 1995, 1996, 1997 by Trusted Information Systems, Inc.
 *
 * Permission to use, copy modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND TRUSTED INFORMATION SYSTEMS
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
 * TRUSTED INFORMATION SYSTEMS BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THE SOFTWARE.
 */
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

#include "val_errors.h"
#include "val_resquery.h"
#include "val_support.h"
#include "val_zone.h"
#include "val_cache.h"
#include "val_log.h"


#define ITS_BEEN_DONE   TRUE
#define IT_HASNT        FALSE

#define MERGE_RR(old_rr, new_rr) do{ \
	if (old_rr == NULL) \
		old_rr = new_rr;\
	else {\
		struct rrset_rec    *tail;\
		tail = old_rr;\
		while (tail->rrs_next != NULL)\
			tail = tail->rrs_next;\
		tail->rrs_next = new_rr;\
	}\
} while (0)

static int skip_questions(const u_int8_t *buf)
{
    return 12 + wire_name_length (&buf[12]) + 4;
}

int register_query (struct query_list **q, u_int8_t *name_n, u_int32_t type_h, u_int8_t *zone_n)
{
    if (*q==NULL)
    {
        *q = (struct query_list *)MALLOC(sizeof(struct query_list));
        if (*q==NULL)
        {
            /* Out of memory */
        }
        memcpy ((*q)->ql_name_n, name_n, wire_name_length(name_n));
        memcpy ((*q)->ql_zone_n, zone_n, wire_name_length(zone_n));
        (*q)->ql_type_h = type_h;
        (*q)->ql_next = NULL;
    }
    else
    {
        while ((*q)->ql_next != NULL)
        {
            if(namecmp((*q)->ql_zone_n,zone_n)==0&&namecmp((*q)->ql_name_n,zone_n)==0)
                return ITS_BEEN_DONE;
            (*q) = (*q)->ql_next;
        }
        if(namecmp((*q)->ql_zone_n,zone_n)==0&&namecmp((*q)->ql_name_n,zone_n)==0)
                return ITS_BEEN_DONE;
        (*q)->ql_next = (struct query_list *)MALLOC(sizeof(struct query_list));
        (*q) = (*q)->ql_next;
        if ((*q) == NULL)
        {
            /* Out of memory */
                                                                                                                          
    /* Check for NO MORE MEMORY */
                                                                                                                          
        }
        memcpy ((*q)->ql_name_n, name_n, wire_name_length(name_n));
        memcpy ((*q)->ql_zone_n, zone_n, wire_name_length(zone_n));
        (*q)->ql_type_h = type_h;
        (*q)->ql_next = NULL;
    }
    return IT_HASNT;
}
                                                                                                                          
void deregister_queries (struct query_list **q)
{
    struct query_list   *p;
                                                                                                                          
    if (*q==NULL) return;

	while(*q) {
		p = *q;
		*q = (*q)->ql_next;
		FREE(p);
	}
}



int do_referral(		val_context_t		*context,
						u_int8_t			*referral_zone_n, 
						struct query_chain  *matched_q,
                        struct rrset_rec    **answers,
                        struct rrset_rec    **learned_zones,
                        struct qname_chain  **qnames)
{
	struct name_server *ref_ns_list;
    int                 ret_val;
   
    /* Register the request name and zone with our referral monitor */
    /* If this request has already been made then Referral Error */

	if(matched_q->qc_referral == NULL) {
		matched_q->qc_referral = (struct delegation_info *) 
							MALLOC (sizeof(struct delegation_info));
		if (matched_q->qc_referral == NULL)
			return OUT_OF_MEMORY;
		matched_q->qc_referral->queries = NULL;
		matched_q->qc_referral->qnames = NULL;
		matched_q->qc_referral->answers = NULL;
		matched_q->qc_referral->learned_zones = NULL;
	}

    /* Update the qname chain */
	struct rrset_rec    *ref_rrset;

    ref_rrset = *answers;
   	while (ref_rrset)
    {
  	     if (ref_rrset->rrs_type_h == ns_t_cname
                   && namecmp(matched_q->qc_name_n,ref_rrset->rrs_name_n)==0)
         {
   	            if((ret_val=add_to_qname_chain(qnames,
       	                ref_rrset->rrs_data->rr_rdata)) != NO_ERROR)
           	        return ret_val;
         }
   	     ref_rrset = ref_rrset->rrs_next;
    }

	/* save qnames to the query_chain structure */
	if(matched_q->qc_referral->qnames==NULL)
		matched_q->qc_referral->qnames = *qnames;
	else if(*qnames) {
		struct qname_chain  *t_q;	
		for (t_q = *qnames; t_q->qnc_next; t_q=t_q->qnc_next);
		t_q->qnc_next = matched_q->qc_referral->qnames;
		matched_q->qc_referral->qnames = *qnames;
	}
                                                                       
   	 /* Tie new answer to old */
	MERGE_RR(matched_q->qc_referral->answers, *answers);
	/* Update the learned_zones list */
	MERGE_RR(matched_q->qc_referral->learned_zones, *learned_zones);

	if (register_query (&matched_q->qc_referral->queries, matched_q->qc_name_n, 
				matched_q->qc_type_h, referral_zone_n)==ITS_BEEN_DONE) 
		goto err;
		
   /* Get an NS list for the referral zone */
   if ((ret_val=res_zi_unverified_ns_list (context, &ref_ns_list, referral_zone_n, *learned_zones))
                != NO_ERROR)
   {
       if (ret_val == OUT_OF_MEMORY) return ret_val;
   }

   if (ref_ns_list == NULL)
		goto err;

{
char    debug_name1[1024];
char    debug_name2[1024];
memset (debug_name1,0,1024);
memset (debug_name2,0,1024);
ns_name_ntop(matched_q->qc_name_n,debug_name1,1024);
ns_name_ntop(referral_zone_n,debug_name2,1024);
val_log ("QUERYING: '%s.' (referral to %s)\n",
debug_name1, debug_name2);
}
	if(matched_q->qc_ns_list)
		free_name_servers(&matched_q->qc_ns_list);
	matched_q->qc_ns_list = ref_ns_list;

    return NO_ERROR;

err:
	deregister_queries(&matched_q->qc_referral->queries);
	free_qname_chain (&matched_q->qc_referral->qnames);
	res_sq_free_rrset_recs(&matched_q->qc_referral->answers);	
	res_sq_free_rrset_recs(&matched_q->qc_referral->learned_zones);	
	FREE(matched_q->qc_referral);
	matched_q->qc_referral = NULL;
	matched_q->qc_state =  REFERRAL_ERROR;
	return NO_ERROR;
}

#define SAVE_RR_TO_LIST(listtype, name_n, type_h, set_type_h,\
				class_h, ttl_h, rdata, from_section,authoritive) \
	do { \
            rr_set = find_rr_set (&listtype, name_n, type_h, set_type_h,\
                             class_h, ttl_h, rdata, from_section,authoritive);\
            if (rr_set==NULL) return OUT_OF_MEMORY;\
            rr_set->rrs_ans_kind = SR_ANS_STRAIGHT;\
            if (type_h != ns_t_rrsig)\
            {\
                /* Add this record to its chain of rr_rec's. */\
                if ((ret_val = add_to_set(rr_set,rdata_len_h,rdata))!=NO_ERROR) \
                    return ret_val;\
            }\
            else\
            {\
                /* Add this record to the sig of rrset_rec. */\
                if ((ret_val = add_as_sig(rr_set,rdata_len_h,rdata))!=NO_ERROR)\
                    return ret_val;\
            }\
	} while (0);


int digest_response (   val_context_t 		*context,
						struct query_chain *matched_q,
                        struct rrset_rec    **answers,
                        struct qname_chain  **qnames,
                        u_int8_t            *response,
                        u_int32_t           response_length)
{
    u_int16_t           question, answer, authority, additional;
    u_int16_t           rrs_to_go;
    HEADER              *header = (HEADER *) response;
    u_int8_t            *end =(u_int8_t*)((u_int32_t)response+response_length);
    int                 i;
    int                 response_index;
    u_int8_t            name_n[MAXDNAME];
    u_int16_t           type_h;
    u_int16_t           set_type_h;
    u_int16_t           class_h;
    u_int32_t           ttl_h;
    u_int16_t           rdata_len_h;
    int                 rdata_index;
    struct rrset_rec    *rr_set;
    int                 authoritive;
    u_int8_t            *rdata;
    int                 ret_val;
    int                 nothing_other_than_cname;
    int                 from_section;
    struct rrset_rec    *learned_zones = NULL;
    struct rrset_rec    *learned_keys = NULL;
    struct rrset_rec    *learned_ds = NULL;

	const u_int8_t      *query_name_n = matched_q->qc_name_n;
    u_int16_t           query_type_h = matched_q->qc_type_h;
    u_int16_t           query_class_h = matched_q->qc_class_h;
                                                                                                  
    *answers = NULL;
    *qnames = NULL;

    int referral_seen = FALSE;
    u_int8_t            referral_zone_n[MAXDNAME];
                                                                                                                          
    question = ntohs(header->qdcount);
    answer = ntohs(header->ancount);
    authority = ntohs(header->nscount);
    additional = ntohs(header->arcount);
                                                                                                                          
    response_index = skip_questions (response);
                                                                                                                          
    rrs_to_go = answer + authority + additional;
                                                                                                                          
    if (rrs_to_go == 0 /*&& header->rcode == ns_r_nxdomain*/)
    {
        /*
            We got an response with no records and the NXDOMAIN code
            in the RCODE section of the header.
                                                                                                                          
            Create a dummy answer record to handle this.  
        */
        return prepare_empty_nxdomain (answers, query_name_n, query_type_h,
                                            query_class_h);
    }
                                                                                                                          
    nothing_other_than_cname = query_type_h != ns_t_cname &&
                                    query_type_h != ns_t_any;

    /* Add the query name to the chain of acceptable names */
    if ((ret_val=add_to_qname_chain(qnames,query_name_n))!=NO_ERROR)
        return ret_val;
                                                                                                                          
    for (i = 0; i < rrs_to_go; i++)
    {
                                                                                                                          
        /* Determine what part of the response I'm reading */
                                                                                                                          
        if (i < answer) from_section = SR_FROM_ANSWER;
        else if (i < answer+authority) from_section = SR_FROM_AUTHORITY;
        else from_section = SR_FROM_ADDITIONAL;
                                                                                                                          
        /* Response_index points to the beginning of an RR */
        /* Grab the uncompressed name, type, class, ttl, rdata_len */
        /* If the type is a signature, get the type_covered */
        /* Leave a pointer to the rdata */
        /* Advance the response_index */
                                                                                                                          
        if ((ret_val = extract_from_rr (response, &response_index,end,name_n,&type_h,
            &set_type_h,&class_h,&ttl_h,&rdata_len_h,&rdata_index))!=NO_ERROR)
		        return ret_val; 
                                                                                                                          
        authoritive = (header->aa == 1) && qname_chain_first_name (*qnames,name_n);
                                                                                                                          
        /*
            response[rdata_index] is the first byte of the RDATA of the
            record.  The data may contain domain names in compressed format,
            so they need to be expanded.  This is type-dependent...
        */
        if ((ret_val = decompress(&rdata, response, rdata_index, end, type_h,
                            &rdata_len_h))!= NO_ERROR) {
		        return ret_val; 
        }
                                                                                                                          
        if (nothing_other_than_cname && (i < answer))
            nothing_other_than_cname = (set_type_h == ns_t_cname);
                                                                                                                          
        if ( from_section == SR_FROM_ANSWER
                || (from_section == SR_FROM_AUTHORITY
                        && nothing_other_than_cname && 
							set_type_h != ns_t_ns 
								&& set_type_h != ns_t_ds))
        {
            if (type_h == ns_t_cname &&
                    query_type_h != ns_t_cname &&
                    query_type_h != ns_t_any &&
                    namecmp((*qnames)->qnc_name_n,name_n)==0)
                if((ret_val=add_to_qname_chain(qnames,rdata))!=NO_ERROR)
                    return ret_val;
                                                                                                                          
            /* Find the rrset_rec for this record, create it if need be */
                                                                                                                          
            rr_set = find_rr_set (answers, name_n, type_h, set_type_h,
                                        class_h, ttl_h, rdata, from_section,authoritive);
            if (rr_set==NULL) return OUT_OF_MEMORY;

            if (type_h != ns_t_rrsig)
            {
                /* Add this record to its chain of rr_rec's. */
                if ((ret_val = add_to_set(rr_set,rdata_len_h,rdata))!=NO_ERROR)
                    return ret_val;
            }
            else
            {
                /* Add this record to the sig of rrset_rec. */
                if ((ret_val = add_as_sig(rr_set,rdata_len_h,rdata))!=NO_ERROR)
                    return ret_val;
            }
        }
        else if (from_section != SR_FROM_ADDITIONAL
                    && nothing_other_than_cname && set_type_h == ns_t_ns)
        {
            /* This is a referral */
            if (referral_seen==FALSE)
                memcpy (referral_zone_n, name_n, wire_name_length (name_n));
            else
                if (namecmp(referral_zone_n, name_n) != 0)
                {
                    /* Malformed referral notice */
					matched_q->qc_state =  REFERRAL_ERROR;
			        return NO_ERROR; 
                }
                                                                                                                          
            referral_seen = TRUE;
        }
	
		if (set_type_h==ns_t_dnskey)
		{
			SAVE_RR_TO_LIST(learned_keys, name_n, type_h, set_type_h,
                             class_h, ttl_h, rdata, from_section,authoritive); 
		}
		if (set_type_h==ns_t_ds)
		{
			SAVE_RR_TO_LIST(learned_ds, name_n, type_h, set_type_h,
                             class_h, ttl_h, rdata, from_section,authoritive); 
		}
        else if (set_type_h==ns_t_ns || /*set_type_h==ns_t_soa ||*/
                (set_type_h==ns_t_a && from_section == SR_FROM_ADDITIONAL))
        {
            /* This record belongs in the zone_info chain */
			SAVE_RR_TO_LIST(learned_zones, name_n, type_h, set_type_h,
                             class_h, ttl_h, rdata, from_section,authoritive); 
        }

        FREE (rdata);
    }

	if (referral_seen) {

		ret_val = do_referral(context, referral_zone_n, matched_q,
					answers, &learned_zones, qnames);
		/* all of these are consumed inside do_referral */
		*answers = NULL;
		*qnames = NULL;
		learned_zones = NULL;
		matched_q->qc_state = Q_INIT;

	}
	/* Check if this is the response to a referral request */
	else {
		if (matched_q->qc_referral != NULL) {
    		/* We can de-register all requests now. */
		    deregister_queries (&matched_q->qc_referral->queries);
		
			/* Merge answer and qnames */
			MERGE_RR((*answers), matched_q->qc_referral->answers);	
			if(*qnames==NULL)
				*qnames = matched_q->qc_referral->qnames;
			else if(matched_q->qc_referral->qnames) {
				struct qname_chain  *t_q;	
				for (t_q = *qnames; t_q->qnc_next; t_q=t_q->qnc_next);
				t_q->qnc_next = matched_q->qc_referral->qnames;
			}
			/* stow the learned zone information */
			stow_zone_info (matched_q->qc_referral->learned_zones);

			matched_q->qc_referral->queries = NULL;
			matched_q->qc_referral->answers = NULL;
			matched_q->qc_referral->qnames = NULL;
			matched_q->qc_referral->learned_zones = NULL;

			FREE(matched_q->qc_referral);
			matched_q->qc_referral = NULL;	
		}
		matched_q->qc_state = Q_ANSWERED;
		ret_val = NO_ERROR;
	}

	stow_zone_info (learned_zones);
	stow_key_info (learned_keys);
	stow_ds_info (learned_ds);

    return ret_val;
}


int val_resquery_send (	val_context_t           *context,
                        struct query_chain      *matched_q)
{
	char name[MAXDNAME];
	int ret_val;

    /* Get a (set of) answer(s) from the default NS's */

	/* If nslist is NULL, read the cached zones and name servers
	 * in context to create the nslist
	 */
	// XXX Identify which are relevant and create the ns_list
	struct name_server *nslist;
	if (matched_q->qc_ns_list == NULL) {
		// XXX look into the cache also
		if(context == NULL)
			return BAD_ARGUMENT;
		nslist = context->nslist;
	}
	else {
		nslist = matched_q->qc_ns_list;
	}

	if(ns_name_ntop(matched_q->qc_name_n, name, MAXDNAME-1) == -1) {
		matched_q->qc_state = Q_ERROR_BASE + SR_CALL_ERROR;
		return NO_ERROR;	
	}

	if ((ret_val = query_send(name, matched_q->qc_type_h, matched_q->qc_class_h, 
						nslist, &(matched_q->qc_trans_id))) == SR_UNSET)
			return NO_ERROR; 

	/* ret_val contains a resolver error */
	matched_q->qc_state = Q_ERROR_BASE + ret_val;
	return NO_ERROR;
}

int val_resquery_rcv ( 	
					val_context_t *context,
					struct query_chain *matched_q,
					struct domain_info **response)
{
    struct name_server  *server = NULL;
	u_int8_t			*response_data = NULL;
	u_int32_t			response_length;
	char name[MAXDNAME];

    struct rrset_rec    *answers = NULL;
    struct qname_chain  *qnames = NULL;

    int                 ret_val;

	*response = NULL;
    ret_val = response_recv(&(matched_q->qc_trans_id), &server, 
					&response_data, &response_length);
	if (ret_val == SR_NO_ANSWER_YET)
		return NO_ERROR;
	else if (ret_val != SR_UNSET)
		return ret_val;

    *response = (struct domain_info *) MALLOC (sizeof(struct domain_info));
    if (*response == NULL)
        return OUT_OF_MEMORY;
                            
    /* Initialize the response structure */
	(*response)->di_rrset = NULL;
	(*response)->di_qnames = NULL;
    (*response)->di_requested_type_h = matched_q->qc_type_h;
    (*response)->di_requested_class_h = matched_q->qc_class_h;

	if(ns_name_ntop(matched_q->qc_name_n, name, MAXDNAME-1) == -1) {
		matched_q->qc_state = Q_ERROR_BASE + SR_RCV_INTERNAL_ERROR;
		(*response)->di_res_error = matched_q->qc_state;  
		return NO_ERROR;	
	}
    if (((*response)->di_requested_name_h = STRDUP (name))==NULL)
        return OUT_OF_MEMORY;

	free_name_server(&server);

    if ((ret_val = digest_response (context, matched_q,
                    &answers, &qnames, response_data, 
					response_length)) != NO_ERROR)
    {
        FREE (response_data);
        return ret_val;
    }
	    
    if(matched_q->qc_state > Q_ERROR_BASE)
		(*response)->di_res_error = matched_q->qc_state; 

    /* What happens when an empty NXDOMAIN is returned? */
    /* What happens when an empty NOERROR is returned? */
    
    FREE (response_data);

	(*response)->di_rrset = answers;
	(*response)->di_qnames = qnames;
	
    return NO_ERROR;
}

