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
#include <netinet/in.h>

#include <resolv.h>

#include <resolver.h>
#include <validator.h>
#include "val_resquery.h"
#include "val_support.h"
#include "val_cache.h"
#include "val_assertion.h"

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

static int register_query (struct query_list **q, u_int8_t *name_n, u_int32_t type_h, u_int8_t *zone_n)
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
            if(namecmp((*q)->ql_zone_n,zone_n)==0&&namecmp((*q)->ql_name_n,name_n)==0)
                return ITS_BEEN_DONE;
            (*q) = (*q)->ql_next;
        }
        if(namecmp((*q)->ql_zone_n,zone_n)==0&&namecmp((*q)->ql_name_n,name_n)==0)
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
                                                                                                                          
static void deregister_queries (struct query_list **q)
{
    struct query_list   *p;
                                                                                                                          
    if (*q==NULL) return;

	while(*q) {
		p = *q;
		*q = (*q)->ql_next;
		FREE(p);
	}
}


static void *weird_al_realloc (void *old, size_t new_size)
{
    void    *new;
                                                                                                                          
    if (new_size>0)
    {
        new = MALLOC (new_size);
        if (new==NULL) return new;
        memset (new, 0, new_size);
        if (old) memcpy (new, old, new_size);
    }
    if (old) FREE (old);
                                                                                                                          
    return new;
}

int extract_glue_from_rdata(struct rr_rec *addr_rr, struct name_server **ns)
{
    struct sockaddr_in  *sock_in;
    size_t              new_ns_size;
    while (addr_rr)
    {
        if ((*ns)->ns_number_of_addresses > 0)
        {
            /* Have to grow the ns structure */
            /* Determine the new size */
            new_ns_size = sizeof (struct name_server)
                           + (*ns)->ns_number_of_addresses
                               * sizeof (struct sockaddr);
                                                                                                                          
            /*
             * Realloc the ns's structure to be able to
             * add a struct sockaddr
             */
            (*ns) = (struct name_server *) weird_al_realloc(*ns, new_ns_size);
                                                                                                                          
            if (*ns==NULL) return OUT_OF_MEMORY;
		}    
                                                                                                                      
        sock_in = (struct sockaddr_in *)
                            &(*ns)->ns_address[(*ns)->ns_number_of_addresses];
                                                                                                                          
        sock_in->sin_family = AF_INET;
        sock_in->sin_port = htons (DNS_PORT);
        memset (sock_in->sin_zero,0,sizeof(sock_in->sin_zero));
        memcpy (&(sock_in->sin_addr), addr_rr->rr_rdata, sizeof(u_int32_t));
                                                                                                                          
        (*ns)->ns_number_of_addresses++;
        addr_rr = addr_rr->rr_next;

	}
	return NO_ERROR;
}

void  merge_glue_in_referral(struct val_query_chain *pc, struct val_query_chain **queries)
{
	int retval;
	struct val_query_chain *glueptr = pc->qc_referral->glueptr;
	struct name_server *pending_ns;

	/* Check if glue was obtained */
	if((glueptr->qc_state == Q_ANSWERED) && 
		(glueptr->qc_as != NULL) && 
		(glueptr->qc_as->_as->ac_data != NULL)) {

		if(glueptr->qc_as->_as->ac_data->rrs_type_h != ns_t_a) {
			pc->qc_state = Q_ERROR_BASE + SR_REFERRAL_ERROR;
		}
		else if(NO_ERROR != (retval = extract_glue_from_rdata(glueptr->qc_as->_as->ac_data->rrs_data,
					&pc->qc_referral->pending_glue_ns))) {
			glueptr->qc_state = Q_ERROR_BASE+SR_RCV_INTERNAL_ERROR;
		}
		else {
	    	if(pc->qc_ns_list) {
		        free_name_servers(&pc->qc_ns_list);
				pc->qc_ns_list = NULL;
			}
		    if (pc->qc_respondent_server) {
		        free_name_server(&pc->qc_respondent_server);
		        pc->qc_respondent_server = NULL;
   	 		}
			pending_ns = pc->qc_referral->pending_glue_ns;
			if(pending_ns->ns_next)
				free_name_servers(&pending_ns->ns_next);
			pending_ns->ns_next = NULL;
	    	pc->qc_ns_list = pending_ns;
			pc->qc_referral->pending_glue_ns = NULL;
   			pc->qc_state =  Q_INIT;
			pc->qc_referral->glueptr = NULL;
		}
	}

	if (glueptr->qc_state > Q_ERROR_BASE) {

		/* look for next ns to send our glue request to */
		pending_ns = pc->qc_referral->pending_glue_ns->ns_next;
		free_name_server(&pc->qc_referral->pending_glue_ns);
		pc->qc_referral->pending_glue_ns = pending_ns;

		if(pending_ns == NULL) {
			pc->qc_state = Q_ERROR_BASE + SR_MISSING_GLUE;
		}
		else {
			add_to_query_chain(queries, pending_ns->ns_name_n, ns_t_a, ns_c_in);
			pc->qc_referral->glueptr = *queries; 
			pc->qc_referral->glueptr->qc_glue_request = 1;
		}
	}
}

int res_zi_unverified_ns_list(struct name_server **ns_list,
			u_int8_t *zone_name, struct rrset_rec *unchecked_zone_info, 
			struct name_server **pending_glue)
{
    /* Look through the unchecked_zone stuff for answers */
    struct rrset_rec    *unchecked_set;
    struct rrset_rec    *trailer;
    struct rr_rec       *ns_rr;
    struct name_server  *temp_ns;
    struct name_server  *ns;
    struct name_server  *trail_ns;
    struct name_server  *outer_trailer;
    struct name_server  *tail_ns;
    size_t              name_len;
	int retval;        
                                                                                                                  
    *ns_list = NULL;
                                                                                                                          
    unchecked_set = unchecked_zone_info;
    while (unchecked_set != NULL)
    {
        if (unchecked_set->rrs_type_h == ns_t_ns &&
                (namecmp(zone_name, unchecked_set->rrs_name_n) == 0))
        {
            if (*ns_list != NULL)
            {
                /* We've hit a duplicate, remove it from the list */
                /*
                    Now that I'm thinking about it, I may remove duplicates
                    during the stowage of the zone information.
                    If so, this code may never get executed.
                */
                trailer->rrs_next = unchecked_set->rrs_next;
                unchecked_set->rrs_next = NULL;
                res_sq_free_rrset_recs (&unchecked_set);
                unchecked_set = trailer;
            }
            else
            {
                ns_rr = unchecked_set->rrs_data;
                while (ns_rr)
                {
                    /* Create the structure for the name server */
                    temp_ns = (struct name_server *)
                                    MALLOC(sizeof(struct name_server));
                    if (temp_ns == NULL)
                    {
                        /* Since we're in trouble, free up just in case */
                        free_name_servers (ns_list);
                        return OUT_OF_MEMORY;
                    }
                                                                                                                          
                    /* Make room for the name and insert the name */
                    name_len = wire_name_length (ns_rr->rr_rdata);
                    temp_ns->ns_name_n = (u_int8_t *)MALLOC(name_len);
                    if (temp_ns->ns_name_n==NULL)
                    {
                        free_name_servers (ns_list);
                        return OUT_OF_MEMORY;
                    }
                    memcpy (temp_ns->ns_name_n, ns_rr->rr_rdata, name_len);
                                                                                                                          
                    /* Initialize the rest of the fields */
                    temp_ns->ns_tsig_key = NULL;
                    temp_ns->ns_security_options = ZONE_USE_NOTHING;
                    temp_ns->ns_status = SR_ZI_STATUS_LEARNED;

					temp_ns->ns_retrans = RES_TIMEOUT;
					temp_ns->ns_retry = RES_RETRY;
					temp_ns->ns_options = RES_DEFAULT; 

                    temp_ns->ns_next = NULL;
                    temp_ns->ns_number_of_addresses = 0;
                    /* Add the name server record to the list */
                    if (*ns_list == NULL)
                        *ns_list = temp_ns;
                    else
                    {
                        /* Preserving order in case of round robin */
                        tail_ns = *ns_list;
                        while (tail_ns->ns_next != NULL)
                            tail_ns = tail_ns->ns_next;
                        tail_ns->ns_next = temp_ns;
                    }
                ns_rr = ns_rr->rr_next;
                }
            }
        }
        trailer = unchecked_set;
        unchecked_set = unchecked_set->rrs_next;
    }
                                                                                                                          
    /* Now, we need the addresses */
    /*
        This is ugly - loop through unchecked data for address records,
        then through the name server records to find a match,
        then through the (possibly multiple) addresses under the A set
                                                                                                                          
        There is no suppport for an IPv6 NS address yet.
    */
                                                                                                                          
    unchecked_set = unchecked_zone_info;
    while (unchecked_set != NULL)
    {
        if (unchecked_set->rrs_type_h == ns_t_a)
        {
            /* If the owner name matches the name in an *ns_list entry...*/
            trail_ns = NULL;
            ns = *ns_list;
            while (ns)
            {
                if (namecmp(unchecked_set->rrs_name_n,ns->ns_name_n)==0)
                {
					struct name_server *old_ns = ns;
                    /* Found that address set is for an NS */
					if(NO_ERROR != (retval = extract_glue_from_rdata(unchecked_set->rrs_data, &ns)))
						return retval;
					if(old_ns != ns) {
						/* ns was realloc'd */
						if (trail_ns)
    	                    trail_ns->ns_next = ns;
        	            else
            	            *ns_list = ns;
					}
                    ns = NULL; /* Force dropping out from the loop */
                }
                else
                {
                    trail_ns = ns;
                    ns = ns->ns_next;
                }
            }
		}
		unchecked_set = unchecked_set->rrs_next;
	}

    ns = *ns_list;
    outer_trailer = NULL;
	*pending_glue = NULL;
    while (ns)
    {
        if (ns->ns_number_of_addresses==0)
        {
            if (outer_trailer)
            {
                outer_trailer->ns_next = ns->ns_next;
				ns->ns_next = *pending_glue;
				*pending_glue = ns;
                ns = outer_trailer->ns_next;
            }
            else
            {
                *ns_list = ns->ns_next;
				ns->ns_next = *pending_glue;
				*pending_glue = ns;
                ns = *ns_list;
            }
        }
        else /* There is at least one address */
        {
            outer_trailer = ns;
            ns = ns->ns_next;
        }
	}


	return NO_ERROR;
}

void free_referral_members(struct delegation_info *del)
{
	if(del == NULL)
		return;

	if(del->queries != NULL) {
		deregister_queries(&del->queries);
		del->queries = NULL;
	}
	if (del->qnames) {
		free_qname_chain (&del->qnames);
		del->qnames = NULL;
	}
	if(del->answers) {
		res_sq_free_rrset_recs(&del->answers);	
		del->answers = NULL;
	}
	if(del->learned_zones) {
		res_sq_free_rrset_recs(&del->learned_zones);	
		del->learned_zones = NULL;
	}
	if(del->pending_glue_ns) {
		free_name_servers(&del->pending_glue_ns);
		del->pending_glue_ns = NULL;
	}

	del->glueptr = NULL;
}

static int do_referral(		val_context_t		*context,
						u_int8_t			*referral_zone_n, 
						struct val_query_chain  *matched_q,
                        struct rrset_rec    **answers,
                        struct rrset_rec    **learned_zones,
                        struct qname_chain  **qnames,
						struct val_query_chain **queries)
{
	struct name_server *ref_ns_list = NULL;
	struct name_server *pending_glue;
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
		matched_q->qc_referral->pending_glue_ns = NULL;
		matched_q->qc_referral->glueptr = NULL;
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
       	                ref_rrset->rrs_data->rr_rdata)) != NO_ERROR) {
					free_qname_chain (qnames);
           	        return ret_val;
				}
         }
   	     ref_rrset = ref_rrset->rrs_next;
    }

	/* save qnames to the val_query_chain structure */
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
				matched_q->qc_type_h, referral_zone_n)==ITS_BEEN_DONE) {
		matched_q->qc_state =  Q_ERROR_BASE + SR_REFERRAL_ERROR;
	}
   	else {

		if ((ret_val=res_zi_unverified_ns_list (&ref_ns_list, referral_zone_n, *learned_zones, &pending_glue))
                != NO_ERROR) {
   			/* Get an NS list for the referral zone */
	       if (ret_val == OUT_OF_MEMORY) return ret_val;
	    }

		if(ref_ns_list == NULL) {

			/* Don't fetch glue if we're already fetching glue */
			if (matched_q->qc_glue_request) {
				free_name_servers(&pending_glue);
				matched_q->qc_state =  Q_ERROR_BASE + SR_REFERRAL_ERROR;
			}
			/* didn't find any referral with glue, look for one now */
			else if(pending_glue) {
	
				/* Create a query for glue for pending_ns */
				matched_q->qc_referral->pending_glue_ns = pending_glue;
				add_to_query_chain(queries, pending_glue->ns_name_n, ns_t_a, ns_c_in);		
				matched_q->qc_referral->glueptr = *queries;
				matched_q->qc_referral->glueptr->qc_glue_request = 1;
				matched_q->qc_state = Q_WAIT_FOR_GLUE;
				return NO_ERROR;
			}
			else {
				/* nowhere to look */
				matched_q->qc_state = Q_ERROR_BASE + SR_MISSING_GLUE; 
			}
		}
		else {
			free_name_servers(&pending_glue);
			matched_q->qc_state =  Q_INIT;
		}
	}

{
char    debug_name1[1024];
char    debug_name2[1024];
memset (debug_name1,0,1024);
memset (debug_name2,0,1024);
ns_name_ntop(matched_q->qc_name_n,debug_name1,1024);
ns_name_ntop(referral_zone_n,debug_name2,1024);
val_log (context, LOG_DEBUG, "QUERYING: '%s.' (referral to %s)\n",
debug_name1, debug_name2);
}

	if (matched_q->qc_respondent_server) {
		free_name_server(&matched_q->qc_respondent_server);
		matched_q->qc_respondent_server = NULL;
	}
	if(matched_q->qc_ns_list) {
		free_name_servers(&matched_q->qc_ns_list);
		matched_q->qc_ns_list = NULL;
	}

	if(matched_q->qc_state > Q_ERROR_BASE) {
		free_referral_members(matched_q->qc_referral);	
		/* don't free qc_referral itself */
	}

	matched_q->qc_ns_list = ref_ns_list;

	return NO_ERROR;
}



static int digest_response (   val_context_t 		*context,
						struct val_query_chain *matched_q,
						struct name_server *respondent_server,
                        struct rrset_rec    **answers,
                        struct qname_chain  **qnames,
						struct val_query_chain **queries,
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
                                            query_class_h) ;
    }
                                                                                                                          
    nothing_other_than_cname = query_type_h != ns_t_cname &&
                                    query_type_h != ns_t_any;

    /* Add the query name to the chain of acceptable names */
    if ((ret_val=add_to_qname_chain(qnames,query_name_n))!=NO_ERROR)
        return ret_val;
                                                                                                                          
    for (i = 0; i < rrs_to_go; i++)
    {
                                                                                                                          
        /* Determine what part of the response I'm reading */
                                                                                                                          
        if (i < answer) from_section = VAL_FROM_ANSWER;
        else if (i < answer+authority) from_section = VAL_FROM_AUTHORITY;
        else from_section = VAL_FROM_ADDITIONAL;
                                                                                                                          
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
                                                                                                                          
        if ( from_section == VAL_FROM_ANSWER
                || (from_section == VAL_FROM_AUTHORITY
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
                                                                                                                          
            rr_set = find_rr_set (respondent_server, answers, name_n, type_h, set_type_h,
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
        else if (from_section != VAL_FROM_ADDITIONAL && 
					set_type_h == ns_t_ns &&
						(nothing_other_than_cname || answer == 0))
        {
            /* This is a referral */
            if (referral_seen==FALSE)
                memcpy (referral_zone_n, name_n, wire_name_length (name_n));
            else
                if (namecmp(referral_zone_n, name_n) != 0)
                {
                    /* Malformed referral notice */
					matched_q->qc_state =  Q_ERROR_BASE + SR_REFERRAL_ERROR;
			        return NO_ERROR; 
                }
                                                                                                                          
            referral_seen = TRUE;
        }
	
		if (set_type_h==ns_t_dnskey)
		{
			SAVE_RR_TO_LIST(respondent_server, learned_keys, name_n, type_h, set_type_h,
                             class_h, ttl_h, rdata, rdata_len_h, from_section, authoritive); 
		}
		if (set_type_h==ns_t_ds)
		{
			SAVE_RR_TO_LIST(respondent_server, learned_ds, name_n, type_h, set_type_h,
                             class_h, ttl_h, rdata, rdata_len_h, from_section, authoritive); 
		}
        else if (set_type_h==ns_t_ns || /*set_type_h==ns_t_soa ||*/
                (set_type_h==ns_t_a && from_section == VAL_FROM_ADDITIONAL))
        {
            /* This record belongs in the zone_info chain */
			SAVE_RR_TO_LIST(respondent_server, learned_zones, name_n, type_h, set_type_h,
                             class_h, ttl_h, rdata, rdata_len_h, from_section, authoritive); 
        }

        FREE (rdata);
    }

	if (referral_seen) {
		ret_val = do_referral(context, referral_zone_n, matched_q,
					answers, &learned_zones, qnames, queries);
		/* all of these are consumed inside do_referral */
		*answers = NULL;
		*qnames = NULL;
		learned_zones = NULL;
	}
	/* Check if this is the response to a referral request */
	else {
		if (matched_q->qc_referral != NULL) {

			if(matched_q->qc_ns_list != NULL) {
				free_name_servers(&matched_q->qc_ns_list);
				matched_q->qc_ns_list = NULL;
			}

			/* Consume answer, qnames and learned_zones */
			MERGE_RR((*answers), matched_q->qc_referral->answers);	
			matched_q->qc_referral->answers = NULL;
			if(*qnames==NULL)
				*qnames = matched_q->qc_referral->qnames;
			else if(matched_q->qc_referral->qnames) {
				struct qname_chain  *t_q;	
				for (t_q = *qnames; t_q->qnc_next; t_q=t_q->qnc_next);
				t_q->qnc_next = matched_q->qc_referral->qnames;
			}
			matched_q->qc_referral->qnames = NULL;
			/* stow the learned zone information */
			if(NO_ERROR != (ret_val = stow_zone_info (matched_q->qc_referral->learned_zones))){
				res_sq_free_rrset_recs(&matched_q->qc_referral->learned_zones);
				matched_q->qc_referral->learned_zones = NULL;
				return ret_val;
			}
			matched_q->qc_referral->learned_zones = NULL;

			/* Note that we don't free qc_referral here */
			free_referral_members(matched_q->qc_referral);
		}
		matched_q->qc_state = Q_ANSWERED;
		ret_val = NO_ERROR;
	}

	if( NO_ERROR != (ret_val = stow_zone_info (learned_zones))) {
		res_sq_free_rrset_recs(&learned_zones);
		return ret_val;
	}

	if (NO_ERROR != (ret_val = stow_key_info (learned_keys))) {
		res_sq_free_rrset_recs(&learned_keys);
		return ret_val;
	}

	if (NO_ERROR != (ret_val = stow_ds_info (learned_ds))) {
		res_sq_free_rrset_recs(&learned_ds);
		return ret_val;
	}

    return ret_val;
}

int val_resquery_send (	val_context_t           *context,
                        struct val_query_chain      *matched_q)
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
					struct val_query_chain *matched_q,
					struct domain_info **response,
					struct val_query_chain **queries)
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

	matched_q->qc_respondent_server = server;
	server = NULL;

	if (ret_val != SR_UNSET) { 
		matched_q->qc_state = Q_ERROR_BASE + ret_val;
		return NO_ERROR;
	}

	if(ns_name_ntop(matched_q->qc_name_n, name, MAXDNAME-1) == -1) {
		matched_q->qc_state = Q_ERROR_BASE + SR_RCV_INTERNAL_ERROR;
		return NO_ERROR;	
	}

    *response = (struct domain_info *) MALLOC (sizeof(struct domain_info));
    if (*response == NULL)
        return OUT_OF_MEMORY;
                            
    /* Initialize the response structure */
	(*response)->di_rrset = NULL;
	(*response)->di_qnames = NULL;
    (*response)->di_requested_type_h = matched_q->qc_type_h;
    (*response)->di_requested_class_h = matched_q->qc_class_h;

    if (((*response)->di_requested_name_h = STRDUP (name))==NULL)
        return OUT_OF_MEMORY;

    if ((ret_val = digest_response (context, matched_q, 
					matched_q->qc_respondent_server,
                    &answers, &qnames, queries, response_data, 
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

