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

#include "val_resquery.h"
#include "val_support.h"
#include "val_zone.h"
#include "val_cache.h"
#include "val_log.h"

#define NO_DOMAIN_NAME  "val_resquery: domain_name omitted from query request"


#define ITS_BEEN_DONE   TRUE
#define IT_HASNT        FALSE

struct query_list
{
    u_int8_t            ql_name_n[MAXDNAME];
    u_int8_t            ql_zone_n[MAXDNAME];
    u_int16_t           ql_type_h;
    struct query_list   *ql_next;
};

static struct query_list    *queries = NULL;
                                                                                                                          
static int res_sq_set_message(char **error_msg, char *msg, int error_code)
{
    *error_msg = (char *) MALLOC (strlen(msg)+1);
    if (*error_msg==NULL) return SR_MEMORY_ERROR;
    sprintf (*error_msg, "%s", msg);
    return error_code;
}

static int skip_questions(const u_int8_t *buf)
{
    return 12 + wire_name_length (&buf[12]) + 4;
}

int register_query (u_int8_t *name_n, u_int32_t type_h, u_int8_t *zone_n)
{
    struct query_list   *q = queries;
                                                                                                                          
    if (q==NULL)
    {
        queries = (struct query_list *)MALLOC(sizeof(struct query_list));
        if (queries==NULL)
        {
            /* Out of memory */
        }
        memcpy (queries->ql_name_n, name_n, wire_name_length(name_n));
        memcpy (queries->ql_zone_n, zone_n, wire_name_length(zone_n));
        queries->ql_type_h = type_h;
        queries->ql_next = NULL;
    }
    else
    {
        while (q->ql_next != NULL)
        {
            if(namecmp(q->ql_zone_n,zone_n)==0&&namecmp(q->ql_name_n,zone_n)==0)
                return ITS_BEEN_DONE;
            q = q->ql_next;
        }
        if(namecmp(q->ql_zone_n,zone_n)==0&&namecmp(q->ql_name_n,zone_n)==0)
                return ITS_BEEN_DONE;
        q->ql_next = (struct query_list *)MALLOC(sizeof(struct query_list));
        q = q->ql_next;
        if (q == NULL)
        {
            /* Out of memory */
                                                                                                                          
    /* Check for NO MORE MEMORY */
                                                                                                                          
        }
        memcpy (q->ql_name_n, name_n, wire_name_length(name_n));
        memcpy (q->ql_zone_n, zone_n, wire_name_length(zone_n));
        q->ql_type_h = type_h;
        q->ql_next = NULL;
    }
    return IT_HASNT;
}
                                                                                                                          
void deregister_query (u_int8_t *name_n, u_int32_t type_h, u_int8_t *zone_n)
{
    struct query_list   *q = queries;
    struct query_list   *p;
                                                                                                                          
    if (q==NULL) return;
                                                                                                                          
    if(namecmp(q->ql_zone_n,zone_n)==0 && namecmp(q->ql_zone_n,zone_n)==0
        && q->ql_type_h == type_h)
    {
        queries = q->ql_next;
        FREE (q);
        return;
    }
                                                                                                                          
    while (q->ql_next &&
                (
                    namecmp (q->ql_next->ql_zone_n, zone_n) != 0 ||
                    namecmp (q->ql_next->ql_name_n, name_n) != 0 ||
                    q->ql_type_h != type_h
                )
        )
        q = q->ql_next;
                                                                                                                          
    if ((p = q->ql_next) == NULL) return;
                                                                                                                          
    q->ql_next = q->ql_next->ql_next;
                                                                                                                          
    FREE (p);
}


int do_referral(		val_context_t		*context,
						u_int8_t			*referral_zone_n, 
						u_int16_t           query_type_h,
                        u_int16_t           query_class_h,
                        struct rrset_rec    **answers,
                        struct rrset_rec    **learned_zones,
                        struct qname_chain  **qnames,
						char                **error_msg)
{
	struct name_server *ref_ns_list;
	struct domain_info  ref_resp;
    struct rrset_rec    *ref_rrset;
    struct rrset_rec    *ans_tail;
    int                 ret_val;
   
	char referral_name[MAXDNAME];
	u_int8_t    referral_name_n[MAXDNAME];
    memcpy (referral_name_n, (*qnames)->qnc_name_n,
                        wire_name_length ((*qnames)->qnc_name_n));
                                                                                                                       
    /* Register the request name and zone with our referral monitor */
    /* If this request has already been made then Referral Error */
                                                                                                                          
   if (register_query (referral_name_n, query_type_h,
                                    referral_zone_n)==ITS_BEEN_DONE)
   {
		free_qname_chain (qnames);
        return res_sq_set_message (error_msg, "Referral failed",
                SR_REFERRAL_ERROR);
   }
		
   /* Get an NS list for the referral zone */
   if ((ret_val=res_zi_unverified_ns_list (context, &ref_ns_list, referral_zone_n, *learned_zones))
                != SR_UNSET)
   {
       if (ret_val == SR_MEMORY_ERROR) return SR_MEMORY_ERROR;
   }

   if (ref_ns_list == NULL)
   {
		free_qname_chain (qnames);
        return res_sq_set_message (error_msg, "Referral failed",
                SR_REFERRAL_ERROR);
   }
   /* Call val_resquery for the (maybe new name and) ref_ns_list */
   memset (&ref_resp, 0, sizeof (struct domain_info));
                                                                                                                          
	if(ns_name_ntop(referral_name_n,referral_name, MAXDNAME-1) == -1)
	{
		free_name_servers (&ref_ns_list);
		return -1;
	}

{
char    debug_name2[1024];
memset (debug_name2,0,1024);
ns_name_ntop(referral_zone_n,debug_name2,1024);
val_log ("QUERYING: '%s.' (referral to %s)\n",
referral_name, debug_name2);
}
    ret_val = val_resquery (context, referral_name, query_type_h,
                               query_class_h, ref_ns_list, &ref_resp);
	//XXX Merge other settings from context->nslist to ref_ns_list
	free_name_servers (&ref_ns_list);
                                                                                                                  
    if (ret_val == SR_MEMORY_ERROR) return SR_MEMORY_ERROR;
                                                                                                                          
    if (ret_val==SR_NULLPTR_ERROR || ret_val==SR_CALL_ERROR
         || ret_val==SR_INITIALIZATION_ERROR || ret_val==SR_HEADER_ERROR
         || ret_val==SR_TSIG_ERROR || ret_val==SR_INTERNAL_ERROR
         || ret_val==SR_MESSAGE_ERROR || ret_val==SR_DATA_MISSING_ERROR
         || ret_val==SR_REFERRAL_ERROR || ret_val==SR_NO_ANSWER)
    {
        free_domain_info_ptrs (&ref_resp);
		free_qname_chain (qnames);
        return res_sq_set_message (error_msg, "Referral failed",
                SR_REFERRAL_ERROR);
    }
                                                                                                                          
    /* We can de-register the request now. */
    deregister_query (referral_name_n, query_type_h, referral_zone_n);

    /* Update the qname chain */
    ref_rrset = ref_resp.di_rrset;
    while (ref_rrset)
    {
         if (ref_rrset->rrs_type_h == ns_t_cname
                    && namecmp(referral_name_n,ref_rrset->rrs_name_n)==0)
         {
                if((ret_val=add_to_qname_chain(qnames,
                        ref_rrset->rrs_data->rr_rdata)) !=SR_UNSET)
                    return SR_MEMORY_ERROR;
         }
         ref_rrset = ref_rrset->rrs_next;
     }
                                                                                                                          
     /* Tie new answer to old */
                                                                                                                          
     if (*answers==NULL)
            *answers = ref_resp.di_rrset;
     else
     {
         ans_tail = *answers;
         while (ans_tail->rrs_next != NULL)
                ans_tail = ans_tail->rrs_next;
         ans_tail->rrs_next = ref_resp.di_rrset;
     }
                                                                                                                          
     ref_resp.di_rrset = NULL;
     free_domain_info_ptrs (&ref_resp);

    return SR_UNSET;
}

#define SAVE_RR_TO_LIST(listtype, name_n, type_h, set_type_h,\
				class_h, ttl_h, rdata, from_section,authoritive,tsig_trusted) \
	do { \
            rr_set = find_rr_set (&listtype, name_n, type_h, set_type_h,\
                             class_h, ttl_h, rdata, from_section,authoritive,tsig_trusted);\
            if (rr_set==NULL) return SR_MEMORY_ERROR;\
            rr_set->rrs_ans_kind = SR_ANS_STRAIGHT;\
            if (type_h != ns_t_rrsig)\
            {\
                /* Add this record to its chain of rr_rec's. */\
                if ((ret_val = add_to_set(rr_set,rdata_len_h,rdata))!=SR_UNSET) \
                    return ret_val;\
            }\
            else\
            {\
                /* Add this record to the sig of rrset_rec. */\
                if ((ret_val = add_as_sig(rr_set,rdata_len_h,rdata))!=SR_UNSET)\
                    return ret_val;\
            }\
	} while (0);


int digest_response (   val_context_t 		*context,
						const u_int8_t      *query_name_n,
                        u_int16_t           query_type_h,
                        u_int16_t           query_class_h,
                        struct rrset_rec    **answers,
                        struct qname_chain  **qnames,
                        u_int8_t            *response,
                        u_int32_t           response_length,
                        int                 tsig_trusted,
                        char                **error_msg)
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
                                                                                                                          
            Create a dummy answer record to handle this.  The status is
            SR_EMPTY_NXDOMAIN, with no data or signature records.
        */
        return prepare_empty_nxdomain (answers, query_name_n, query_type_h,
                                            query_class_h);
    }
                                                                                                                          
    nothing_other_than_cname = query_type_h != ns_t_cname &&
                                    query_type_h != ns_t_any;

    /* Add the query name to the chain of acceptable names */
    if ((ret_val=add_to_qname_chain(qnames,query_name_n))!=SR_UNSET)
        return SR_MEMORY_ERROR;
                                                                                                                          
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
                                                                                                                          
        if (extract_from_rr (response, &response_index,end,name_n,&type_h,
            &set_type_h,&class_h,&ttl_h,&rdata_len_h,&rdata_index)!=SR_UNSET)
            return res_sq_set_message (error_msg,
                "Failed to extract RR", SR_INTERNAL_ERROR);
                                                                                                                          
        authoritive = (header->aa == 1) && qname_chain_first_name (*qnames,name_n);
                                                                                                                          
        /*
            response[rdata_index] is the first byte of the RDATA of the
            record.  The data may contain domain names in compressed format,
            so they need to be expanded.  This is type-dependent...
        */
        if ((ret_val = decompress(&rdata, response, rdata_index, end, type_h,
                            &rdata_len_h))!= SR_UNSET) {
            if (ret_val == SR_MEMORY_ERROR)
                return ret_val;
            else
                return res_sq_set_message (error_msg,
                            "Failed to decompress RR", SR_INTERNAL_ERROR);
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
                if((ret_val=add_to_qname_chain(qnames,rdata))!=SR_UNSET)
                    return SR_MEMORY_ERROR;
                                                                                                                          
            /* Find the rrset_rec for this record, create it if need be */
                                                                                                                          
            rr_set = find_rr_set (answers, name_n, type_h, set_type_h,
                                        class_h, ttl_h, rdata, from_section,authoritive,tsig_trusted);
            if (rr_set==NULL) return SR_MEMORY_ERROR;

            if (type_h != ns_t_rrsig)
            {
                /* Add this record to its chain of rr_rec's. */
                if ((ret_val = add_to_set(rr_set,rdata_len_h,rdata))!=SR_UNSET)
                    return ret_val;
            }
            else
            {
                /* Add this record to the sig of rrset_rec. */
                if ((ret_val = add_as_sig(rr_set,rdata_len_h,rdata))!=SR_UNSET)
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
                    return res_sq_set_message (error_msg,
                        "Referral message w/multiple zones", SR_MESSAGE_ERROR);
                }
                                                                                                                          
            referral_seen = TRUE;
        }
	
		if (set_type_h==ns_t_dnskey)
		{
			SAVE_RR_TO_LIST(learned_keys, name_n, type_h, set_type_h,
                             class_h, ttl_h, rdata, from_section,authoritive,tsig_trusted); 
		}
		if (set_type_h==ns_t_ds)
		{
			SAVE_RR_TO_LIST(learned_ds, name_n, type_h, set_type_h,
                             class_h, ttl_h, rdata, from_section,authoritive,tsig_trusted); 
		}
        else if (set_type_h==ns_t_ns || /*set_type_h==ns_t_soa ||*/
                (set_type_h==ns_t_a && from_section == SR_FROM_ADDITIONAL))
        {
            /* This record belongs in the zone_info chain */
			SAVE_RR_TO_LIST(learned_zones, name_n, type_h, set_type_h,
                             class_h, ttl_h, rdata, from_section,authoritive,tsig_trusted); 
        }

        FREE (rdata);
    }


	if (referral_seen)
		ret_val = do_referral(context, referral_zone_n, query_type_h, query_class_h,
					answers, &learned_zones, qnames, error_msg);
	else
		ret_val = SR_UNSET;

	stow_zone_info (learned_zones);
	stow_key_info (learned_keys);
	stow_ds_info (learned_ds);

    return ret_val;
}


int val_resquery ( 	val_context_t			*context,
					const char              *domain_name,
                    const u_int16_t         type,
                    const u_int16_t         class,
					struct name_server 		*pref_nslist, 
					struct domain_info      *response)
{
    struct name_server  *server = NULL;
	u_int8_t			*response_data = NULL;
	u_int32_t			response_length;

	int                 tsig_trusted;
    struct rrset_rec    *answers = NULL;
    struct qname_chain  *qnames = NULL;
	u_char domain_name_n[MAXCDNAME];

    int                 ret_val;

    /* If there is no place to put the answer, complain */
    if (response==NULL) return SR_NULLPTR_ERROR;
                                
    /* Initialize the response structure */
	response->di_rrset = NULL;
	response->di_qnames = NULL;
    response->di_error_message = NULL;
    response->di_requested_type_h = type;
    response->di_requested_class_h = class;

    if (domain_name==NULL)
        return res_sq_set_message (&response->di_error_message,
                                        NO_DOMAIN_NAME, SR_CALL_ERROR);
                                                                                     
    if ((response->di_requested_name_h = STRDUP (domain_name))==NULL)
        return SR_MEMORY_ERROR;

                                                                                                                          
    /* Get a (set of) answer(s) from the default NS's */

	/* If nslist is NULL, read the cached zones and name servers
	 * in context to create the nslist
	 */
	struct name_server *nslist;
	if (pref_nslist == NULL) {
		// XXX Identify which are relevant and create the ns_list
		// XXX look into the cache also
		nslist = context->nslist;
	}
	else {
		nslist = pref_nslist;
	}

    if ((ret_val = get (domain_name, type, class,  
								nslist, &server, 
								&response_data, &response_length,
                                &response->di_error_message)) != SR_UNSET)
		return ret_val;

	tsig_trusted = server->ns_security_options & ZONE_USE_TSIG;

    if (ns_name_pton(domain_name, domain_name_n, MAXCDNAME-1) == -1)
        return (SR_CALL_ERROR);

    if ((ret_val = digest_response (context, domain_name_n, type, class, 
                    &answers, &qnames, response_data, response_length,
                    tsig_trusted, &response->di_error_message)) != SR_UNSET)
    {
        FREE (response_data);
        return ret_val;
    }
   
                                                                                                                      
    /* What happens when an empty NXDOMAIN is returned? */
    /* What happens when an empty NOERROR is returned? */
    
    FREE (response_data);

	response->di_rrset = answers;
	response->di_qnames = qnames;
	
    return ret_val;
}
