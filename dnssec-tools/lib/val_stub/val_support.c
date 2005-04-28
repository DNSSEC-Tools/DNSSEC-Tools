
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
#include <res_errors.h>
#include <support.h>
#include <res_query.h>

#include "val_errors.h"
#include "val_log.h"

#define SIGNBY              18

void free_name_server (struct name_server **ns)
{
    if (ns && *ns)
    {
        if ((*ns)->ns_name_n) FREE ((*ns)->ns_name_n);
        if ((*ns)->ns_tsig_key) FREE ((*ns)->ns_tsig_key);
        FREE (*ns);
        *ns=NULL;
    }
}
                                                                                                                          
void free_name_servers (struct name_server **ns)
{
    if (ns && *ns)
    {
        if ((*ns)->ns_next) free_name_servers (&((*ns)->ns_next));
        free_name_server (ns);
    }
}



void res_sq_free_rr_recs (struct rr_rec **rr)
{
    if (rr==NULL) return;
                                                                                                                          
    if (*rr)
    {
        if ((*rr)->rr_rdata) FREE ((*rr)->rr_rdata);
        if ((*rr)->rr_next) res_sq_free_rr_recs(&((*rr)->rr_next));
        FREE (*rr);
        *rr = NULL;
    }
}


void res_sq_free_rrset_recs (struct rrset_rec **set)
{
    if (set==NULL) return;
                                                                                                                          
    if (*set)
    {
        if ((*set)->rrs_name_n) FREE ((*set)->rrs_name_n);
        if ((*set)->rrs_data) res_sq_free_rr_recs (&((*set)->rrs_data));
        if ((*set)->rrs_sig) res_sq_free_rr_recs (&((*set)->rrs_sig));
        if ((*set)->rrs_next) res_sq_free_rrset_recs (&((*set)->rrs_next));
        FREE (*set);
        *set = NULL;
    }
}


int add_to_qname_chain (  struct qname_chain  **qnames,
                                const u_int8_t      *name_n)
{
    struct qname_chain *temp;
                                                                                                                          
    temp = (struct qname_chain *) MALLOC (sizeof (struct qname_chain));
                                                                                                                          
    if (temp==NULL) return SR_MEMORY_ERROR;
                                                                                                                          
    memcpy (temp->qc_name_n, name_n, wire_name_length(name_n));
                                                                                                                          
    temp->qc_next = *qnames;
    *qnames = temp;
                                                                                                                          
    return SR_UNSET;
}


int qname_chain_first_name (struct qname_chain *qnames, const u_int8_t *name_n)
{
    struct qname_chain  *qc;
                                                                                                                          
    if (qnames == NULL || name_n==NULL) return FALSE;
                                                                                                                          
    qc = qnames;
    while (qc != NULL && namecmp(qc->qc_name_n,name_n)!=0)
        qc = qc->qc_next;
                                                                                                                          
    return (qc!=NULL && qc->qc_next==NULL);
}

void free_qname_chain (struct qname_chain **qnames)
{
    if (qnames==NULL || (*qnames)==NULL) return;
                                                                                                                          
    if ((*qnames)->qc_next)
        free_qname_chain (&((*qnames)->qc_next));
                                                                                                                          
    FREE (*qnames);
    (*qnames) = NULL;
}

void free_domain_info_ptrs (struct domain_info *di)
{
    if (di==NULL) return;
                                                                                                                          
    if (di->di_requested_name_h)
    {
        FREE (di->di_requested_name_h);
        di->di_requested_name_h = NULL;
    }
                                                                                                                          
    if (di->di_rrset) res_sq_free_rrset_recs (&di->di_rrset);
                                                                                                                          
	if (di->di_qnames)
	{
		free_qname_chain(&di->di_qnames);
	}

    if (di->di_error_message)
    {
        FREE (di->di_error_message);
        di->di_error_message = NULL;
    }

}

int is_tail (u_int8_t *full, u_int8_t *tail)
{
    int f_len = wire_name_length (full);
    int t_len = wire_name_length (tail);
                                                                                                                          
    if (f_len==t_len)
        return memcmp(full, tail, f_len)==0;
                                                                                                                          
    if (t_len > f_len)
        return FALSE;
                                                                                                                          
    if (memcmp (&full[f_len-t_len], tail, t_len)==0)
    {
        u_int8_t    index = 0;
                                                                                                                          
        while (index < (f_len-t_len))
        {
            index += (full[index]) + (u_int8_t) 1;
            if (index == f_len-t_len) return TRUE;
        }
    }
                                                                                                                          
    return FALSE;
}
                                                                                                                          
int nxt_sig_match (u_int8_t *owner, u_int8_t *next, u_int8_t *signer)
{
    int o_len = wire_name_length (owner);
    int s_len = wire_name_length (signer);
                                                                                                                          
    if (o_len==s_len && memcmp(signer, owner, o_len)==0)
        return (is_tail(next,signer));
    else
        return (is_tail(next,signer) && !is_tail(next,owner));
}


int add_to_set (struct rrset_rec *rr_set,u_int16_t rdata_len_h,u_int8_t *rdata)
{
    struct rr_rec *rr;
                                                                                                                          
    /* Add it to the end of the current list of RR's */
    if (rr_set->rrs_data==NULL)
    {
        rr_set->rrs_data = (struct rr_rec *) MALLOC (sizeof(struct rr_rec));
        rr = rr_set->rrs_data;
    }
    else
    {
        rr = rr_set->rrs_data;
        while (rr->rr_next)
            rr = rr->rr_next;
        rr->rr_next = (struct rr_rec *) MALLOC (sizeof(struct rr_rec));
        rr = rr->rr_next;
    }
                                                                                                                          
    /* Make sure we got the memory for it */
    if (rr == NULL) return SR_MEMORY_ERROR;
                                                                                                                          
    /* Insert the data, copying the rdata pointer */
    rr->rr_rdata_length_h = rdata_len_h;
    rr->rr_rdata = (u_int8_t *) MALLOC (rdata_len_h);
    memcpy (rr->rr_rdata ,rdata, rdata_len_h);
    rr->rr_next = NULL;
                                                                                                                          
    return SR_UNSET;
}

int add_as_sig (struct rrset_rec *rr_set,u_int16_t rdata_len_h,u_int8_t *rdata)
{
    struct rr_rec *rr;
                                                                                                                          
    if (rr_set->rrs_sig==NULL)
    {
        rr_set->rrs_sig = (struct rr_rec *) MALLOC (sizeof(struct rr_rec));
        rr = rr_set->rrs_sig;
    }
    else
    {
        /*
            If this code is executed, then there is a problem brewing.
            It will be caught in pre_verify to keep the code level.
        */
        rr = rr_set->rrs_sig;
        while (rr->rr_next)
            rr = rr->rr_next;
        rr->rr_next = (struct rr_rec *) MALLOC (sizeof(struct rr_rec));
        rr = rr->rr_next;
    }
                                                                                                                          
    /* Make sure we got the memory for it */
    if (rr == NULL) return SR_MEMORY_ERROR;
                                                                                                                          
    /* Insert the data, copying the rdata pointer */
    rr->rr_rdata_length_h = rdata_len_h;
    rr->rr_rdata = (u_int8_t *) MALLOC (rdata_len_h);
                                                                                                                          
    /* Check for NO MORE MEMORY */
                                                                                                                          
    memcpy (rr->rr_rdata ,rdata, rdata_len_h);
    rr->rr_next = NULL;
                                                                                                                          
    return SR_UNSET;
}

int init_rr_set (   struct rrset_rec    *new_set,
                    u_int8_t            *name_n,
                    u_int16_t           type_h,
                    u_int16_t           set_type_h,
                    u_int16_t           class_h,
                    u_int32_t           ttl_h,
                    u_int8_t            *rdata_n,
                    int                 from_section,
                    int                 authoritive_answer,
                    int                 tsig_ed)
{
    int                 name_len = wire_name_length(name_n);
                                                                                                                          
    if (new_set->rrs_name_n != NULL)
        /* This has already been initialized */
        return SR_UNSET;
                                                                                                                          
    /* Initialize it */
    new_set->rrs_name_n = (u_int8_t *)MALLOC (name_len);
    if (new_set->rrs_name_n==NULL)
    {
        FREE (new_set);
        return SR_MEMORY_ERROR;
    }
                                                                                                                          
    memcpy (new_set->rrs_name_n, name_n, name_len);
    new_set->rrs_type_h = set_type_h;
    new_set->rrs_class_h = class_h;
    new_set->rrs_ttl_h = ttl_h;
    new_set->rrs_data = NULL;
    new_set->rrs_sig = NULL;
    new_set->rrs_next = NULL;
                                                                                                                          
    /* Set the credibility */
   if (from_section==SR_FROM_ANSWER)
        new_set->rrs_cred = authoritive_answer?
                                SR_CRED_AUTH_ANS:SR_CRED_NONAUTH_ANS;
    else if (from_section==SR_FROM_AUTHORITY)
        new_set->rrs_cred = authoritive_answer?
                                SR_CRED_AUTH_AUTH:SR_CRED_NONAUTH_AUTH;
    else if (from_section==SR_FROM_ADDITIONAL)
        new_set->rrs_cred = authoritive_answer?
                                SR_CRED_AUTH_ADD:SR_CRED_NONAUTH_ADD;
    else
        new_set->rrs_cred = SR_CRED_UNSET;
                                                                                                                          
    /* Set the status */
                                                                                                                          
    new_set->rrs_status = tsig_ed ? SR_TSIG_PROTECTED : SR_DATA_UNCHECKED;
                                                                                                                          
    /* Set the source section */
                                                                                                                          
    new_set->rrs_section = from_section;
                                                                                                                          
    /* Can't set the answer kind yet - need the cnames figured out first */
                                                                                                                          
    new_set->rrs_ans_kind = SR_ANS_UNSET;
                                                                                                                          
    return SR_UNSET;
}

#define IS_THE_ONE(a,n,l,t,s,c,r) \
(                                                                             \
    a &&                                     /* If there's a record */        \
    (                                                                         \
        (s != ns_t_nsec &&                    /* If the type is not nxt: */    \
        a->rrs_type_h == s &&                    /* does type match */        \
        a->rrs_class_h == c &&                   /* does class match */       \
        memcmp (a->rrs_name_n,n,l)==0            /* does name match */        \
        )                                                                     \
        ||                                   /* or */                         \
        (t == ns_t_rrsig &&                    /* if it is a sig(nxt) */        \
        a->rrs_sig==NULL &&                      /* is there no sig here */   \
        a->rrs_data!=NULL &&                     /* is there data here */     \
        a->rrs_class_h == c &&                   /* does class match */       \
        memcmp (a->rrs_name_n,n,l)==0 &&         /* does name match */        \
        nxt_sig_match (n,a->rrs_data->rr_rdata,&r[SIGNBY])                    \
                                                 /* does sig match nxt */     \
        )                                                                     \
        ||                                   /* or */                         \
        (t == ns_t_nsec &&                    /* if it is a nxt */             \
        a->rrs_sig!=NULL &&                      /* is there a sig here */    \
        a->rrs_data==NULL &&                     /* is there no data here */  \
        a->rrs_class_h == c &&                   /* does class match */       \
        memcmp (a->rrs_name_n,n,l)==0 &&         /* does name match */        \
        nxt_sig_match (n,r,&a->rrs_sig->rr_rdata[SIGNBY])                     \
                                                 /* does sig match nxt */     \
        )                                                                     \
    )                                                                         \
)

struct rrset_rec *find_rr_set (
                                struct rrset_rec    **the_list,
                                u_int8_t            *name_n,
                                u_int16_t           type_h,
                                u_int16_t           set_type_h,
                                u_int16_t           class_h,
                                u_int32_t           ttl_h,
                                u_int8_t            *rdata_n,
                                int                 from_section,
                                int                 authoritive_answer,
                                int                 tsig_ed)
{
    struct rrset_rec    *try;
    struct rrset_rec    *last;
    struct rrset_rec    *new_one;
    int                 name_len = wire_name_length(name_n);
                                                                                                                          
    /* Search through the list for a matching record */
    try = *the_list;
    last = NULL;
                                                                                                                          
    while (try)
    {
        if (IS_THE_ONE (try, name_n, name_len, type_h, set_type_h,
                                class_h, rdata_n))
            break;
        last = try;
        try = try->rrs_next;
    }
    /* If no record matches, then create a new one */
    if (try==NULL)
    {
        new_one = (struct rrset_rec *) MALLOC (sizeof(struct rrset_rec));
                                                                                                                          
        if (new_one==NULL) return NULL;
                                                                                                                          
        /* If this is the first ever record, change *the_list */
        if (last==NULL)
            *the_list = new_one;
        else
            last->rrs_next = new_one;
        /*  we need to at least set the predecesor, while we have it */
                                                                                                                          
        memset (new_one, 0, sizeof (struct rrset_rec));
        if ((init_rr_set (new_one, name_n, type_h, set_type_h,
                class_h,ttl_h,rdata_n,from_section, authoritive_answer,tsig_ed))
                    !=SR_UNSET)
        {
            res_sq_free_rrset_recs (the_list);
            return NULL;
        }
    }
    else
    {
        new_one = try;
        /* Make sure it has the lowest ttl (doesn't really matter) */
        if (new_one->rrs_ttl_h > ttl_h) new_one->rrs_ttl_h = ttl_h;
    }
                                                                                                                          
    /* In all cases, return the value of new_one */
    return new_one;
}




int prepare_empty_nxdomain (struct rrset_rec    **answers,
                            const u_int8_t      *query_name_n,
                            u_int16_t           query_type_h,
                            u_int16_t           query_class_h)
{
    size_t length = wire_name_length (query_name_n);
                                                                                                                          
    if (length ==0) return SR_INTERNAL_ERROR;
                                                                                                                          
    *answers = (struct rrset_rec *) MALLOC (sizeof(struct rrset_rec));
                                                                                                                          
    if (*answers==NULL) return SR_MEMORY_ERROR;
                                                                                                                          
    (*answers)->rrs_name_n = (u_int8_t *) MALLOC (length);
                                                                                                                          
    if ((*answers)->rrs_name_n == NULL)
    {
        FREE (*answers);
        *answers = NULL;
        return SR_MEMORY_ERROR;
    }
                                                                                                                          
    memcpy ((*answers)->rrs_name_n, query_name_n, length);
    (*answers)->rrs_type_h = query_type_h;
    (*answers)->rrs_class_h = query_class_h;
    (*answers)->rrs_ttl_h = 0;
    (*answers)->rrs_cred = SR_CRED_UNSET;
    (*answers)->rrs_status = SR_EMPTY_NXDOMAIN;
    (*answers)->rrs_section = SR_FROM_UNSET;
    (*answers)->rrs_data = NULL;
    (*answers)->rrs_sig = NULL;
    (*answers)->rrs_next = NULL;
                                                                                                                          
    return SR_UNSET;
}

int decompress( u_int8_t    **rdata,
                u_int8_t    *response,
                int         rdata_index,
                u_int8_t    *end,
                u_int16_t   type_h,
                u_int16_t   *rdata_len_h)
{
    u_int8_t    expanded_name[MAXDNAME];
    u_int8_t    other_expanded_name[MAXDNAME];
    u_int8_t    prefix[6];
    int         p_index = 0;
    size_t      new_size;
    int         working_index = rdata_index;
    int         other_name_length = 0;
    int         name_length = 0;
    int         insert_index = 0;
    int         working_increment;
    int         expansion = 0;
                                                                                                                          
    switch (type_h)
    {
        /* The first group has no domain names to convert */
                                                                                                                          
        case ns_t_nsap: case ns_t_eid:      case ns_t_nimloc:   case ns_t_dnskey:
        case ns_t_aaaa: case ns_t_loc:      case ns_t_atma:     case ns_t_a:
        case ns_t_wks:  case ns_t_hinfo:    case ns_t_txt:      case ns_t_x25:
        case ns_t_isdn: case ns_t_ds:	default:
            new_size = (size_t)*rdata_len_h;
            *rdata = (u_int8_t*) MALLOC (new_size);
            if (*rdata==NULL) return SR_MEMORY_ERROR;
                                                                                                                          
            memcpy (&(*rdata)[insert_index], &response[rdata_index], new_size);
            *rdata_len_h = *rdata_len_h; /* No change */
            break;
                                                                                                                          
        /* The next group starts with one or two domain names */
                                                                                                                          
        case ns_t_soa:  case ns_t_minfo:    case ns_t_rp:
                                                                                                                          
            working_increment = ns_name_unpack (response,end,
                                    &response[working_index],
                                    other_expanded_name,MAXDNAME);
                                                                                                                          
            if (working_increment < 0) return SR_INTERNAL_ERROR;
                                                                                                                          
            working_index += working_increment;
            other_name_length = wire_name_length (other_expanded_name);
            expansion += other_name_length - working_increment;
                                                                                                                          
            /* fall through */
        case ns_t_ns:   case ns_t_cname:    case ns_t_mb:       case ns_t_mg:
        case ns_t_mr:   case ns_t_ptr:      case ns_t_nsec:
                                                                                                                          
            working_increment = ns_name_unpack (response,end,
                                    &response[working_index],
                                    expanded_name,MAXDNAME);
            if (working_increment < 0) return SR_INTERNAL_ERROR;
                                                                                                                          
            working_index += working_increment;
            name_length = wire_name_length (expanded_name);
            expansion += name_length - working_increment;
                                                                                                                          
            /* Make the new data area */
                                                                                                                          
            new_size = (size_t) (*rdata_len_h + expansion);
                                                                                                                          
            *rdata = (u_int8_t*) MALLOC (new_size);
            if (*rdata==NULL) return SR_MEMORY_ERROR;
                                                                                                                          
            /* Copy in the names */
                                                                                                                          
            memcpy(&(*rdata)[insert_index], other_expanded_name,
                                                other_name_length);
            insert_index += other_name_length;
                                                                                                                          
            memcpy(&(*rdata)[insert_index],expanded_name,name_length);
            insert_index += name_length;
                                                                                                                          
            /* Copy any remaining data */
                                                                                                                          
            memcpy(&(*rdata)[insert_index],&response[working_index],
                *rdata_len_h + expansion - other_name_length - name_length);
                                                                                                                          
            *rdata_len_h += expansion;
                                                                                                                          
            break;
                                                                                                                          
        /* The following group ends with one or two domain names */
        case ns_t_srv:
                                                                                                                          
            memcpy (&prefix[p_index],&response[working_index],
                                                2*sizeof(u_int16_t));
            working_index += 2*sizeof(u_int16_t);
            p_index += 2*sizeof(u_int16_t);
        case ns_t_rt: case ns_t_mx: case ns_t_afsdb: case ns_t_px:
                                                                                                                          
            memcpy (&prefix[p_index],&response[working_index],
                                                sizeof(u_int16_t));
            working_index += sizeof(u_int16_t);
            p_index += sizeof(u_int16_t);
                                                                                                                          
            working_increment = ns_name_unpack (response,end,
                                    &response[working_index],
                                    expanded_name,MAXDNAME);
            if (working_increment < 0) return SR_INTERNAL_ERROR;
                                                                                                                          
            working_index += working_increment;
            name_length = wire_name_length (expanded_name);
            expansion += name_length - working_increment;
                                                                                                                          
            if (type_h == ns_t_px)
            {
                working_increment = ns_name_unpack (response,end,
                                    &response[working_index],
                                    other_expanded_name,MAXDNAME);
                if (working_increment < 0) return SR_INTERNAL_ERROR;
                                                                                                                          
                working_index += working_increment;
                other_name_length = wire_name_length (other_expanded_name);
                expansion += other_name_length - working_increment;
            }
                                                                                                                          
            /* Make the new data area */
                                                                                                                          
            new_size = (size_t) (*rdata_len_h + expansion);
                                                                                                                          
            *rdata = (u_int8_t*) MALLOC (new_size);
            if (*rdata==NULL) return SR_MEMORY_ERROR;
                                                                                                                          
            /* Copy in the prefix */
            memcpy(&*rdata[insert_index],prefix,p_index);
            insert_index += p_index;
                                                                                                                          
            /* Copy in the names */
                                                                                                                          
            memcpy(&(*rdata)[insert_index], expanded_name, name_length);
            insert_index += name_length;
                                                                                                                          
            memcpy(&(*rdata)[insert_index],other_expanded_name,
                            other_name_length);
            insert_index += other_name_length;
                                                                                                                          
            *rdata_len_h += expansion;
                                                                                                                          
            break;
                                                                                                                          
        /* The special case - the SIG record */
        case ns_t_rrsig:

            working_increment = ns_name_unpack (response,end,
                    &response[working_index+SIGNBY], expanded_name,MAXDNAME);
            if (working_increment < 0) return SR_INTERNAL_ERROR;
                                                                                                                          
            name_length = wire_name_length (expanded_name);
            expansion += name_length - working_increment;
                                                                                                                          
            /* Make the new data area */
                                                                                                                          
            new_size = (size_t) (*rdata_len_h + expansion);
                                                                                                                          
            *rdata = (u_int8_t*) MALLOC (new_size);
            if (*rdata==NULL) return SR_MEMORY_ERROR;
                                                                                                                          
            memcpy(&(*rdata)[insert_index], &response[working_index],SIGNBY);
            insert_index += SIGNBY;
            working_index += SIGNBY;
                                                                                                                          
            memcpy(&(*rdata)[insert_index], expanded_name, name_length);
            insert_index += name_length;
            working_index += working_increment;
                                                                                                                          
            memcpy(&(*rdata)[insert_index], &response[working_index],
                                *rdata_len_h - working_increment - SIGNBY);
                                                                                                                          
            *rdata_len_h += expansion;
    }
                                                                                                                          
    return SR_UNSET;
}

int extract_from_rr (   u_int8_t *response,
                        int *response_index,
                        u_int8_t *end,
                        u_int8_t *name_n,
                        u_int16_t *type_h,
                        u_int16_t *set_type_h,
                        u_int16_t *class_h,
                        u_int32_t *ttl_h,
                        u_int16_t *rdata_length_h,
                        int *rdata_index)
{
    u_int16_t   net_short;
    u_int32_t   net_int;
    int         ret_val;
                                                                                                                          
    /* Extract the uncompressed (unpacked) domain name in protocol format */
    if ((ret_val = ns_name_unpack (response, end, &response[*response_index],
                                    name_n, MAXDNAME))==-1)
        return SR_INTERNAL_ERROR;
                                                                                                                          
    *response_index += ret_val;
                                                                                                                          
    /* Extract the type, and save it in host format */
    memcpy (&net_short, &response[*response_index], sizeof (u_int16_t));
    *type_h = ntohs(net_short);
    *response_index += sizeof (u_int16_t);
                                                                                                                          
    /* Extract the class, and save it in host format */
    memcpy (&net_short, &response[*response_index], sizeof (u_int16_t));
    *class_h = ntohs(net_short);
    *response_index += sizeof (u_int16_t);
                                                                                                                          
    /* Extract the ttl, and save it in host format */
    memcpy (&net_int, &response[*response_index], sizeof (u_int32_t));
    *ttl_h = ntohl(net_int);
    *response_index += sizeof (u_int32_t);
                                                                                                                          
    /* Extract the rdata length, and save it in host format */
    memcpy (&net_short, &response[*response_index], sizeof (u_int16_t));
    *rdata_length_h = ntohs(net_short);
    *response_index += sizeof (u_int16_t);
                                                                                                                          
    *rdata_index = *response_index;
                                                                                                                          
    /*
        If this is a signature, then get the type covered to serve as
        the *set_type_h.  If this is not a signature, then set the *set_type_h
        to *type_h.
                                                                                                                          
        Don't advance the response_index yet, it will be done in the next
        step.
    */
                                                                                                                          
    if (*type_h == ns_t_rrsig)
    {
        /* Extract the set type, and save it in host format */
        memcpy (&net_short, &response[*response_index], sizeof (u_int16_t));
        *set_type_h = ntohs(net_short);
    }
    else
        *set_type_h = *type_h;
                                                                                                                          
    *response_index += *rdata_length_h;
                                                                                                                          
    return SR_UNSET;
}

char *p_val_error(int errno)
{
    switch (errno) {

    case NO_ERROR: return "NO_ERROR"; break;
    case NOT_IMPLEMENTED: return "NOT_IMPLEMENTED"; break;
    case OUT_OF_MEMORY: return "OUT_OF_MEMORY"; break;
    case BAD_ARGUMENT: return "BAD_ARGUMENT"; break;
    case INTERNAL_ERROR: return "INTERNAL_ERROR"; break;
    case NO_PERMISSION: return "NO_PERMISSION"; break;
    case RESOURCE_UNAVAILABLE: return "RESOURCE_UNAVAILABLE"; break;
    case CONF_PARSE_ERROR: return "CONF_PARSE_ERROR"; break;
    case NO_POLICY: return "NO_POLICY"; break;
    case MALFORMED_LOCALE: return "MALFORMED_LOCALE"; break;
    case UNKNOWN_LOCALE: return "UNKNOWN_LOCALE"; break;
    case FILE_ERROR: return "FILE_ERROR"; break;
    case VALIDATE_SUCCESS: return "VALIDATE_SUCCESS"; break;
    case BOGUS: return "BOGUS"; break;
    case INDETERMINATE: return "INDETERMINATE"; break;
    case PROVABLY_UNSECURE: return "PROVABLY_UNSECURE"; break;
    case SECURITY_LAME: return "SECURITY_LAME"; break;
    case NAME_EXPANSION_FAILURE: return "NAME_EXPANSION_FAILURE"; break;
    case NO_PREFERRED_SEP: return "NO_PREFERRED_SEP"; break;
    case NO_TRUST_ANCHOR: return "NO_TRUST_ANCHOR"; break;
    case TOO_MANY_LINKS: return "TOO_MANY_LINKS"; break;
    case TRUST_ANCHOR_TIMEOUT: return "TRUST_ANCHOR_TIMEOUT"; break;
    case OVERREACHING_NSEC: return "OVERREACHING_NSEC"; break;
    case NSEC_POINTING_UPWARDS: return "NSEC_POINTING_UPWARDS"; break;
    case IRRELEVANT_PROOF: return "IRRELEVANT_PROOF"; break;
    case INCOMPLETE_PROOF: return "INCOMPLETE_PROOF"; break;
    case PROVED_OWNERNAME_MISSING: return "PROVED_OWNERNAME_MISSING"; break;
    case PROVED_TYPE_MISSING: return "PROVED_TYPE_MISSING"; break;
    case RRSIG_VERIFIED: return "RRSIG_VERIFIED"; break;
    case RRSIG_VERIFY_FAILED: return "RRSIG_VERIFY_FAILED"; break;
    case BARE_RRSIG: return "BARE_RRSIG"; break;
    case RRSIG_EXPIRED: return "RRSIG_EXPIRED"; break;
    case RRSIG_NOTYETACTIVE: return "RRSIG_NOTYETACTIVE"; break;
    case KEY_TOO_LARGE: return "KEY_TOO_LARGE"; break;
    case KEY_TOO_SMALL: return "KEY_TOO_SMALL"; break;
    case KEY_NOT_AUTHORIZED: return "KEY_NOT_AUTHORIZED"; break;
    case NOT_A_ZONE_KEY: return "NOT_A_ZONE_KEY"; break;
    case CLOCK_SKEW: return "CLOCK_SKEW"; break;
    case ALGO_REFUSED: return "ALGO_REFUSED"; break;
    case UNAUTHORIZED_SIGNER: return "UNAUTHORIZED_SIGNER"; break;
    case RRSIG_MISSING: return "RRSIG_MISSING"; break;
    case DNSKEY_MISSING: return "DNSKEY_MISSING"; break;
    case DS_MISSING: return "DS_MISSING"; break;
    case NSEC_MISSING: return "NSEC_MISSING"; break;
    case DUPLICATE_KEYTAG: return "DUPLICATE_KEYTAG"; break;
    case CONFLICTING_PROOFS: return "CONFLICTING_PROOFS"; break;
    case UNKNOWN_ALGO: return "UNKNOWN_ALGO"; break;
    case ALGO_NOT_SUPPORTED: return "ALGO_NOT_SUPPORTED"; break;
    case WRONG_RRSIG_OWNER: return "WRONG_RRSIG_OWNER"; break;
    case KEYTAG_MISMATCH: return "KEYTAG_MISMATCH"; break;
    case UNKNOWN_DNSKEY_PROTO: return "UNKNOWN_DNSKEY_PROTO"; break;
    case DNS_FAILURE: return "DNS_FAILURE"; break;
    case WAITING: return "WAITING"; break;
    case WAKEUP: return "WAKEUP"; break;
	/*
    case INSUFFICIENT_DATA: return "INSUFFICIENT_DATA"; break;
    case HEADER_ERROR: return "HEADER_ERROR"; break;
    case WRONG_LABEL_COUNT: return "WRONG_LABEL_COUNT"; break;
    case EDNS_VERSION_ERROR: return "EDNS_VERSION_ERROR"; break;
    case UNSUPP_ENDS0_LABEL: return "UNSUPP_ENDS0_LABEL"; break;
    case FLOOD_ATTACK_DETECTED: return "FLOOD_ATTACK_DETECTED"; break;
    case DNSSEC_VERSION_ERROR: return "DNSSEC_VERSION_ERROR"; break;
    case SUSPICIOUS_BIT: return "SUSPICIOUS_BIT"; break;
	*/
    default: return "Unknown Error Value";
    }
}
