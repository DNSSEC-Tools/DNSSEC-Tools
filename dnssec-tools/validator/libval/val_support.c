
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
#include "validator-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <resolver.h>
#include <validator.h>
#include "val_support.h"

int labelcmp (const u_int8_t *name1, const u_int8_t *name2)
{
    /* Compare two names, assuming same number of labels in each */
    int             index1 = 0;
    int             index2 = 0;
    int             length1 = (int) name1[index1];
    int             length2 = (int) name2[index2];
    int             min_len = length1 < length2 ? length1 : length2;
    int             ret_val;
                                                                                                                          
    u_int8_t        buffer1[NS_MAXDNAME];
    u_int8_t        buffer2[NS_MAXDNAME];
    int             i;
                                                                                                                          
    /* Degenerate case - root versus root */
    if (length1==0 && length2==0) return 0;
                                                                                                                          
    /* Recurse to try more significant label(s) first */
    ret_val=labelcmp(&name1[length1+1],&name2[length2+1]);
                                                                                                                          
    /* If there is a difference, propogate that back up the calling tree */
    if (ret_val!=0) return ret_val;
                                                                                                                          
    /* Compare this label's first min_len bytes */
    /* Convert to lower case first */
    memcpy (buffer1, &name1[index1+1], min_len);
    for (i =0; i < min_len; i++)
        if (isupper(buffer1[i])) buffer1[i]=tolower(buffer1[i]);
                                                                                                                          
    memcpy (buffer2, &name2[index2+1], min_len);
    for (i =0; i < min_len; i++)
        if (isupper(buffer2[i])) buffer2[i]=tolower(buffer2[i]);
                                                                                                                          
    ret_val=memcmp(buffer1, buffer2, min_len);
                                                                                                                          
    /* If they differ, propgate that */
    if (ret_val!=0) return ret_val;
    /* If the first n bytes are the same, then the length determines
        the difference - if any */
    return length1-length2;
}
                                                                                                                          
int namecmp (const u_int8_t *name1, const u_int8_t *name2)
{
    /* compare the DNS wire format names in name1 and name2 */
    /* return -1 if name1 is before name2, 0 if equal, +1 otherwise */
    int labels1 = 1;
    int labels2 = 1;
    int index1 = 0;
    int index2 = 0;
    int ret_val;
    int i;
                                                                                                                          
    /* count labels */
    for (;name1[index1];index1 += (int) name1[index1]+1) labels1++;
    for (;name2[index2];index2 += (int) name2[index2]+1) labels2++;
                                                                                                                          
    index1 = 0;
    index2 = 0;
                                                                                                                          
    if (labels1 > labels2)
        for (i = 0; i < labels1-labels2; i++) index1 += (int) name1[index1]+1;
    else
        for (i = 0; i < labels2-labels1; i++) index2 += (int) name2[index2]+1;
                                                                                                                          
    ret_val = labelcmp(&name1[index1], &name2[index2]);
                                                                                                                          
    if (ret_val != 0) return ret_val;
                                                                                                                          
    /* If one dname is a "proper suffix" of the other,
        the shorter comes first */
    return labels1-labels2;
}

u_int16_t wire_name_labels (const u_int8_t *field)
{
    /* Calculates the number of bytes in a DNS wire format name */
    u_short j;
    u_short l=0;
    if (field==NULL) return 0;
                                                                                                                          
    for (j = 0; field[j]&&!(0xc0&field[j])&&j<NS_MAXDNAME ; j += field[j]+1)
        l++;
    if (field[j]) j++;
    j++;
    l++;
                                                                                                                          
    if (j > NS_MAXDNAME)
        return 0;
    else
        return l;
}

u_int16_t wire_name_length (const u_int8_t *field)
{
    /* Calculates the number of bytes in a DNS wire format name */
    u_short j;
    if (field==NULL) return 0;
                                                                                                                          
    for (j = 0; field[j]&&!(0xc0&field[j])&&j<NS_MAXDNAME ; j += field[j]+1);
    if (field[j]) j++;
    j++;
                                                                                                                          
    if (j > NS_MAXDNAME)
        return 0;
    else
        return j;
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
		if ((*set)->rrs_respondent_server) free_name_server(&((*set)->rrs_respondent_server));
        if ((*set)->rrs->val_rrset_name_n) FREE ((*set)->rrs->val_rrset_name_n);
        if ((*set)->rrs->val_rrset_data) res_sq_free_rr_recs (&((*set)->rrs->val_rrset_data));
        if ((*set)->rrs->val_rrset_sig) res_sq_free_rr_recs (&((*set)->rrs->val_rrset_sig));
		if ((*set)->rrs) FREE((*set)->rrs);
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
                                                                                                                          
    if (temp==NULL) return VAL_OUT_OF_MEMORY;
                                                                                                                          
    memcpy (temp->qnc_name_n, name_n, wire_name_length(name_n));
                                                                                                                          
    temp->qnc_next = *qnames;
    *qnames = temp;
                                                                                                                          
    return VAL_NO_ERROR;
}


int qname_chain_first_name (struct qname_chain *qnames, const u_int8_t *name_n)
{
    struct qname_chain  *qc;
                                                                                                                          
    if (qnames == NULL || name_n==NULL) return FALSE;
                                                                                                                          
    qc = qnames;
    while (qc != NULL && namecmp(qc->qnc_name_n,name_n)!=0)
        qc = qc->qnc_next;
                                                                                                                          
    return (qc!=NULL && qc->qnc_next==NULL);
}

void free_qname_chain (struct qname_chain **qnames)
{
    if (qnames==NULL || (*qnames)==NULL) return;
                                                                                                                          
    if ((*qnames)->qnc_next)
        free_qname_chain (&((*qnames)->qnc_next));
                                                                                                                          
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
    if (rr_set->rrs->val_rrset_data==NULL)
    {
        rr_set->rrs->val_rrset_data = (struct rr_rec *) MALLOC (sizeof(struct rr_rec));
        rr = rr_set->rrs->val_rrset_data;
    }
    else
    {
        rr = rr_set->rrs->val_rrset_data;
        while (rr->rr_next)
            rr = rr->rr_next;
        rr->rr_next = (struct rr_rec *) MALLOC (sizeof(struct rr_rec));
        rr = rr->rr_next;
    }
                                                                                                                          
    /* Make sure we got the memory for it */
    if (rr == NULL) return VAL_OUT_OF_MEMORY;
                                                                                                                          
    /* Insert the data, copying the rdata pointer */
    rr->rr_rdata_length_h = rdata_len_h;
    rr->rr_rdata = (u_int8_t *) MALLOC (rdata_len_h);
    memcpy (rr->rr_rdata ,rdata, rdata_len_h);
    rr->rr_next = NULL;
                                                                                                                          
    return VAL_NO_ERROR;
}

int add_as_sig (struct rrset_rec *rr_set,u_int16_t rdata_len_h,u_int8_t *rdata)
{
    struct rr_rec *rr;
                                                                                                                          
    if (rr_set->rrs->val_rrset_sig==NULL)
    {
        rr_set->rrs->val_rrset_sig = (struct rr_rec *) MALLOC (sizeof(struct rr_rec));
        rr = rr_set->rrs->val_rrset_sig;
    }
    else
    {
        /*
            If this code is executed, then there is a problem brewing.
            It will be caught in pre_verify to keep the code level.
        */
        rr = rr_set->rrs->val_rrset_sig;
        while (rr->rr_next)
            rr = rr->rr_next;
        rr->rr_next = (struct rr_rec *) MALLOC (sizeof(struct rr_rec));
        rr = rr->rr_next;
    }
                                                                                                                          
    /* Make sure we got the memory for it */
    if (rr == NULL) return VAL_OUT_OF_MEMORY;
                                                                                                                          
    /* Insert the data, copying the rdata pointer */
    rr->rr_rdata_length_h = rdata_len_h;
    rr->rr_rdata = (u_int8_t *) MALLOC (rdata_len_h);
                                                                                                                          
    /* Check for NO MORE MEMORY */
                                                                                                                          
    memcpy (rr->rr_rdata ,rdata, rdata_len_h);
    rr->rr_next = NULL;
                                                                                                                          
    return VAL_NO_ERROR;
}

int init_rr_set (   struct rrset_rec    *new_set,
                    u_int8_t            *name_n,
                    u_int16_t           type_h,
                    u_int16_t           set_type_h,
                    u_int16_t           class_h,
                    u_int32_t           ttl_h,
                    u_int8_t            *rdata_n,
                    int                 from_section,
                    int                 authoritive_answer)
{
    int                 name_len = wire_name_length(name_n);
                                                                                                                          
    if (new_set->rrs->val_rrset_name_n != NULL)
        /* This has already been initialized */
        return VAL_NO_ERROR;
                                                                                                                          
    /* Initialize it */
    new_set->rrs->val_rrset_name_n = (u_int8_t *)MALLOC (name_len);
    if (new_set->rrs->val_rrset_name_n==NULL)
    {
        FREE (new_set);
        return VAL_OUT_OF_MEMORY;
    }
                                                                                                                          
    memcpy (new_set->rrs->val_rrset_name_n, name_n, name_len);
    new_set->rrs->val_rrset_type_h = set_type_h;
    new_set->rrs->val_rrset_class_h = class_h;
    new_set->rrs->val_rrset_ttl_h = ttl_h;
    new_set->rrs->val_rrset_data = NULL;
    new_set->rrs->val_rrset_sig = NULL;
    new_set->rrs_next = NULL;
                                                                                                                          
    /* Set the credibility */
   if (from_section==VAL_FROM_ANSWER)
        new_set->rrs_cred = authoritive_answer?
                                SR_CRED_AUTH_ANS:SR_CRED_NONAUTH_ANS;
    else if (from_section==VAL_FROM_AUTHORITY)
        new_set->rrs_cred = authoritive_answer?
                                SR_CRED_AUTH_AUTH:SR_CRED_NONAUTH_AUTH;
    else if (from_section==VAL_FROM_ADDITIONAL)
        new_set->rrs_cred = authoritive_answer?
                                SR_CRED_AUTH_ADD:SR_CRED_NONAUTH_ADD;
    else
        new_set->rrs_cred = SR_CRED_UNSET;
                                                                                                                          
    /* Set the source section */
                                                                                                                          
    new_set->rrs->val_rrset_section = from_section;
                                                                                                                          
    /* Can't set the answer kind yet - need the cnames figured out first */
                                                                                                                          
    new_set->rrs_ans_kind = SR_ANS_UNSET;
                                                                                                                          
    return VAL_NO_ERROR;
}

#define IS_THE_ONE(a,n,l,t,s,c,r) \
(                                                                             \
    a &&                                     /* If there's a record */        \
    (                                                                         \
        (s != ns_t_nsec &&                    /* If the type is not nxt: */    \
        a->rrs->val_rrset_type_h == s &&                    /* does type match */        \
        a->rrs->val_rrset_class_h == c &&                   /* does class match */       \
        memcmp (a->rrs->val_rrset_name_n,n,l)==0            /* does name match */        \
        )                                                                     \
        ||                                   /* or */                         \
        (t == ns_t_rrsig &&                    /* if it is a sig(nxt) */        \
        a->rrs->val_rrset_sig==NULL &&                      /* is there no sig here */   \
        a->rrs->val_rrset_data!=NULL &&                     /* is there data here */     \
        a->rrs->val_rrset_class_h == c &&                   /* does class match */       \
        memcmp (a->rrs->val_rrset_name_n,n,l)==0 &&         /* does name match */        \
        nxt_sig_match (n,a->rrs->val_rrset_data->rr_rdata,&r[SIGNBY])                    \
                                                 /* does sig match nxt */     \
        )                                                                     \
        ||                                   /* or */                         \
        (t == ns_t_nsec &&                    /* if it is a nxt */             \
        a->rrs->val_rrset_sig!=NULL &&                      /* is there a sig here */    \
        a->rrs->val_rrset_data==NULL &&                     /* is there no data here */  \
        a->rrs->val_rrset_class_h == c &&                   /* does class match */       \
        memcmp (a->rrs->val_rrset_name_n,n,l)==0 &&         /* does name match */        \
        nxt_sig_match (n,r,&a->rrs->val_rrset_sig->rr_rdata[SIGNBY])                     \
                                                 /* does sig match nxt */     \
        )                                                                     \
    )                                                                         \
)

struct rrset_rec *find_rr_set (
								struct name_server *respondent_server,
                                struct rrset_rec    **the_list,
                                u_int8_t            *name_n,
                                u_int16_t           type_h,
                                u_int16_t           set_type_h,
                                u_int16_t           class_h,
                                u_int32_t           ttl_h,
                                u_int8_t            *rdata_n,
                                int                 from_section,
                                int                 authoritive_answer)
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
        memset (new_one, 0, sizeof (struct rrset_rec));
		new_one->rrs = (struct val_rrset *) MALLOC (sizeof(struct val_rrset));
		if(new_one->rrs == NULL) return NULL;
        memset (new_one->rrs, 0, sizeof (struct val_rrset));

        /* If this is the first ever record, change *the_list */
        if (last==NULL)
            *the_list = new_one;
        else
            last->rrs_next = new_one;
        /*  we need to at least set the predecesor, while we have it */
        
		if( SR_UNSET != clone_ns(&new_one->rrs_respondent_server, respondent_server)) {
            res_sq_free_rrset_recs (the_list);
            return NULL;
		}
 
        if ((init_rr_set (new_one, name_n, type_h, set_type_h,
                class_h,ttl_h,rdata_n,from_section, authoritive_answer))
                    !=VAL_NO_ERROR)
        {
            res_sq_free_rrset_recs (the_list);
            return NULL;
        }
    }
    else
    {
        new_one = try;
        /* Make sure it has the lowest ttl (doesn't really matter) */
        if (new_one->rrs->val_rrset_ttl_h > ttl_h) new_one->rrs->val_rrset_ttl_h = ttl_h;
    }
                                                                                                                          
    /* In all cases, return the value of new_one */
    return new_one;
}


int check_label_count (
                            struct rrset_rec    *the_set,
                            struct rr_rec       *the_sig,
                            int                 *is_a_wildcard)
{
    u_int8_t owner_labels = wire_name_labels (the_set->rrs->val_rrset_name_n);
    u_int8_t sig_labels = the_sig->rr_rdata[RRSIGLABEL] + 1;
                                                                                                                          
    if (sig_labels > owner_labels) return VAL_ERROR;
                                                                                                                          
    *is_a_wildcard = (owner_labels - sig_labels);
                                                                                                                          
    return VAL_NO_ERROR;
}


int prepare_empty_nxdomain (struct rrset_rec    **answers,
                            const u_int8_t      *query_name_n,
                            u_int16_t           query_type_h,
                            u_int16_t           query_class_h)
{
    size_t length = wire_name_length (query_name_n);
                                                                                                                          
    if (length ==0) return VAL_INTERNAL_ERROR;
                                                                                                                          
    *answers = (struct rrset_rec *) MALLOC (sizeof(struct rrset_rec));
    if (*answers==NULL) return VAL_OUT_OF_MEMORY;
	(*answers)->rrs = (struct val_rrset *) MALLOC (sizeof(struct val_rrset));
	if((*answers)->rrs == NULL) return VAL_OUT_OF_MEMORY;

	(*answers)->rrs_respondent_server = NULL;                                                                                                          
    (*answers)->rrs->val_rrset_name_n = (u_int8_t *) MALLOC (length);
                                                                                                                          
    if ((*answers)->rrs->val_rrset_name_n == NULL)
    {
        FREE (*answers);
        *answers = NULL;
        return VAL_OUT_OF_MEMORY;
    }
                                                                                                                          
    memcpy ((*answers)->rrs->val_rrset_name_n, query_name_n, length);
    (*answers)->rrs->val_rrset_type_h = query_type_h;
    (*answers)->rrs->val_rrset_class_h = query_class_h;
    (*answers)->rrs->val_rrset_ttl_h = 0;
    (*answers)->rrs_cred = SR_CRED_UNSET;
    (*answers)->rrs->val_rrset_section = VAL_FROM_UNSET;
    (*answers)->rrs->val_rrset_data = NULL;
    (*answers)->rrs->val_rrset_sig = NULL;
    (*answers)->rrs_next = NULL;
                                                                                                                          
    return VAL_NO_ERROR;
}

int decompress( u_int8_t    **rdata,
                u_int8_t    *response,
                int         rdata_index,
                u_int8_t    *end,
                u_int16_t   type_h,
                u_int16_t   *rdata_len_h)
{
    u_int8_t    expanded_name[NS_MAXDNAME];
    u_int8_t    other_expanded_name[NS_MAXDNAME];
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
            if (*rdata==NULL) return VAL_OUT_OF_MEMORY;
                                                                                                                          
            memcpy (&(*rdata)[insert_index], &response[rdata_index], new_size);
            *rdata_len_h = *rdata_len_h; /* No change */
            break;
                                                                                                                          
        /* The next group starts with one or two domain names */
                                                                                                                          
        case ns_t_soa:  case ns_t_minfo:    case ns_t_rp:
                                                                                                                          
            working_increment = ns_name_unpack (response,end,
                                    &response[working_index],
                                    other_expanded_name,NS_MAXDNAME);
                                                                                                                          
            if (working_increment < 0) return VAL_INTERNAL_ERROR;
                                                                                                                          
            working_index += working_increment;
            other_name_length = wire_name_length (other_expanded_name);
            expansion += other_name_length - working_increment;
                                                                                                                          
            /* fall through */
        case ns_t_ns:   case ns_t_cname:    case ns_t_mb:       case ns_t_mg:
        case ns_t_mr:   case ns_t_ptr:      case ns_t_nsec:
                                                                                                                          
            working_increment = ns_name_unpack (response,end,
                                    &response[working_index],
                                    expanded_name,NS_MAXDNAME);
            if (working_increment < 0) return VAL_INTERNAL_ERROR;
                                                                                                                          
            working_index += working_increment;
            name_length = wire_name_length (expanded_name);
            expansion += name_length - working_increment;
                                                                                                                          
            /* Make the new data area */
                                                                                                                          
            new_size = (size_t) (*rdata_len_h + expansion);
                                                                                                                          
            *rdata = (u_int8_t*) MALLOC (new_size);
            if (*rdata==NULL) return VAL_OUT_OF_MEMORY;
                                                                                                                          
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
                                    expanded_name,NS_MAXDNAME);
            if (working_increment < 0) return VAL_INTERNAL_ERROR;
                                                                                                                          
            working_index += working_increment;
            name_length = wire_name_length (expanded_name);
            expansion += name_length - working_increment;
                                                                                                                          
            if (type_h == ns_t_px)
            {
                working_increment = ns_name_unpack (response,end,
                                    &response[working_index],
                                    other_expanded_name,NS_MAXDNAME);
                if (working_increment < 0) return VAL_INTERNAL_ERROR;
                                                                                                                          
                working_index += working_increment;
                other_name_length = wire_name_length (other_expanded_name);
                expansion += other_name_length - working_increment;
            }
                                                                                                                          
            /* Make the new data area */
                                                                                                                          
            new_size = (size_t) (*rdata_len_h + expansion);
                                                                                                                          
            *rdata = (u_int8_t*) MALLOC (new_size);
            if (*rdata==NULL) return VAL_OUT_OF_MEMORY;
                                                                                                                          
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
                    &response[working_index+SIGNBY], expanded_name,NS_MAXDNAME);
            if (working_increment < 0) return VAL_INTERNAL_ERROR;
                                                                                                                          
            name_length = wire_name_length (expanded_name);
            expansion += name_length - working_increment;
                                                                                                                          
            /* Make the new data area */
                                                                                                                          
            new_size = (size_t) (*rdata_len_h + expansion);
                                                                                                                          
            *rdata = (u_int8_t*) MALLOC (new_size);
            if (*rdata==NULL) return VAL_OUT_OF_MEMORY;
                                                                                                                          
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
                                                                                                                          
    return VAL_NO_ERROR;
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
                                    name_n, NS_MAXDNAME))==-1)
        return VAL_INTERNAL_ERROR;
                                                                                                                          
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
                                                                                                                          
    return VAL_NO_ERROR;
}

void lower_name (u_int8_t rdata[], size_t *index)
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
                                                                                                                          
    size_t index = 0;
                                                                                                                          
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
    memcpy (copy_set, rr_set, sizeof(struct rrset_rec));
	copy_set->rrs = (struct val_rrset *) MALLOC (sizeof(struct val_rrset));
	if(copy_set->rrs == NULL) return NULL;
    memcpy (copy_set->rrs, rr_set->rrs, sizeof(struct val_rrset));

    o_length = wire_name_length (rr_set->rrs->val_rrset_name_n);

	if (SR_UNSET != clone_ns(&copy_set->rrs_respondent_server, rr_set->rrs_respondent_server)) {
		FREE(copy_set);
		return NULL;
	}
    copy_set->rrs->val_rrset_data = NULL;
    copy_set->rrs_next = NULL;
    copy_set->rrs->val_rrset_sig = NULL;
    copy_set->rrs->val_rrset_name_n = NULL;
	copy_set->rrs->val_rrset_name_n = (u_int8_t *) MALLOC (o_length);
	if (copy_set->rrs->val_rrset_name_n == NULL) {
		FREE(copy_set);
		return NULL;
	}
	memcpy(copy_set->rrs->val_rrset_name_n, rr_set->rrs->val_rrset_name_n, o_length); 
                                                                                                                     
    /*
        Do an insertion sort of the records in rr_set.  As records are
        copied, convert the domain names to lower case.
    */
                                                                                                                          
    for (orig_rr = rr_set->rrs->val_rrset_data; orig_rr; orig_rr = orig_rr->rr_next)
    {
        /* Copy it into the right form for verification */
        copy_rr = copy_rr_rec (rr_set->rrs->val_rrset_type_h, orig_rr, 1);
                                                                                                                          
        if (copy_rr==NULL) return NULL;
                                                                                                                          
        /* Now, find a place for it */
                                                                                                                          
        link_rr (&copy_set->rrs->val_rrset_data, copy_rr);
    }
	/* Copy the rrsigs also */

    for (orig_rr = rr_set->rrs->val_rrset_sig; orig_rr; orig_rr = orig_rr->rr_next)
    {
        /* Copy it into the right form for verification */
        copy_rr = copy_rr_rec (rr_set->rrs->val_rrset_type_h, orig_rr, 0);
                                                                                                                          
        if (copy_rr==NULL) return NULL;
                                                                                                                          
        /* Now, find a place for it */
                                                                                                                          
        link_rr (&copy_set->rrs->val_rrset_sig, copy_rr);
    }

    return copy_set;
}

