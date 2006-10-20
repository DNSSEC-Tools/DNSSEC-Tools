
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
#include <sys/time.h>

#ifndef NAMESER_HAS_HEADER
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#else
#include "arpa/header.h"
#endif
#endif /* NAMESER_HAS_HEADER */

#include <resolver.h>
#include <validator.h>
#include "val_support.h"

int
labelcmp(const u_int8_t * name1, const u_int8_t * name2)
{
    /*
     * Compare two names, assuming same number of labels in each 
     */
    int             index1 = 0;
    int             index2 = 0;
    int             length1;
    int             length2;
    int             min_len;
    int             ret_val;

    u_int8_t        buffer1[NS_MAXCDNAME];
    u_int8_t        buffer2[NS_MAXCDNAME];
    int             i;

    length1 = (int) name1 ? name1[index1] : 0;
    length2 = (int) name2 ? name2[index2] : 0;
    min_len = (length1 < length2) ? length1 : length2;

    /*
     * Degenerate case - root versus root 
     */
    if (length1 == 0 && length2 == 0)
        return 0;

    /*
     * If the first n bytes are the same, then the length determines
     * the difference - if any 
     */
    if (length1 == 0 || length2 == 0)
        return length1 - length2;

    /*
     * Recurse to try more significant label(s) first 
     */
    ret_val = labelcmp(&name1[length1 + 1], &name2[length2 + 1]);

    /*
     * If there is a difference, propogate that back up the calling tree 
     */
    if (ret_val != 0)
        return ret_val;

    /*
     * Compare this label's first min_len bytes 
     */
    /*
     * Convert to lower case first 
     */
    memcpy(buffer1, &name1[index1 + 1], min_len);
    for (i = 0; i < min_len; i++)
        if (isupper(buffer1[i]))
            buffer1[i] = tolower(buffer1[i]);

    memcpy(buffer2, &name2[index2 + 1], min_len);
    for (i = 0; i < min_len; i++)
        if (isupper(buffer2[i]))
            buffer2[i] = tolower(buffer2[i]);

    ret_val = memcmp(buffer1, buffer2, min_len);

    /*
     * If they differ, propgate that 
     */
    if (ret_val != 0)
        return ret_val;
    /*
     * If the first n bytes are the same, then the length determines
     * the difference - if any 
     */
    return length1 - length2;
}

/*
 * compare DNS wire format names
 *
 * returns
 *      <0 if name1 is before name2
 *       0 if equal
 *      >0 if name1 is after name2
 */
int
namecmp(const u_int8_t * name1, const u_int8_t * name2)
{
    int             labels1 = 1;
    int             labels2 = 1;
    int             index1 = 0;
    int             index2 = 0;
    int             ret_val;
    int             i;

    /*
     * deal w/any null ptrs 
     */
    if (name1 == NULL) {
        if (name2 == NULL)
            return 0;
        else
            return -1;
    } else {
        if (name2 == NULL)
            return 1;
    }

    /*
     * count labels 
     */
    for (; name1[index1]; index1 += (int) name1[index1] + 1)
        labels1++;
    for (; name2[index2]; index2 += (int) name2[index2] + 1)
        labels2++;

    index1 = 0;
    index2 = 0;

    /*
     * find index in longer name where the number of labels is equal 
     */
    if (labels1 > labels2)
        for (i = 0; i < labels1 - labels2; i++)
            index1 += (int) name1[index1] + 1;
    else
        for (i = 0; i < labels2 - labels1; i++)
            index2 += (int) name2[index2] + 1;

    /*
     * compare last N labels 
     */
    ret_val = labelcmp(&name1[index1], &name2[index2]);

    if (ret_val != 0)
        return ret_val;

    /*
     * If one dname is a "proper suffix" of the other,
     * the shorter comes first 
     */
    return labels1 - labels2;
}

#ifdef LIBVAL_NSEC3

/*
 * create the Base 32 Encoding With Extended Hex Alphabet according to
 * rfc3548bis
 */
void
base32hex_encode(u_int8_t * in, u_int8_t inlen, u_int8_t ** out,
                 u_int8_t * outlen)
{
    u_int8_t        base32hex[32] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    u_int8_t       *in_ch, *buf;
    u_int8_t       *out_ch;
    u_int8_t        padbuf[5];
    int             i, rem, extra;

    *out = NULL;
    *outlen = 0;

    if ((in == NULL) || (inlen <= 0))
        return;

    /*
     * outlen = (inlen * 3/5) 
     */
    rem = inlen % 5;
    extra = rem ? (40 - rem) : 0;

    *outlen = inlen + ((inlen * 8 + extra) / 40) * 3;
    *out = (u_int8_t *) MALLOC(*outlen * sizeof(u_int8_t));
    if (*out == NULL) {
        *outlen = 0;
        return;
    }

    memset(*out, 0, *outlen);
    out_ch = *out;

    memset(padbuf, 0, 5);
    in_ch = in;

    while (inlen > 0) {

        if (inlen - 5 < 0) {
            /*
             * pad with zeros 
             */
            i = 0;
            while (inlen) {
                padbuf[i++] = *in_ch;
                in_ch++;
                inlen--;
            }
            buf = padbuf;
        } else {
            /*
             * identify next 40 bits 
             */
            buf = in_ch;
            in_ch += 5;
            inlen -= 5;
        }

        /*
         * There are 40 bits in buf 
         */
        *out_ch = tolower(base32hex[((buf[0] & 0xf8) >> 3)]);
        out_ch++;
        *out_ch =
            tolower(base32hex
                    [((buf[0] & 0x07) << 2) | ((buf[1] & 0xc0) >> 6)]);
        out_ch++;
        *out_ch = tolower(base32hex[((buf[1] & 0x3e) >> 1)]);
        out_ch++;
        *out_ch =
            tolower(base32hex
                    [((buf[1] & 0x01) << 4) | ((buf[2] & 0xf0) >> 4)]);
        out_ch++;
        *out_ch =
            tolower(base32hex
                    [((buf[2] & 0x0f) << 1) | ((buf[3] & 0x80) >> 7)]);
        out_ch++;
        *out_ch = tolower(base32hex[((buf[3] & 0x7c) >> 2)]);
        out_ch++;
        *out_ch =
            tolower(base32hex
                    [((buf[3] & 0x03) << 3) | ((buf[4] & 0xe0) >> 5)]);
        out_ch++;
        *out_ch = tolower(base32hex[(buf[4] & 0x1f)]);
        out_ch++;
    }
}

/*
 * This is a straight copy from labelcmp() 
 */
int
nsec3_order_cmp(u_int8_t * hash1, int length1, u_int8_t * hash2,
                int length2)
{
    u_int8_t        buffer1[NS_MAXCDNAME];
    u_int8_t        buffer2[NS_MAXCDNAME];
    int             i;
    int             min_len;
    int             ret_val;

    min_len = (length1 < length2) ? length1 : length2;

    if (length1 == 0 && length2 == 0)
        return 0;

    /*
     * If the first n bytes are the same, then the length determines
     * the difference - if any 
     */
    if (length1 == 0 || length2 == 0)
        return length1 - length2;


    /*
     * Compare this label's first min_len bytes 
     */
    /*
     * Convert to lower case first 
     */
    memcpy(buffer1, hash1, min_len);
    for (i = 0; i < min_len; i++)
        if (isupper(buffer1[i]))
            buffer1[i] = tolower(buffer1[i]);

    memcpy(buffer2, hash2, min_len);
    for (i = 0; i < min_len; i++)
        if (isupper(buffer2[i]))
            buffer2[i] = tolower(buffer2[i]);

    ret_val = memcmp(buffer1, buffer2, min_len);

    /*
     * If they differ, propgate that 
     */
    if (ret_val != 0)
        return ret_val;
    /*
     * If the first n bytes are the same, then the length determines
     * the difference - if any 
     */
    return length1 - length2;
}
#endif

u_int16_t
wire_name_labels(const u_int8_t * field)
{
    /*
     * Calculates the number of labels in a DNS wire format name 
     */
    u_short         j;
    u_short         l = 0;
    if (field == NULL)
        return 0;

    for (j = 0; field[j] && !(0xc0 & field[j]) && j < NS_MAXCDNAME;
         j += field[j] + 1)
        l++;
    if (field[j])
        j++;
    j++;
    l++;

    if (j > NS_MAXCDNAME)
        return 0;
    else
        return l;
}

u_int16_t
wire_name_length(const u_int8_t * field)
{
    /*
     * Calculates the number of bytes in a DNS wire format name 
     */
    u_short         j;
    if (field == NULL)
        return 0;

    for (j = 0; field[j] && !(0xc0 & field[j]) && j < NS_MAXCDNAME;
         j += field[j] + 1);
    if (field[j])
        j++;
    j++;

    if (j > NS_MAXCDNAME)
        return 0;
    else
        return j;
}


void
res_sq_free_rr_recs(struct rr_rec **rr)
{
    if (rr == NULL)
        return;

    if (*rr) {
        if ((*rr)->rr_rdata)
            FREE((*rr)->rr_rdata);
        if ((*rr)->rr_next)
            res_sq_free_rr_recs(&((*rr)->rr_next));
        FREE(*rr);
        *rr = NULL;
    }
}


void
res_sq_free_rrset_recs(struct rrset_rec **set)
{
    if (set == NULL)
        return;

    if (*set) {
        if ((*set)->rrs_zonecut_n)
            FREE((*set)->rrs_zonecut_n);
        if ((*set)->rrs.val_msg_header) 
            FREE((*set)->rrs.val_msg_header);
        if ((*set)->rrs.val_rrset_name_n)
            FREE((*set)->rrs.val_rrset_name_n);
        if ((*set)->rrs.val_rrset_data)
            res_sq_free_rr_recs(&((*set)->rrs.val_rrset_data));
        if ((*set)->rrs.val_rrset_sig)
            res_sq_free_rr_recs(&((*set)->rrs.val_rrset_sig));
        if ((*set)->rrs_next)
            res_sq_free_rrset_recs(&((*set)->rrs_next));
        FREE(*set);
        *set = NULL;
    }
}


int
add_to_qname_chain(struct qname_chain **qnames, const u_int8_t * name_n)
{
    struct qname_chain *temp;

    if ((qnames == NULL) || (name_n == NULL))
        return VAL_BAD_ARGUMENT;

    temp = (struct qname_chain *) MALLOC(sizeof(struct qname_chain));

    if (temp == NULL)
        return VAL_OUT_OF_MEMORY;

    memcpy(temp->qnc_name_n, name_n, wire_name_length(name_n));

    temp->qnc_next = *qnames;
    *qnames = temp;

    return VAL_NO_ERROR;
}


int
qname_chain_first_name(struct qname_chain *qnames, const u_int8_t * name_n)
{
    struct qname_chain *qc;

    if (qnames == NULL || name_n == NULL)
        return FALSE;

    qc = qnames;
    while (qc != NULL && namecmp(qc->qnc_name_n, name_n) != 0)
        qc = qc->qnc_next;

    return (qc != NULL && qc->qnc_next == NULL);
}

void
free_qname_chain(struct qname_chain **qnames)
{
    if (qnames == NULL || (*qnames) == NULL)
        return;

    if ((*qnames)->qnc_next)
        free_qname_chain(&((*qnames)->qnc_next));

    FREE(*qnames);
    (*qnames) = NULL;
}

void
free_domain_info_ptrs(struct domain_info *di)
{
    if (di == NULL)
        return;

    if (di->di_requested_name_h) {
        FREE(di->di_requested_name_h);
        di->di_requested_name_h = NULL;
    }

    if (di->di_answers)
        res_sq_free_rrset_recs(&di->di_answers);

    if (di->di_proofs)
        res_sq_free_rrset_recs(&di->di_proofs);

    if (di->di_qnames) {
        free_qname_chain(&di->di_qnames);
    }
}

int
is_tail(u_int8_t * full, u_int8_t * tail)
{
    int             f_len = wire_name_length(full);
    int             t_len = wire_name_length(tail);

    if (f_len == t_len) {
        if (f_len)
            return memcmp(full, tail, f_len) == 0;
        else
            return 0;
    }

    if (t_len > f_len)
        return FALSE;

    if (memcmp(&full[f_len - t_len], tail, t_len) == 0) {
        u_int8_t        index = 0;

        while (index < (f_len - t_len)) {
            index += (full[index]) + (u_int8_t) 1;
            if (index == f_len - t_len)
                return TRUE;
        }
    }

    return FALSE;
}

/*
 * make sure that this is the correct nxt, rrsig combination (both from parent, or both from child) 
 */
int
nsec_sig_match(u_int8_t * owner, u_int8_t * next, u_int8_t * signer)
{
    int             o_len = wire_name_length(owner);
    int             s_len = wire_name_length(signer);

    if (o_len == s_len && memcmp(signer, owner, o_len) == 0)
        return (is_tail(next, signer));
    else
        return (is_tail(next, signer) && !is_tail(next, owner));
}


int
add_to_set(struct rrset_rec *rr_set, u_int16_t rdata_len_h,
           u_int8_t * rdata)
{
    struct rr_rec  *rr;

    if ((rr_set == NULL) || (rdata == NULL) || (rdata_len_h == 0))
        return VAL_BAD_ARGUMENT;

    /*
     * Make sure we got the memory for it 
     */
    rr = (struct rr_rec *) MALLOC(sizeof(struct rr_rec));
    if (rr == NULL)
        return VAL_OUT_OF_MEMORY;

    rr->rr_rdata = (u_int8_t *) MALLOC(rdata_len_h);
    if (rr->rr_rdata == NULL) {
        free(rr);
        return VAL_OUT_OF_MEMORY;
    }

    /*
     * Add it to the end of the current list of RR's 
     */
    if (rr_set->rrs.val_rrset_data == NULL) {
        rr_set->rrs.val_rrset_data = rr;
    } else {
        struct rr_rec  *tmp_rr;
        tmp_rr = rr_set->rrs.val_rrset_data;
        while (tmp_rr->rr_next)
            tmp_rr = tmp_rr->rr_next;
        tmp_rr->rr_next = rr;
    }


    /*
     * Insert the data, copying the rdata pointer 
     */
    rr->rr_rdata_length_h = rdata_len_h;
    memcpy(rr->rr_rdata, rdata, rdata_len_h);
    rr->rr_status = VAL_A_UNSET;
    rr->rr_next = NULL;

    return VAL_NO_ERROR;
}

int
add_as_sig(struct rrset_rec *rr_set, u_int16_t rdata_len_h,
           u_int8_t * rdata)
{
    struct rr_rec  *rr;

    if ((rr_set == NULL) || (rdata == NULL) || (rdata_len_h == 0))
        return VAL_BAD_ARGUMENT;

    /*
     * Make sure we got the memory for it 
     */
    rr = (struct rr_rec *) MALLOC(sizeof(struct rr_rec));
    if (rr == NULL)
        return VAL_OUT_OF_MEMORY;

    rr->rr_rdata = (u_int8_t *) MALLOC(rdata_len_h);
    if (rr->rr_rdata == NULL) {
        free(rr);
        return VAL_OUT_OF_MEMORY;
    }

    if (rr_set->rrs.val_rrset_sig == NULL) {
        rr_set->rrs.val_rrset_sig = rr;
    } else {
        /*
         * If this code is executed, then there is a problem brewing.
         * It will be caught in pre_verify to keep the code level.
         */
        struct rr_rec  *tmp_rr;
        tmp_rr = rr_set->rrs.val_rrset_sig;
        while (tmp_rr->rr_next)
            tmp_rr = tmp_rr->rr_next;
        tmp_rr->rr_next = rr;
    }

    /*
     * Insert the data, copying the rdata pointer 
     */
    rr->rr_rdata_length_h = rdata_len_h;
    memcpy(rr->rr_rdata, rdata, rdata_len_h);
    rr->rr_status = VAL_A_UNSET;
    rr->rr_next = NULL;

    return VAL_NO_ERROR;
}

int
init_rr_set(struct rrset_rec *new_set, u_int8_t * name_n, 
            u_int16_t type_h, u_int16_t set_type_h, 
            u_int16_t class_h, u_int32_t ttl_h, 
            u_int8_t * hptr, int from_section, 
            int authoritive_answer,
            struct name_server *respondent_server)
{
    int             name_len = wire_name_length(name_n);
    struct timeval  tv;

    if ((new_set == NULL) || (name_n == NULL))
        return VAL_BAD_ARGUMENT;

    if (new_set->rrs.val_rrset_name_n != NULL)
        /*
         * This has already been initialized 
         */
        return VAL_NO_ERROR;

    /*
     * Initialize it 
     */
    new_set->rrs.val_rrset_name_n = (u_int8_t *) MALLOC(name_len * sizeof(u_int8_t));
    if (new_set->rrs.val_rrset_name_n == NULL)
        return VAL_OUT_OF_MEMORY;

	if (hptr) {
		new_set->rrs.val_msg_header = (u_int8_t *)MALLOC(sizeof(HEADER) * sizeof(u_int8_t)); 
		if (new_set->rrs.val_msg_header == NULL) {
			FREE(new_set->rrs.val_rrset_name_n);
			new_set->rrs.val_rrset_name_n = NULL;
			return VAL_OUT_OF_MEMORY;
		}
		memcpy(new_set->rrs.val_msg_header, hptr, sizeof(HEADER));
		new_set->rrs.val_msg_headerlen = sizeof(HEADER); 
	}
	else {
		new_set->rrs.val_msg_header = NULL;
		new_set->rrs.val_msg_headerlen = 0;
	}
                                                                                                                          
    memcpy(new_set->rrs.val_rrset_name_n, name_n, name_len);
    new_set->rrs.val_rrset_type_h = set_type_h;
    new_set->rrs.val_rrset_class_h = class_h;
    new_set->rrs.val_rrset_ttl_h = ttl_h;
    if (0 == gettimeofday(&tv,NULL)) {
        new_set->rrs.val_rrset_ttl_x = tv.tv_sec + ttl_h;
    }
    else
        new_set->rrs.val_rrset_ttl_x = 0;
    new_set->rrs.val_rrset_data = NULL;
    new_set->rrs.val_rrset_sig = NULL;

    if (respondent_server == NULL) {
        new_set->rrs.val_rrset_server = NULL;
    } else {
        new_set->rrs.val_rrset_server = 
            (struct sockaddr *) MALLOC (sizeof (struct sockaddr_storage));
        if (new_set->rrs.val_rrset_server == NULL) { 
			FREE(new_set->rrs.val_rrset_name_n);
			new_set->rrs.val_rrset_name_n = NULL;
            return VAL_OUT_OF_MEMORY;
        }
        memcpy(new_set->rrs.val_rrset_server,
               respondent_server->ns_address,
               sizeof(struct sockaddr_storage));
    }
 
    new_set->rrs_next = NULL;

    /*
     * Set the credibility 
     */
    if (from_section == VAL_FROM_ANSWER)
        new_set->rrs_cred = authoritive_answer ?
            SR_CRED_AUTH_ANS : SR_CRED_NONAUTH_ANS;
    else if (from_section == VAL_FROM_AUTHORITY)
        new_set->rrs_cred = authoritive_answer ?
            SR_CRED_AUTH_AUTH : SR_CRED_NONAUTH_AUTH;
    else if (from_section == VAL_FROM_ADDITIONAL)
        new_set->rrs_cred = authoritive_answer ?
            SR_CRED_AUTH_ADD : SR_CRED_NONAUTH_ADD;
    else
        new_set->rrs_cred = SR_CRED_UNSET;

    /*
     * Set the source section 
     */

    new_set->rrs.val_rrset_section = from_section;

    /*
     * Can't set the answer kind yet - need the cnames figured out first 
     */

    new_set->rrs_ans_kind = SR_ANS_UNSET;

    return VAL_NO_ERROR;
}

#define IS_THE_ONE(a,n,l,t,s,c,r) \
(                                                                             \
    a &&                                     /* If there's a record */        \
    (                                                                         \
        (s != ns_t_nsec &&                    /* If the type is not nxt: */    \
        a->rrs.val_rrset_type_h == s &&                    /* does type match */        \
        a->rrs.val_rrset_class_h == c &&                   /* does class match */       \
        memcmp (a->rrs.val_rrset_name_n,n,l)==0            /* does name match */        \
        )                                                                     \
        ||                                   /* or */                         \
        (s == ns_t_nsec &&														\
		 t == ns_t_rrsig &&                    /* if it is a sig(nxt) */        \
        a->rrs.val_rrset_data!=NULL &&                     /* is there data here */     \
        a->rrs.val_rrset_class_h == c &&                   /* does class match */       \
		a->rrs.val_rrset_type_h == ns_t_nsec &&													\
        memcmp (a->rrs.val_rrset_name_n,n,l)==0 &&         /* does name match */        \
        nsec_sig_match (n,a->rrs.val_rrset_data->rr_rdata,&r[SIGNBY])                    \
                                                 /* does sig match nxt */     \
        )                                                                     \
        ||                                   /* or */                         \
        (s == ns_t_nsec &&														\
        t == ns_t_nsec &&                    /* if it is a nxt */             \
        a->rrs.val_rrset_sig!=NULL &&                      /* is there a sig here */    \
        a->rrs.val_rrset_class_h == c &&                   /* does class match */       \
		a->rrs.val_rrset_type_h == ns_t_nsec &&													\
        memcmp (a->rrs.val_rrset_name_n,n,l)==0 &&         /* does name match */        \
        nsec_sig_match (n,r,&a->rrs.val_rrset_sig->rr_rdata[SIGNBY])                     \
                                                 /* does sig match nxt */     \
        )                                                                     \
    )                                                                         \
)

struct rrset_rec *
find_rr_set(struct name_server *respondent_server,
            struct rrset_rec **the_list,
            u_int8_t * name_n,
            u_int16_t type_h,
            u_int16_t set_type_h,
            u_int16_t class_h,
            u_int32_t ttl_h,
            u_int8_t * hptr,
            u_int8_t * rdata_n,
            int from_section, int authoritive_answer, u_int8_t * zonecut_n)
{
    struct rrset_rec *tryit;
    struct rrset_rec *last;
    struct rrset_rec *new_one;
    int             name_len = wire_name_length(name_n);

    if ((the_list == NULL) || (name_n == NULL))
        return NULL;

    /*
     * Search through the list for a matching record 
     */
    tryit = *the_list;
    last = NULL;

    while (tryit) {
        /*
         * make sure this is the correct nsec and rrsig combination 
         */
        /*
         * we don't need to make this check for NSEC3 because the names
         * will be different in the parent and the child.
         * For example, the delegation a.example.com will appear as
         * <hash>.example.com in the parent zone and
         * <hash>.a.example.com in the child zone
         */
        if (IS_THE_ONE(tryit, name_n, name_len, type_h, set_type_h,
                       class_h, rdata_n))
            break;


        last = tryit;
        tryit = tryit->rrs_next;
    }
    /*
     * If no record matches, then create a new one 
     */
    if (tryit == NULL) {
        new_one = (struct rrset_rec *) MALLOC(sizeof(struct rrset_rec));
        if (new_one == NULL)
            return NULL;
        memset(new_one, 0, sizeof(struct rrset_rec));

        /*
         * If this is the first ever record, change *the_list 
         */
        if (last == NULL)
            *the_list = new_one;
        else
            last->rrs_next = new_one;

        if (zonecut_n != NULL) {
            int             len = wire_name_length(zonecut_n);
            new_one->rrs_zonecut_n =
                (u_int8_t *) MALLOC(len * sizeof(u_int8_t));
            if (new_one->rrs_zonecut_n == NULL) {
                res_sq_free_rrset_recs(the_list);
                return NULL;
            }
            memcpy(new_one->rrs_zonecut_n, zonecut_n, len);
        } else
            new_one->rrs_zonecut_n = NULL;

        if ((init_rr_set(new_one, name_n, type_h, set_type_h,
                         class_h, ttl_h, hptr, from_section,
                         authoritive_answer, respondent_server))
            != VAL_NO_ERROR) {
            res_sq_free_rrset_recs(the_list);
            return NULL;
        }
    } else {
        new_one = tryit;
        /*
         * Make sure it has the lowest ttl (doesn't really matter) 
         */
        if (new_one->rrs.val_rrset_ttl_h > ttl_h)
            new_one->rrs.val_rrset_ttl_h = ttl_h;
    }

    /*
     * In all cases, return the value of new_one 
     */
    return new_one;
}


int
check_label_count(struct rrset_rec *the_set,
                  struct rr_rec *the_sig, int *is_a_wildcard)
{
    u_int8_t        owner_labels;;
    u_int8_t        sig_labels;

    if ((the_set == NULL) || (the_sig == NULL) || (is_a_wildcard == NULL))
        return VAL_BAD_ARGUMENT;

    owner_labels = wire_name_labels(the_set->rrs.val_rrset_name_n);
    sig_labels = the_sig->rr_rdata[RRSIGLABEL] + 1;

    if (sig_labels > owner_labels)
        return VAL_BAD_ARGUMENT; 

    *is_a_wildcard = (owner_labels - sig_labels);

    return VAL_NO_ERROR;
}


int
prepare_empty_nxdomain(struct rrset_rec **answers,
                       const u_int8_t * query_name_n,
                       u_int16_t query_type_h, u_int16_t query_class_h)
{
    size_t          length = wire_name_length(query_name_n);

    if (answers == NULL)
        return VAL_BAD_ARGUMENT;

    if (length == 0)
        return VAL_INTERNAL_ERROR;

    *answers = (struct rrset_rec *) MALLOC(sizeof(struct rrset_rec));
    if (*answers == NULL)
        return VAL_OUT_OF_MEMORY;

    (*answers)->rrs_zonecut_n = NULL;
    (*answers)->rrs.val_rrset_name_n = (u_int8_t *) MALLOC(length);

    if ((*answers)->rrs.val_rrset_name_n == NULL) {
        FREE(*answers);
        *answers = NULL;
        return VAL_OUT_OF_MEMORY;
    }

    memcpy((*answers)->rrs.val_rrset_name_n, query_name_n, length);
    (*answers)->rrs.val_rrset_type_h = query_type_h;
    (*answers)->rrs.val_rrset_class_h = query_class_h;
    (*answers)->rrs.val_rrset_ttl_h = 0;
    (*answers)->rrs_cred = SR_CRED_UNSET;
    (*answers)->rrs.val_rrset_section = VAL_FROM_UNSET;
    (*answers)->rrs.val_rrset_data = NULL;
    (*answers)->rrs.val_rrset_sig = NULL;
    (*answers)->rrs_next = NULL;

    return VAL_NO_ERROR;
}

int
decompress(u_int8_t ** rdata,
           u_int8_t * response,
           int rdata_index,
           u_int8_t * end, u_int16_t type_h, u_int16_t * rdata_len_h)
{
    u_int8_t        expanded_name[NS_MAXCDNAME];
    u_int8_t        other_expanded_name[NS_MAXCDNAME];
    u_int8_t        prefix[6];
    int             p_index = 0;
    size_t          new_size;
    int             working_index = rdata_index;
    int             other_name_length = 0;
    int             name_length = 0;
    int             insert_index = 0;
    int             working_increment;
    int             expansion = 0;

    if ((rdata == NULL) || (response == NULL) || (rdata_len_h == NULL))
        return VAL_BAD_ARGUMENT;

    switch (type_h) {
        /*
         * The first group has no domain names to convert 
         */

    case ns_t_nsap:
    case ns_t_eid:
    case ns_t_nimloc:
    case ns_t_dnskey:
    case ns_t_aaaa:
    case ns_t_loc:
    case ns_t_atma:
    case ns_t_a:
    case ns_t_wks:
    case ns_t_hinfo:
    case ns_t_txt:
    case ns_t_x25:
    case ns_t_isdn:
    case ns_t_ds:
    default:
        new_size = (size_t) * rdata_len_h;
        *rdata = (u_int8_t *) MALLOC(new_size);
        if (*rdata == NULL)
            return VAL_OUT_OF_MEMORY;

        memcpy(&(*rdata)[insert_index], &response[rdata_index], new_size);
        *rdata_len_h = *rdata_len_h;    /* No change */
        break;

        /*
         * The next group starts with one or two domain names 
         */

    case ns_t_soa:
    case ns_t_minfo:
    case ns_t_rp:

        working_increment = ns_name_unpack(response, end,
                                           &response[working_index],
                                           other_expanded_name,
                                           sizeof(other_expanded_name));

        if (working_increment < 0)
            return VAL_INTERNAL_ERROR;

        working_index += working_increment;
        other_name_length = wire_name_length(other_expanded_name);
        expansion += other_name_length - working_increment;

        /*
         * fall through 
         */
    case ns_t_ns:
    case ns_t_cname:
    case ns_t_mb:
    case ns_t_mg:
    case ns_t_mr:
    case ns_t_ptr:
    case ns_t_nsec:

        working_increment = ns_name_unpack(response, end,
                                           &response[working_index],
                                           expanded_name,
                                           sizeof(expanded_name));
        if (working_increment < 0)
            return VAL_INTERNAL_ERROR;

        working_index += working_increment;
        name_length = wire_name_length(expanded_name);
        expansion += name_length - working_increment;

        /*
         * Make the new data area 
         */

        new_size = (size_t) (*rdata_len_h + expansion);

        *rdata = (u_int8_t *) MALLOC(new_size);
        if (*rdata == NULL)
            return VAL_OUT_OF_MEMORY;

        /*
         * Copy in the names 
         */

        memcpy(&(*rdata)[insert_index], other_expanded_name,
               other_name_length);
        insert_index += other_name_length;

        memcpy(&(*rdata)[insert_index], expanded_name, name_length);
        insert_index += name_length;

        /*
         * Copy any remaining data 
         */

        memcpy(&(*rdata)[insert_index], &response[working_index],
               *rdata_len_h + expansion - other_name_length - name_length);

        *rdata_len_h += expansion;

        break;

        /*
         * The following group ends with one or two domain names 
         */
    case ns_t_srv:

        memcpy(&prefix[p_index], &response[working_index],
               2 * sizeof(u_int16_t));
        working_index += 2 * sizeof(u_int16_t);
        p_index += 2 * sizeof(u_int16_t);
        /*
         * fall through 
         */

    case ns_t_rt:
    case ns_t_mx:
    case ns_t_afsdb:
    case ns_t_px:

        memcpy(&prefix[p_index], &response[working_index],
               sizeof(u_int16_t));
        working_index += sizeof(u_int16_t);
        p_index += sizeof(u_int16_t);

        working_increment = ns_name_unpack(response, end,
                                           &response[working_index],
                                           expanded_name,
                                           sizeof(expanded_name));
        if (working_increment < 0)
            return VAL_INTERNAL_ERROR;

        working_index += working_increment;
        name_length = wire_name_length(expanded_name);
        expansion += name_length - working_increment;

        if (type_h == ns_t_px) {
            working_increment = ns_name_unpack(response, end,
                                               &response[working_index],
                                               other_expanded_name,
                                               sizeof(other_expanded_name));
            if (working_increment < 0)
                return VAL_INTERNAL_ERROR;

            working_index += working_increment;
            other_name_length = wire_name_length(other_expanded_name);
            expansion += other_name_length - working_increment;
        }

        /*
         * Make the new data area 
         */

        new_size = (size_t) (*rdata_len_h + expansion);

        *rdata = (u_int8_t *) MALLOC(new_size);
        if (*rdata == NULL)
            return VAL_OUT_OF_MEMORY;

        /*
         * Copy in the prefix 
         */
        memcpy(&*rdata[insert_index], prefix, p_index);
        insert_index += p_index;

        /*
         * Copy in the names 
         */

        memcpy(&(*rdata)[insert_index], expanded_name, name_length);
        insert_index += name_length;

        memcpy(&(*rdata)[insert_index], other_expanded_name,
               other_name_length);
        insert_index += other_name_length;

        *rdata_len_h += expansion;

        break;

        /*
         * The special case - the SIG record 
         */
    case ns_t_rrsig:

        working_increment = ns_name_unpack(response, end,
                                           &response[working_index +
                                                     SIGNBY],
                                           expanded_name,
                                           sizeof(expanded_name));
        if (working_increment < 0)
            return VAL_INTERNAL_ERROR;

        name_length = wire_name_length(expanded_name);
        expansion += name_length - working_increment;

        /*
         * Make the new data area 
         */

        new_size = (size_t) (*rdata_len_h + expansion);

        *rdata = (u_int8_t *) MALLOC(new_size);
        if (*rdata == NULL)
            return VAL_OUT_OF_MEMORY;

        memcpy(&(*rdata)[insert_index], &response[working_index], SIGNBY);
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

int
extract_from_rr(u_int8_t * response,
                int *response_index,
                u_int8_t * end,
                u_int8_t * name_n,
                u_int16_t * type_h,
                u_int16_t * set_type_h,
                u_int16_t * class_h,
                u_int32_t * ttl_h,
                u_int16_t * rdata_length_h, int *rdata_index)
{
    u_int16_t       net_short;
    u_int32_t       net_int;
    int             ret_val;

    if ((response == NULL) || (response_index == NULL) || (type_h == NULL)
        || (class_h == NULL) || (ttl_h == NULL) || (rdata_length_h == NULL)
        || (set_type_h == NULL))
        return VAL_BAD_ARGUMENT;

    /*
     * Extract the uncompressed (unpacked) domain name in protocol format 
     */
    if ((ret_val =
         ns_name_unpack(response, end, &response[*response_index], name_n,
                        NS_MAXCDNAME)) == -1)
        return VAL_INTERNAL_ERROR;

    *response_index += ret_val;

    /*
     * Extract the type, and save it in host format 
     */
    memcpy(&net_short, &response[*response_index], sizeof(u_int16_t));
    *type_h = ntohs(net_short);
    *response_index += sizeof(u_int16_t);

    /*
     * Extract the class, and save it in host format 
     */
    memcpy(&net_short, &response[*response_index], sizeof(u_int16_t));
    *class_h = ntohs(net_short);
    *response_index += sizeof(u_int16_t);

    /*
     * Extract the ttl, and save it in host format 
     */
    memcpy(&net_int, &response[*response_index], sizeof(u_int32_t));
    *ttl_h = ntohl(net_int);
    *response_index += sizeof(u_int32_t);    

    /*
     * Extract the rdata length, and save it in host format 
     */
    memcpy(&net_short, &response[*response_index], sizeof(u_int16_t));
    *rdata_length_h = ntohs(net_short);
    *response_index += sizeof(u_int16_t);

    *rdata_index = *response_index;

    /*
     * If this is a signature, then get the type covered to serve as
     * the *set_type_h.  If this is not a signature, then set the *set_type_h
     * to *type_h.
     * 
     * Don't advance the response_index yet, it will be done in the next
     * step.
     */

    if (*type_h == ns_t_rrsig) {
        /*
         * Extract the set type, and save it in host format 
         */
        memcpy(&net_short, &response[*response_index], sizeof(u_int16_t));
        *set_type_h = ntohs(net_short);
    } else
        *set_type_h = *type_h;

    *response_index += *rdata_length_h;

    return VAL_NO_ERROR;
}

void
lower_name(u_int8_t rdata[], size_t * index)
{
    int             length;

    if ((rdata == NULL) || (index == NULL))
        return;

    /*
     * Convert the upper case characters in a domain name to lower case 
     */

    length = wire_name_length(&rdata[(*index)]);

    while ((*index) < length) {
        rdata[(*index)] = tolower(rdata[(*index)]);
        (*index)++;
    }
}

void
lower(u_int16_t type_h, u_int8_t * rdata, int len)
{
    /*
     * Convert the case of any domain name to lower in the RDATA section 
     */

    size_t          index = 0;

    if (rdata == NULL)
        return;

    switch (type_h) {
        /*
         * These RR's have no domain name in them 
         */

    case ns_t_nsap:
    case ns_t_eid:
    case ns_t_nimloc:
    case ns_t_dnskey:
    case ns_t_aaaa:
    case ns_t_loc:
    case ns_t_atma:
    case ns_t_a:
    case ns_t_wks:
    case ns_t_hinfo:
    case ns_t_txt:
    case ns_t_x25:
    case ns_t_isdn:
    case ns_t_ds:
    default:

        return;

        /*
         * These RR's have two domain names at the start 
         */

    case ns_t_soa:
    case ns_t_minfo:
    case ns_t_rp:

        lower_name(rdata, &index);
        /*
         * fall through 
         */


        /*
         * These have one name (and are joined by the code above) 
         */

    case ns_t_ns:
    case ns_t_cname:
    case ns_t_mb:
    case ns_t_mg:
    case ns_t_mr:
    case ns_t_ptr:
    case ns_t_nsec:

        lower_name(rdata, &index);

        return;

        /*
         * These RR's end in one or two domain names 
         */

    case ns_t_srv:

        index = 4;              /* SRV has three preceeding 16 bit quantities */

    case ns_t_rt:
    case ns_t_mx:
    case ns_t_afsdb:
    case ns_t_px:

        index += 2;             /* Pass the 16 bit quatity prior to the name */

        lower_name(rdata, &index);

        /*
         * Get the second tail name (only in PX records) 
         */
        if (type_h == ns_t_px)
            lower_name(rdata, &index);

        return;

        /*
         * The last case is RR's with names in the middle. 
         */
        /*
         * Note: this code is never used as SIG's are the only record in
         * this case.  SIG's are not signed, so they never are run through
         * this code.  This is left here in case other RR's are defined in
         * this unfortunate (for them) manner.
         */
    case ns_t_rrsig:

        index = SIGNBY;

        lower_name(rdata, &index);

        return;
    }
}



struct rr_rec  *
copy_rr_rec(u_int16_t type_h, struct rr_rec *r, int dolower)
{
    /*
     * Make a copy of an RR, lowering the case of any contained
     * domain name in the RR section.
     */
    struct rr_rec  *the_copy;

    if (r == NULL)
        return NULL;
    the_copy = (struct rr_rec *) MALLOC(sizeof(struct rr_rec));

    if (the_copy == NULL)
        return NULL;

    the_copy->rr_rdata_length_h = r->rr_rdata_length_h;
    the_copy->rr_rdata = (u_int8_t *) MALLOC(the_copy->rr_rdata_length_h);

    if (the_copy->rr_rdata == NULL) {
        FREE(the_copy);
        return NULL;
    }

    memcpy(the_copy->rr_rdata, r->rr_rdata, r->rr_rdata_length_h);

    if (dolower)
        lower(type_h, the_copy->rr_rdata, the_copy->rr_rdata_length_h);

    the_copy->rr_status = r->rr_status;
    the_copy->rr_next = NULL;

    //
    // xxx-audit: uninitialized member in structure
    //     appropriate value (or 0?) for rr_status
    //
    return the_copy;
}

/*
 * copy the entire list of rr_recs
 *
 * see copy_rr_rec() to copy a single rr_rec
 */
struct rr_rec *
copy_rr_rec_list(u_int16_t type_h, struct rr_rec *o_rr, int dolower)
{
    struct rr_rec *n_rr, *n_head;

    if (NULL == o_rr)
        return NULL;

    /*
     * copy list head
     */
    n_head = n_rr = copy_rr_rec(type_h, o_rr, dolower);
    if (NULL == n_rr)
        return NULL;

    /*
     * loop over list and copy each record
     */
    while (o_rr->rr_next) {
        n_rr->rr_next = copy_rr_rec(type_h, o_rr->rr_next, dolower);
        if (NULL == n_rr->rr_next)
            break;
        
        o_rr = o_rr->rr_next;
        n_rr = n_rr->rr_next;
    }

    return n_head;
}

#define INSERTED    1
#define DUPLICATE   -1
int
link_rr(struct rr_rec **cs, struct rr_rec *cr)
{
    /*
     * Insert a copied RR into the set being prepared for signing.  This
     * is an implementation of an insertion sort.
     */
    int             ret_val;
    int             length;
    struct rr_rec  *temp_rr;

    if (cs == NULL)
        return 0;

    if (*cs == NULL) {
        *cs = cr;
        return INSERTED;
    } else {
        length = (*cs)->rr_rdata_length_h < cr->rr_rdata_length_h ?
            (*cs)->rr_rdata_length_h : cr->rr_rdata_length_h;

        ret_val = memcmp((*cs)->rr_rdata, cr->rr_rdata, length);

        if (ret_val == 0
            && (*cs)->rr_rdata_length_h == cr->rr_rdata_length_h) {
            /*
             * cr is a copy of an existing record, forget it... 
             */
            FREE(cr->rr_rdata);
            FREE(cr);
            return DUPLICATE;
        } else if (ret_val > 0
                   || (ret_val == 0 && length == cr->rr_rdata_length_h)) {
            cr->rr_next = *cs;
            *cs = cr;
            return INSERTED;
        } else {
            temp_rr = *cs;

            if (temp_rr->rr_next == NULL) {
                temp_rr->rr_next = cr;
                cr->rr_next = NULL;
                return INSERTED;
            }
            while (temp_rr->rr_next) {
                length = temp_rr->rr_next->rr_rdata_length_h <
                    cr->rr_rdata_length_h ?
                    temp_rr->rr_next->rr_rdata_length_h :
                    cr->rr_rdata_length_h;

                ret_val = memcmp(temp_rr->rr_next->rr_rdata, cr->rr_rdata,
                                 length);
                if (ret_val == 0 &&
                    temp_rr->rr_next->rr_rdata_length_h ==
                    cr->rr_rdata_length_h) {
                    /*
                     * cr is a copy of an existing record, forget it... 
                     */
                    FREE(cr->rr_rdata);
                    FREE(cr);
                    return DUPLICATE;
                } else if (ret_val > 0
                           || (ret_val == 0
                               && length == cr->rr_rdata_length_h)) {
                    /*
                     * We've found a home for the record 
                     */
                    cr->rr_next = temp_rr->rr_next;
                    temp_rr->rr_next = cr;
                    return INSERTED;
                }
                temp_rr = temp_rr->rr_next;
            }

            /*
             * If we've gone this far, add the record to the end of the list 
             */

            temp_rr->rr_next = cr;
            cr->rr_next = NULL;
            return INSERTED;
        }
    }
}

struct rrset_rec *
copy_rrset_rec(struct rrset_rec *rr_set)
{
    struct rrset_rec *copy_set;
    struct rr_rec  *orig_rr;
    struct rr_rec  *copy_rr;
    size_t          o_length;

    if (rr_set == NULL)
        return NULL;

    copy_set = (struct rrset_rec *) MALLOC(sizeof(struct rrset_rec));
    if (copy_set == NULL)
        return NULL;
	memset(copy_set, 0, sizeof(struct rrset_rec));

	if (rr_set->rrs_zonecut_n != NULL) {
		int len = wire_name_length(rr_set->rrs_zonecut_n);
		copy_set->rrs_zonecut_n = (u_int8_t *) MALLOC (len * sizeof(u_int8_t));
		if (copy_set->rrs_zonecut_n == NULL) {
			FREE(copy_set);
			return NULL;
		}
		memcpy(copy_set->rrs_zonecut_n, rr_set->rrs_zonecut_n, len);
	}

    copy_set->rrs_cred = SR_CRED_UNSET;
    copy_set->rrs_ans_kind = SR_ANS_UNSET;
    copy_set->rrs_next = NULL;

	/* Copy the val_rrset members */
	if (rr_set->rrs.val_msg_header) {
		copy_set->rrs.val_msg_headerlen = rr_set->rrs.val_msg_headerlen;
		copy_set->rrs.val_msg_header = (u_int8_t *) MALLOC (rr_set->rrs.val_msg_headerlen * sizeof(u_int8_t));
		if (copy_set->rrs.val_msg_header == NULL) {
			goto err;
		}
		memcpy(copy_set->rrs.val_msg_header, rr_set->rrs.val_msg_header, rr_set->rrs.val_msg_headerlen);
	}

	if (rr_set->rrs.val_rrset_name_n) {
    	o_length = wire_name_length (rr_set->rrs.val_rrset_name_n);
		copy_set->rrs.val_rrset_name_n = (u_int8_t *) MALLOC (o_length);
		if (copy_set->rrs.val_rrset_name_n == NULL) {
			goto err;
		}
		memcpy(copy_set->rrs.val_rrset_name_n, rr_set->rrs.val_rrset_name_n, o_length);
	}

	copy_set->rrs.val_rrset_class_h = rr_set->rrs.val_rrset_class_h;
	copy_set->rrs.val_rrset_type_h = rr_set->rrs.val_rrset_type_h;
	copy_set->rrs.val_rrset_ttl_h = rr_set->rrs.val_rrset_ttl_h;
	copy_set->rrs.val_rrset_ttl_x = rr_set->rrs.val_rrset_ttl_x;
	copy_set->rrs.val_rrset_section = rr_set->rrs.val_rrset_section;
	
    copy_set->rrs.val_rrset_data = NULL;
    copy_set->rrs.val_rrset_sig = NULL;
    /*
     * Do an insertion sort of the records in rr_set.  As records are
     * copied, convert the domain names to lower case.
     */

    for (orig_rr = rr_set->rrs.val_rrset_data; orig_rr;
         orig_rr = orig_rr->rr_next) {
        /*
         * Copy it into the right form for verification 
         */
        copy_rr = copy_rr_rec(rr_set->rrs.val_rrset_type_h, orig_rr, 1);

        if (copy_rr == NULL) {
            goto err;
        }

        /*
         * Now, find a place for it 
         */

        link_rr(&copy_set->rrs.val_rrset_data, copy_rr);
    }
    /*
     * Copy the rrsigs also 
     */

    for (orig_rr = rr_set->rrs.val_rrset_sig; orig_rr;
         orig_rr = orig_rr->rr_next) {
        /*
         * Copy it into the right form for verification 
         */
        copy_rr = copy_rr_rec(rr_set->rrs.val_rrset_type_h, orig_rr, 0);

        if (copy_rr == NULL) {
            goto err;
        }

        /*
         * Now, find a place for it 
         */

        link_rr(&copy_set->rrs.val_rrset_sig, copy_rr);
    }

    /* Copy respondent server information */
    copy_set->rrs.val_rrset_server = 
        (struct sockaddr *) MALLOC (sizeof (struct sockaddr_storage));
    if (copy_set->rrs.val_rrset_server == NULL) {
        goto err;
    }
    memcpy(copy_set->rrs.val_rrset_server, rr_set->rrs.val_rrset_server,
            sizeof(struct sockaddr_storage)); 
 
    return copy_set;

err:
	res_sq_free_rrset_recs(&copy_set);
	return NULL;
}
