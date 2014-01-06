
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
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#include "validator-internal.h"

#include "val_support.h"

u_char * 
namename(u_char * big_name, u_char * little_name)
{
    u_char *p = big_name;
    
    if (!big_name || !little_name)
        return NULL;

    /* if the name only consists of the root, move to the last label */
    if (*little_name == '\0') {
        size_t d = wire_name_length(p);
        if (d >= 1)
            return p+d-1;
        return NULL;
    }
    
    while (*p != '\0') {
        int d = namecmp(p, little_name);
        if (d == 0) {
            return p;
        }
        else if (d < 0)
            break; 
        p = p + p[0] + 1;
    }

    return NULL;
}


#ifdef LIBVAL_NSEC3

/*
 * create the Base 32 Encoding With Extended Hex Alphabet according to
 * rfc3548bis
 */
void
base32hex_encode(u_char * in, size_t inlen, u_char ** out,
                 size_t * outlen)
{
    u_char        base32hex[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    u_char       *in_ch, *buf;
    u_char       *out_ch;
    u_char        padbuf[5];
    size_t        i, rem, extra;
    int           len = inlen;

    *out = NULL;
    *outlen = 0;

    if ((in == NULL) || (inlen == 0))
        return;

    /*
     * outlen = (inlen * 3/5) 
     */
    rem = inlen % 5;
    extra = rem ? (40 - rem) : 0;

    *outlen = inlen + ((inlen * 8 + extra) / 40) * 3;
    *out = (u_char *) MALLOC(*outlen * sizeof(u_char));
    if (*out == NULL) {
        *outlen = 0;
        return;
    }

    memset(*out, 0, *outlen);
    out_ch = *out;

    memset(padbuf, 0, 5);
    in_ch = in;

    len = inlen;
    while (len > 0) {

        if (len - 5 < 0) {
            /*
             * pad with zeros 
             */
            i = 0;
            while (len > 0) {
                padbuf[i++] = *in_ch;
                in_ch++;
                len--;
            }
            buf = padbuf;
        } else {
            /*
             * identify next 40 bits 
             */
            buf = in_ch;
            in_ch += 5;
            len -= 5;
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

#endif

size_t
wire_name_labels(const u_char * field)
{
    /*
     * Calculates the number of labels in a DNS wire format name 
     */
    size_t   j;
    size_t   l = 0;
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

void
res_sq_free_rr_recs(struct rrset_rr **rr)
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
        if ((*set)->rrs_name_n)
            FREE((*set)->rrs_name_n);
        if ((*set)->rrs_server)
            FREE((*set)->rrs_server);
        if ((*set)->rrs_data)
            res_sq_free_rr_recs(&((*set)->rrs_data));
        if ((*set)->rrs_sig)
            res_sq_free_rr_recs(&((*set)->rrs_sig));
        if ((*set)->rrs_next)
            res_sq_free_rrset_recs(&((*set)->rrs_next));
        FREE(*set);
        *set = NULL;
    }
}


int
add_to_qname_chain(struct qname_chain **qnames, const u_char * name_n)
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
name_in_qname_chain(struct qname_chain *qnames, const u_char * name_n)
{
    struct qname_chain *qc;

    if (qnames == NULL || name_n == NULL)
        return FALSE;

    qc = qnames;
    while (qc != NULL && namecmp(qc->qnc_name_n, name_n) != 0)
        qc = qc->qnc_next;

    return (qc != NULL);
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
is_tail(u_char * full, u_char * tail)
{
    size_t             f_len = wire_name_length(full);
    size_t             t_len = wire_name_length(tail);

    if (f_len == t_len) {
        if (f_len)
            return namecmp(full, tail) == 0;
        else
            return 0;
    }

    if (t_len > f_len)
        return FALSE;

    if (namecmp(&full[f_len - t_len], tail) == 0) {
        size_t        index = 0;

        while (index < (f_len - t_len)) {
            index += (full[index]) + (u_char) 1;
            if (index == f_len - t_len)
                return TRUE;
        }
    }

    return FALSE;
}

int
add_to_set(struct rrset_rec *rr_set, size_t rdata_len_h,
           u_char * rdata)
{
    struct rrset_rr  *rr;

    if ((rr_set == NULL) || (rdata == NULL) || (rdata_len_h == 0))
        return VAL_BAD_ARGUMENT;

    /*
     * Make sure we got the memory for it 
     */
    rr = (struct rrset_rr *) MALLOC(sizeof(struct rrset_rr));
    if (rr == NULL)
        return VAL_OUT_OF_MEMORY;

    rr->rr_rdata = (u_char *) MALLOC(rdata_len_h * sizeof(u_char));
    if (rr->rr_rdata == NULL) {
        FREE(rr);
        return VAL_OUT_OF_MEMORY;
    }

    /*
     * Add it to the end of the current list of RR's 
     */
    if (rr_set->rrs_data == NULL) {
        rr_set->rrs_data = rr;
    } else {
        struct rrset_rr  *tmp_rr;
        tmp_rr = rr_set->rrs_data;
        while (tmp_rr->rr_next)
            tmp_rr = tmp_rr->rr_next;
        tmp_rr->rr_next = rr;
    }


    /*
     * Insert the data, copying the rdata pointer 
     */
    rr->rr_rdata_length = rdata_len_h;
    memcpy(rr->rr_rdata, rdata, rdata_len_h);
    rr->rr_status = VAL_AC_UNSET;
    rr->rr_next = NULL;

    return VAL_NO_ERROR;
}

int
add_as_sig(struct rrset_rec *rr_set, size_t rdata_len_h,
           u_char * rdata)
{
    struct rrset_rr  *rr;

    if ((rr_set == NULL) || (rdata == NULL) || (rdata_len_h == 0))
        return VAL_BAD_ARGUMENT;

    /*
     * Make sure we got the memory for it 
     */
    rr = (struct rrset_rr *) MALLOC(sizeof(struct rrset_rr));
    if (rr == NULL)
        return VAL_OUT_OF_MEMORY;

    rr->rr_rdata = (u_char *) MALLOC(rdata_len_h * sizeof(u_char));
    if (rr->rr_rdata == NULL) {
        FREE(rr);
        return VAL_OUT_OF_MEMORY;
    }

    if (rr_set->rrs_sig == NULL) {
        rr_set->rrs_sig = rr;
    } else {
        /*
         * If this code is executed, then there is a problem brewing.
         * It will be caught in pre_verify to keep the code level.
         */
        struct rrset_rr  *tmp_rr;
        tmp_rr = rr_set->rrs_sig;
        while (tmp_rr->rr_next)
            tmp_rr = tmp_rr->rr_next;
        tmp_rr->rr_next = rr;
    }

    /*
     * Insert the data, copying the rdata pointer 
     */
    rr->rr_rdata_length = rdata_len_h;
    memcpy(rr->rr_rdata, rdata, rdata_len_h);
    rr->rr_status = VAL_AC_UNSET;
    rr->rr_next = NULL;

    return VAL_NO_ERROR;
}

int
init_rr_set(struct rrset_rec *new_set, u_char * name_n,
            u_int16_t type_h, u_int16_t set_type_h,
            u_int16_t class_h, u_int32_t ttl_h,
            u_char * hptr, int from_section,
            int authoritive_answer, int iterative_answer,
            struct name_server *respondent_server)
{
    size_t name_len = wire_name_length(name_n);
    struct timeval  tv;

    if ((new_set == NULL) || (name_n == NULL))
        return VAL_BAD_ARGUMENT;

    if (new_set->rrs_name_n != NULL)
        /*
         * This has already been initialized 
         */
        return VAL_NO_ERROR;

    /*
     * Initialize it 
     */
    new_set->rrs_name_n =
        (u_char *) MALLOC(name_len * sizeof(u_char));
    if (new_set->rrs_name_n == NULL)
        return VAL_OUT_OF_MEMORY;

    if (hptr) {
        new_set->rrs_rcode = ((HEADER *)hptr)->rcode;
    } else {
        new_set->rrs_rcode = 0; 
    }

    memcpy(new_set->rrs_name_n, name_n, name_len);
    new_set->rrs_type_h = set_type_h;
    new_set->rrs_class_h = class_h;
    new_set->rrs_ttl_h = ttl_h;
    if (0 == gettimeofday(&tv, NULL)) {
        new_set->rrs_ttl_x = tv.tv_sec + ttl_h;
    } else
        new_set->rrs_ttl_x = 0;
    new_set->rrs_data = NULL;
    new_set->rrs_sig = NULL;

    if ((respondent_server) &&
        (respondent_server->ns_number_of_addresses > 0)) {
        new_set->rrs_server =
            (struct sockaddr *) MALLOC(sizeof(struct sockaddr_storage));
        if (new_set->rrs_server == NULL) {
            FREE(new_set->rrs_name_n);
            new_set->rrs_name_n = NULL;
            return VAL_OUT_OF_MEMORY;
        }
        memcpy(new_set->rrs_server,
               respondent_server->ns_address[0],
               sizeof(struct sockaddr_storage));
        new_set->rrs_ns_options = respondent_server->ns_options;
    } else {
        new_set->rrs_server = NULL;
        new_set->rrs_ns_options = 0;
    }

    new_set->rrs_next = NULL;

    /*
     * Set the credibility 
     */
    if (from_section == VAL_FROM_ANSWER)
        new_set->rrs_cred = authoritive_answer ?
            SR_CRED_AUTH_ANS : 
                (iterative_answer ? SR_CRED_ITER_ANS : SR_CRED_NONAUTH_ANS);
    else if (from_section == VAL_FROM_AUTHORITY)
        new_set->rrs_cred = authoritive_answer ?
            SR_CRED_AUTH_AUTH : 
                (iterative_answer ? SR_CRED_ITER_AUTH : SR_CRED_NONAUTH_AUTH);
    else if (from_section == VAL_FROM_ADDITIONAL)
        new_set->rrs_cred = authoritive_answer ?
            SR_CRED_AUTH_ADD : 
                (iterative_answer ? SR_CRED_ITER_ADD : SR_CRED_NONAUTH_ADD);
    else
        new_set->rrs_cred = SR_CRED_UNSET;

    /*
     * Set the source section 
     */

    new_set->rrs_section = from_section;

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
        a->rrs_type_h == s &&                    /* does type match */        \
        a->rrs_class_h == c &&                   /* does class match */       \
        namecmp (a->rrs_name_n,n)==0            /* does name match */        \
        )                                                                     \
        ||                                   /* or */                         \
        (s == ns_t_nsec &&														\
		 t == ns_t_rrsig &&                    /* if it is a sig(nxt) */        \
        a->rrs_data!=NULL &&                     /* is there data here */     \
        a->rrs_class_h == c &&                   /* does class match */       \
		a->rrs_type_h == ns_t_nsec &&													\
        namecmp (a->rrs_name_n,n)==0 &&         /* does name match */        \
        is_tail(a->rrs_data->rr_rdata,&r[SIGNBY])                               \
                                                 /* does sig match nxt */     \
        )                                                                     \
        ||                                   /* or */                         \
        (s == ns_t_nsec &&														\
        t == ns_t_nsec &&                    /* if it is a nxt */             \
        a->rrs_sig!=NULL &&                      /* is there a sig here */    \
        a->rrs_class_h == c &&                   /* does class match */       \
		a->rrs_type_h == ns_t_nsec &&													\
        namecmp (a->rrs_name_n,n)==0 &&         /* does name match */        \
        is_tail(r,&a->rrs_sig->rr_rdata[SIGNBY])                                \
                                                 /* does sig match nxt */     \
        )                                                                     \
    )                                                                         \
)

struct rrset_rec *
find_rr_set(struct name_server *respondent_server,
            struct rrset_rec **the_list,
            u_char * name_n,
            u_int16_t type_h,
            u_int16_t set_type_h,
            u_int16_t class_h,
            u_int32_t ttl_h,
            u_char * hptr,
            u_char * rdata_n,
            int from_section, 
            int authoritive_answer, 
            int iterative_answer, 
            u_char * zonecut_n)
{
    struct rrset_rec *tryit;
    struct rrset_rec *last;
    struct rrset_rec *new_one;
    size_t             name_len;

    if ((the_list == NULL) || (name_n == NULL))
        return NULL;

    /*
     * Search through the list for a matching record 
     */
    tryit = *the_list;
    last = NULL;
    name_len = wire_name_length(name_n);

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
                (u_char *) MALLOC(len * sizeof(u_char));
            if (new_one->rrs_zonecut_n == NULL) {
                res_sq_free_rrset_recs(the_list);
                return NULL;
            }
            memcpy(new_one->rrs_zonecut_n, zonecut_n, len);
        } else
            new_one->rrs_zonecut_n = NULL;

        if ((init_rr_set(new_one, name_n, type_h, set_type_h,
                         class_h, ttl_h, hptr, from_section,
                         authoritive_answer, iterative_answer, 
                         respondent_server))
            != VAL_NO_ERROR) {
            res_sq_free_rrset_recs(the_list);
            return NULL;
        }
    } else {
        new_one = tryit;
        /*
         * Make sure it has the lowest ttl (doesn't really matter) 
         */
        if (new_one->rrs_ttl_h > ttl_h)
            new_one->rrs_ttl_h = ttl_h;
    }

    /*
     * In all cases, return the value of new_one 
     */
    return new_one;
}

int
decompress(u_char ** rdata,
           u_char * response,
           size_t rdata_index,
           u_char * end, 
           u_int16_t type_h, 
           size_t * rdata_len_h)
{
    u_char        expanded_name[NS_MAXCDNAME];
    u_char        other_expanded_name[NS_MAXCDNAME];
    u_char        prefix[6];
    size_t        p_index = 0;
    size_t        new_size;
    size_t        working_index = rdata_index;
    size_t        other_name_length = 0;
    size_t        name_length = 0;
    size_t        insert_index = 0;
    int           working_increment;
    size_t        expansion = 0;
    size_t        len = 0;

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
    /* No decompression must happen */
    case ns_t_a6: 
    case ns_t_naptr:
    case ns_t_nsec:
    case ns_t_tlsa:
    default:
        new_size = (size_t) * rdata_len_h;
        if (new_size == 0)
            return VAL_NO_ERROR;

        *rdata = (u_char *) MALLOC(new_size * sizeof(u_char));
        if (*rdata == NULL)
            return VAL_OUT_OF_MEMORY;

        if (response + working_index + new_size > end)
            return VAL_BAD_ARGUMENT;
        memcpy(&(*rdata)[insert_index], &response[working_index], new_size);
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
            return VAL_BAD_ARGUMENT;

        working_index += working_increment;
        other_name_length = wire_name_length(other_expanded_name);
        expansion += other_name_length - working_increment;

        /*
         * fall through 
         */
    case ns_t_ns:
    case ns_t_cname:
    case ns_t_dname:
    case ns_t_mb:
    case ns_t_mg:
    case ns_t_mr:
    case ns_t_md:
    case ns_t_mf:
    case ns_t_ptr:

        working_increment = ns_name_unpack(response, end,
                                           &response[working_index],
                                           expanded_name,
                                           sizeof(expanded_name));
        if (working_increment < 0)
            return VAL_BAD_ARGUMENT;

        working_index += working_increment;
        name_length = wire_name_length(expanded_name);
        expansion += name_length - working_increment;

        /*
         * Make the new data area 
         */

        new_size = (size_t) (*rdata_len_h + expansion);

        *rdata = (u_char *) MALLOC(new_size * sizeof(u_char));
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

        len = *rdata_len_h + expansion - other_name_length - name_length;
        if (response + working_index + len  > end)
            return VAL_BAD_ARGUMENT;
        memcpy(&(*rdata)[insert_index], &response[working_index], len);

        *rdata_len_h += expansion;

        break;

        /*
         * The following group ends with one or two domain names 
         */
    case ns_t_srv:

        if (response + working_index + (2 * sizeof(u_int16_t)) > end)
            return VAL_BAD_ARGUMENT;
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
    case ns_t_kx:
    case ns_t_px:

        if (response + working_index + sizeof(u_int16_t) > end)
            return VAL_BAD_ARGUMENT;
        memcpy(&prefix[p_index], &response[working_index],
               sizeof(u_int16_t));
        working_index += sizeof(u_int16_t);
        p_index += sizeof(u_int16_t);

        working_increment = ns_name_unpack(response, end,
                                           &response[working_index],
                                           expanded_name,
                                           sizeof(expanded_name));
        if (working_increment < 0)
            return VAL_BAD_ARGUMENT;

        working_index += working_increment;
        name_length = wire_name_length(expanded_name);
        expansion += name_length - working_increment;

        if (type_h == ns_t_px) {
            working_increment = ns_name_unpack(response, end,
                                               &response[working_index],
                                               other_expanded_name,
                                               sizeof
                                               (other_expanded_name));
            if (working_increment < 0)
                return VAL_BAD_ARGUMENT;

            working_index += working_increment;
            other_name_length = wire_name_length(other_expanded_name);
            expansion += other_name_length - working_increment;
        }

        /*
         * Make the new data area 
         */

        new_size = (size_t) (*rdata_len_h + expansion);

        *rdata = (u_char *) MALLOC(new_size * sizeof(u_char));
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
            return VAL_BAD_ARGUMENT;

        name_length = wire_name_length(expanded_name);
        expansion += name_length - working_increment;

        /*
         * Make the new data area 
         */

        new_size = (size_t) (*rdata_len_h + expansion);

        *rdata = (u_char *) MALLOC(new_size * sizeof(u_char));
        if (*rdata == NULL)
            return VAL_OUT_OF_MEMORY;

        if (response + working_index + SIGNBY > end)
            return VAL_BAD_ARGUMENT;
        memcpy(&(*rdata)[insert_index], &response[working_index], SIGNBY);
        insert_index += SIGNBY;
        working_index += SIGNBY;

        memcpy(&(*rdata)[insert_index], expanded_name, name_length);
        insert_index += name_length;
        working_index += working_increment;

        len = *rdata_len_h - working_increment - SIGNBY;
        if (response + working_index + len > end)
            return VAL_BAD_ARGUMENT;
        memcpy(&(*rdata)[insert_index], &response[working_index], len);

        *rdata_len_h += expansion;
    }

    return VAL_NO_ERROR;
}

int
extract_from_rr(u_char * response,
                size_t *response_index,
                u_char * end,
                u_char * name_n,
                u_int16_t * type_h,
                u_int16_t * set_type_h,
                u_int16_t * class_h,
                u_int32_t * ttl_h,
                size_t *rdata_length_h, 
                size_t *rdata_index)
{
    u_int16_t       net_short;
    u_int32_t       net_int;
    int             ret_val;

    if ((response == NULL) || (response_index == NULL) || (type_h == NULL)
        || (class_h == NULL) || (ttl_h == NULL) || (rdata_length_h == NULL)
        || (rdata_index == NULL) || (set_type_h == NULL))
        return VAL_BAD_ARGUMENT;

    /*
     * Extract the uncompressed (unpacked) domain name in protocol format 
     */
    if ((ret_val =
         ns_name_unpack(response, end, &response[*response_index], name_n,
                        NS_MAXCDNAME)) == -1)
        return VAL_BAD_ARGUMENT;

    *response_index += ret_val;

    /* check if we have enough data to read the envelope */
    if (response + *response_index + 
        sizeof(u_int16_t) + 
        sizeof(u_int16_t) + 
        sizeof(u_int32_t) + 
        sizeof(u_int16_t) > end) {
            return VAL_BAD_ARGUMENT;
    }

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
        if (response + *response_index + sizeof(u_int16_t) > end)
            return VAL_BAD_ARGUMENT;
        memcpy(&net_short, &response[*response_index], sizeof(u_int16_t));
        *set_type_h = ntohs(net_short);
    } else
        *set_type_h = *type_h;

    *response_index += *rdata_length_h;

    return VAL_NO_ERROR;
}

void
lower_name(u_char rdata[], size_t * index)
{
    size_t             length;

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
lower(u_int16_t type_h, u_char * rdata, size_t len)
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
    /* No lowercasing must happen */
    case ns_t_a6: 
    case ns_t_naptr:
    case ns_t_nsec: 
    case ns_t_rrsig: 
    case ns_t_tlsa:
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
    case ns_t_dname:
    case ns_t_mb:
    case ns_t_mg:
    case ns_t_mr:
    case ns_t_md:
    case ns_t_mf:
    case ns_t_ptr:

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
    case ns_t_kx:
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
         * Note: this code is never used, since there are currently no 
         * record types in this category. 
         * This is left here in case RR's are defined in
         * this unfortunate (for them) manner.
         */
    }
}



struct rrset_rr  *
copy_rr_rec(u_int16_t type_h, struct rrset_rr *r, int dolower)
{
    /*
     * Make a copy of an RR, lowering the case of any contained
     * domain name in the RR section.
     */
    struct rrset_rr  *the_copy;

    if (r == NULL)
        return NULL;
    the_copy = (struct rrset_rr *) MALLOC(sizeof(struct rrset_rr));

    if (the_copy == NULL)
        return NULL;

    the_copy->rr_rdata_length = r->rr_rdata_length;
    the_copy->rr_rdata = (u_char *) MALLOC(the_copy->rr_rdata_length * sizeof
            (u_char));

    if (the_copy->rr_rdata == NULL) {
        FREE(the_copy);
        return NULL;
    }

    memcpy(the_copy->rr_rdata, r->rr_rdata, r->rr_rdata_length);

    if (dolower)
        lower(type_h, the_copy->rr_rdata, the_copy->rr_rdata_length);

    the_copy->rr_status = r->rr_status;
    the_copy->rr_next = NULL;

    return the_copy;
}

int
link_rr(struct rrset_rr **cs, struct rrset_rr *cr)
{
    /*
     * Insert a copied RR into the set being prepared for signing.  This
     * is an implementation of an insertion sort.
     */
    int             ret_val;
    int             length;
    struct rrset_rr  *temp_rr;

    if (cs == NULL)
        return 0;

    if (*cs == NULL) {
        *cs = cr;
        return 1;
    } else {
        length = (*cs)->rr_rdata_length < cr->rr_rdata_length ?
            (*cs)->rr_rdata_length : cr->rr_rdata_length;

        ret_val = memcmp((*cs)->rr_rdata, cr->rr_rdata, length);

        if (ret_val == 0
            && (*cs)->rr_rdata_length == cr->rr_rdata_length) {
            /*
             * cr is a copy of an existing record, forget it... 
             */
            if (cr->rr_next) { // old code was freeing w/out checking
                cr->rr_next = NULL;
            }
            res_sq_free_rr_recs(&cr);
            return -1;
        } else if (ret_val > 0
                   || (ret_val == 0 && length == cr->rr_rdata_length)) {
            cr->rr_next = *cs;
            *cs = cr;
            return 1;
        } else {
            temp_rr = *cs;

            if (temp_rr->rr_next == NULL) {
                temp_rr->rr_next = cr;
                cr->rr_next = NULL;
                return 1;
            }
            while (temp_rr->rr_next) {
                length = temp_rr->rr_next->rr_rdata_length <
                    cr->rr_rdata_length ?
                    temp_rr->rr_next->rr_rdata_length :
                    cr->rr_rdata_length;

                ret_val = memcmp(temp_rr->rr_next->rr_rdata, cr->rr_rdata,
                                 length);
                if (ret_val == 0 &&
                    temp_rr->rr_next->rr_rdata_length ==
                    cr->rr_rdata_length) {
                    /*
                     * cr is a copy of an existing record, forget it... 
                     */
                    if (cr->rr_next) { // old code was freeing w/out checking
                        cr->rr_next = NULL;
                    }
                    res_sq_free_rr_recs(&cr);
                    return -1;
                } else if (ret_val > 0
                           || (ret_val == 0
                               && length == cr->rr_rdata_length)) {
                    /*
                     * We've found a home for the record 
                     */
                    cr->rr_next = temp_rr->rr_next;
                    temp_rr->rr_next = cr;
                    return 1;
                }
                temp_rr = temp_rr->rr_next;
            }

            /*
             * If we've gone this far, add the record to the end of the list 
             */

            temp_rr->rr_next = cr;
            cr->rr_next = NULL;
            return 1;
        }
    }
}


struct rrset_rec *
copy_rrset_rec(struct rrset_rec *rr_set)
{
    struct rrset_rec *copy_set;
    struct rrset_rr  *orig_rr;
    struct rrset_rr  *copy_rr;
    size_t o_length;

    if (rr_set == NULL)
        return NULL;

    copy_set = (struct rrset_rec *) MALLOC(sizeof(struct rrset_rec));
    if (copy_set == NULL)
        return NULL;
    memset(copy_set, 0, sizeof(struct rrset_rec));

    if (rr_set->rrs_zonecut_n != NULL) {
        size_t             len = wire_name_length(rr_set->rrs_zonecut_n);
        copy_set->rrs_zonecut_n =
            (u_char *) MALLOC(len * sizeof(u_char));
        if (copy_set->rrs_zonecut_n == NULL) {
            FREE(copy_set);
            return NULL;
        }
        memcpy(copy_set->rrs_zonecut_n, rr_set->rrs_zonecut_n, len);
    }

    copy_set->rrs_cred = SR_CRED_UNSET;
    copy_set->rrs_ans_kind = SR_ANS_UNSET;
    copy_set->rrs_next = NULL;

    /*
     * Copy the rrs_rec members 
     */
    copy_set->rrs_rcode = rr_set->rrs_rcode;

    if (rr_set->rrs_name_n) {
        o_length = wire_name_length(rr_set->rrs_name_n);
        copy_set->rrs_name_n = (u_char *) MALLOC(o_length * sizeof(u_char));
        if (copy_set->rrs_name_n == NULL) {
            goto err;
        }
        memcpy(copy_set->rrs_name_n,
               rr_set->rrs_name_n, o_length);
    }

    copy_set->rrs_class_h = rr_set->rrs_class_h;
    copy_set->rrs_type_h = rr_set->rrs_type_h;
    copy_set->rrs_ttl_h = rr_set->rrs_ttl_h;
    copy_set->rrs_ttl_x = rr_set->rrs_ttl_x;
    copy_set->rrs_section = rr_set->rrs_section;

    copy_set->rrs_data = NULL;
    copy_set->rrs_sig = NULL;
    /*
     * Do an insertion sort of the records in rr_set.  As records are
     * copied, convert the domain names to lower case.
     */

    for (orig_rr = rr_set->rrs_data; orig_rr;
         orig_rr = orig_rr->rr_next) {
        /*
         * Copy it into the right form for verification 
         */
        copy_rr = copy_rr_rec(rr_set->rrs_type_h, orig_rr, 1);

        if (copy_rr == NULL) {
            goto err;
        }

        /*
         * Now, find a place for it 
         */

        link_rr(&copy_set->rrs_data, copy_rr);
    }
    /*
     * Copy the rrsigs also 
     */

    for (orig_rr = rr_set->rrs_sig; orig_rr;
         orig_rr = orig_rr->rr_next) {
        /*
         * Copy it into the right form for verification 
         */
        copy_rr = copy_rr_rec(rr_set->rrs_type_h, orig_rr, 0);

        if (copy_rr == NULL) {
            goto err;
        }

        /*
         * Now, find a place for it 
         */

        link_rr(&copy_set->rrs_sig, copy_rr);
    }

    /*
     * Copy respondent server information 
     */
    if (rr_set->rrs_server) {
        copy_set->rrs_server =
            (struct sockaddr *) MALLOC(sizeof(struct sockaddr_storage));
        if (copy_set->rrs_server == NULL) {
            goto err;
        }
        memcpy(copy_set->rrs_server, rr_set->rrs_server,
               sizeof(struct sockaddr_storage));
        copy_set->rrs_ns_options = rr_set->rrs_ns_options;
    } else {
        copy_set->rrs_server = NULL;
        copy_set->rrs_ns_options = 0;
    }

    return copy_set;

  err:
    res_sq_free_rrset_recs(&copy_set);
    return NULL;
}

struct rrset_rec *
copy_rrset_rec_list(struct rrset_rec *rr_set) 
{
    struct rrset_rec *copy_set, *cur_set, *prev_set, *new_set;

    copy_set = cur_set = prev_set = new_set = NULL;

    for (cur_set = rr_set; cur_set; cur_set=cur_set->rrs_next) {
        new_set = copy_rrset_rec(cur_set);
        if (!new_set) {
            res_sq_free_rrset_recs(&copy_set);
            return NULL;
        }    
        if (prev_set) {
            prev_set->rrs_next = new_set;
        } else {
            copy_set = new_set;
        }
        prev_set = new_set;
    }
    return copy_set;
}

#if 0
struct rrset_rec *
copy_rrset_rec_list_in_zonecut(struct rrset_rec *rr_set, u_char *qname_n) 
{
    struct rrset_rec *copy_set, *cur_set, *prev_set, *new_set;

    copy_set = cur_set = prev_set = new_set = NULL;

    if (qname_n == NULL)
        return NULL;

    for (cur_set = rr_set; cur_set; cur_set=cur_set->rrs_next) {

        /* 
         * if the zonecut exists, check if it is within the query name 
         * it is okay for the zonecut to be NULL 
         */
        if(cur_set->rrs_zonecut_n && !namename(qname_n, cur_set->rrs_zonecut_n)) {
            continue;
        }

        new_set = copy_rrset_rec(cur_set);
        if (!new_set) {
            res_sq_free_rrset_recs(&copy_set);
            return NULL;
        }    
        if (prev_set) {
            prev_set->rrs_next = new_set;
        } else {
            copy_set = new_set;
        }
        prev_set = new_set;
    }
    return copy_set;
}
#endif

/*
 *
 * returns
 *         ITS_BEEN_DONE
 *         IT_HASNT
 *         IT_WONT
 */
int
register_query(struct query_list **q, u_char * name_n, u_int16_t type_h,
               u_char * zone_n)
{
    if ((q == NULL) || (name_n == NULL))
        return IT_WONT;

    if (*q == NULL) {
        *q = (struct query_list *) MALLOC(sizeof(struct query_list));
        if (*q == NULL) {
            return IT_WONT;     /* Out of memory */
        }
        memcpy((*q)->ql_name_n, name_n, wire_name_length(name_n));
        if (zone_n)
            memcpy((*q)->ql_zone_n, zone_n, wire_name_length(zone_n));
        else
            memset((*q)->ql_zone_n, 0, sizeof((*q)->ql_zone_n));
        (*q)->ql_type_h = type_h;
        (*q)->ql_next = NULL;
    } else {
        struct query_list *cur_q = (*q);
        int             count = 0;
        while (cur_q->ql_next != NULL) {
            if ((!zone_n || namecmp(cur_q->ql_zone_n, zone_n) == 0)
                && namecmp(cur_q->ql_name_n, name_n) == 0)
                return ITS_BEEN_DONE;
            cur_q = cur_q->ql_next;
            if (++count > MAX_ALIAS_CHAIN_LENGTH)
                return IT_WONT;
        }
        if ((!zone_n || namecmp(cur_q->ql_zone_n, zone_n) == 0)
            && namecmp(cur_q->ql_name_n, name_n) == 0)
            return ITS_BEEN_DONE;
        cur_q->ql_next =
            (struct query_list *) MALLOC(sizeof(struct query_list));
        if (cur_q->ql_next == NULL) {
            return IT_WONT;     /* Out of memory */
        }
        cur_q = cur_q->ql_next;
        memcpy(cur_q->ql_name_n, name_n, wire_name_length(name_n));
        if (zone_n)
            memcpy(cur_q->ql_zone_n, zone_n, wire_name_length(zone_n));
        else
            memset(cur_q->ql_zone_n, 0, sizeof((*q)->ql_zone_n));
        cur_q->ql_type_h = type_h;
        cur_q->ql_next = NULL;
    }
    return IT_HASNT;
}

void
deregister_queries(struct query_list **q)
{
    struct query_list *p;

    if (q == NULL)
        return;

    while (*q) {
        p = *q;
        *q = (*q)->ql_next;
        FREE(p);
    }
}

void
merge_rrset_recs(struct rrset_rec **dest, struct rrset_rec *new_info)
{
    struct rrset_rec *new_rr, *prev;
    struct rrset_rec *old;
    struct rrset_rec *trail_new;
    struct rrset_rr  *rr_exchange;

    if (new_info == NULL)
        return;

    /*
     * Tie the two together 
     */
    prev = NULL;
    old = *dest;
    while (old) {

        /*
         * Look for duplicates 
         */
        new_rr = new_info;
        trail_new = NULL;
        while (new_rr) {
            if (old->rrs_type_h == new_rr->rrs_type_h
                && old->rrs_class_h ==
                new_rr->rrs_class_h
                && namecmp(old->rrs_name_n,
                           new_rr->rrs_name_n) == 0) {

                /*
                 * old and new are competitors 
                 */
                if (!(old->rrs_cred < new_rr->rrs_cred ||
                      (old->rrs_cred == new_rr->rrs_cred &&
                       old->rrs_section <=
                       new_rr->rrs_section))) {
                    /*
                     * exchange the two -
                     * copy from new to old: cred, status, section, ans_kind
                     * exchange: data, sig
                     */
                    old->rrs_cred = new_rr->rrs_cred;
                    old->rrs_section =
                        new_rr->rrs_section;
                    old->rrs_ans_kind = new_rr->rrs_ans_kind;
                    rr_exchange = old->rrs_data;
                    old->rrs_data = new_rr->rrs_data;
                    new_rr->rrs_data = rr_exchange;
                    rr_exchange = old->rrs_sig;
                    old->rrs_sig = new_rr->rrs_sig;
                    new_rr->rrs_sig = rr_exchange;
                }

                /*
                 * delete new 
                 */
                if (trail_new == NULL) {
                    new_info = new_rr->rrs_next;
                    if (new_info == NULL) {
                        res_sq_free_rrset_recs(&new_rr);
                        return;
                    }
                } else
                    trail_new->rrs_next = new_rr->rrs_next;
                new_rr->rrs_next = NULL;
                res_sq_free_rrset_recs(&new_rr);

                break;
            } else {
                trail_new = new_rr;
                new_rr = new_rr->rrs_next;
            }
        }
        prev = old;
        old = old->rrs_next;
    }
    if (prev == NULL)
        *dest = new_info;
    else
        prev->rrs_next = new_info;

    return;
}

int
val_create_rr_otw( char *name, 
                   int type,
                   int class,
                   long ttl,
                   size_t rdatalen, 
                   u_char *rdata,
                   size_t *buflen, 
                   u_char **buf)
{
    u_char domain_name_n[NS_MAXCDNAME];
    int ret;
    u_char *cp = NULL;
    size_t namelen  = 0;
    u_int16_t class_h = (u_int16_t) class;
    u_int16_t type_h = (u_int16_t) type;
    u_int16_t ttl_h = (u_int32_t) ttl;

    if (name == NULL || rdata == NULL || buflen == NULL || buf == NULL)
        return VAL_BAD_ARGUMENT;

    *buflen = 0;

    if ((ret = ns_name_pton(name, domain_name_n, NS_MAXCDNAME)) == -1) {
        return VAL_BAD_ARGUMENT;
    }
    
    namelen = wire_name_length(domain_name_n);
    *buflen = namelen + sizeof(u_int16_t) + sizeof(u_int16_t) +
        sizeof(u_int32_t) + sizeof(u_int16_t) + rdatalen;

    *buf = (u_char *) MALLOC (*buflen * sizeof(u_char));
    if (*buf == NULL)
        return VAL_OUT_OF_MEMORY;

    cp = *buf;

    memcpy(cp, domain_name_n, namelen);
    cp += namelen;

    NS_PUT16(type_h, cp);
    NS_PUT16(class_h, cp);
    NS_PUT32(ttl_h, cp);
    NS_PUT16(rdatalen, cp);
    memcpy(cp, rdata, rdatalen);

    return VAL_NO_ERROR;

}

