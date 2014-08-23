
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
#ifndef VAL_SUPPORT_H
#define VAL_SUPPORT_H

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif

#define SET_MIN_TTL(q_ttl, new_ttl) do {\
    if (new_ttl != 0 && \
            (q_ttl == 0 || q_ttl > new_ttl))\
        q_ttl = new_ttl;\
}while(0)

#define ALLOCATE_REFERRAL_BLOCK(ref) do{ \
		ref = (struct delegation_info *) MALLOC (sizeof(struct delegation_info)); \
		if (ref) { \
		    ref->queries = NULL; \
		    ref->answers = NULL; \
		    ref->proofs = NULL; \
		    ref->qnames = NULL; \
		    ref->pending_glue_ns = NULL; \
		    ref->cur_pending_glue_ns = NULL; \
		    ref->saved_zonecut_n = NULL; \
		    ref->learned_zones = NULL; \
        }\
} while(0)


#define ITS_BEEN_DONE   0
#define IT_HASNT        1
#define IT_WONT         (-1)

void            my_free(void *p, char *filename, int lineno);
void           *my_malloc(size_t t, char *filename, int lineno);
char           *my_strdup(const char *str, char *filename, int lineno);

u_char *      namename(u_char * big_name, u_char * little_name);
#ifdef LIBVAL_NSEC3
void            base32hex_encode(u_char * in, size_t inlen,
                                 u_char ** out, size_t * outlen);
#endif
size_t          wire_name_labels(const u_char * field);
size_t          wire_name_length(const u_char * field);

void            res_sq_free_rr_recs(struct rrset_rr **rr);
void            res_sq_free_rrset_recs(struct rrset_rec **set);
int             add_to_qname_chain(struct qname_chain **qnames,
                                   const u_char * name_n);
int             name_in_qname_chain(struct qname_chain *qnames,
                                    const u_char * name_n);
void            free_qname_chain(struct qname_chain **qnames);
void            free_domain_info_ptrs(struct domain_info *di);
int             is_tail(u_char * full, u_char * tail);
int             nxt_sig_match(u_char * owner, u_char * next,
                              u_char * signer);
int             add_to_set(struct rrset_rec *rr_set, size_t rdata_len_h,
                           u_char * rdata);
int             add_as_sig(struct rrset_rec *rr_set, size_t rdata_len_h,
                           u_char * rdata);
int             init_rr_set(struct rrset_rec *new_set, u_char * name_n,
                            u_int16_t type_h, u_int16_t set_type_h,
                            u_int16_t class_h, u_int32_t ttl_h,
                            u_char * hptr, int from_section,
                            int authoritive_answer, int iterative_answer,
                            struct name_server *respondent_server);

struct rrset_rec *find_rr_set(struct name_server *respondent_server,
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
                              u_char * zonecut_n);

int             decompress(u_char ** rdata,
                           u_char * response,
                           size_t rdata_index,
                           u_char * end,
                           u_int16_t type_h, 
                           size_t * rdata_len_h);

int             extract_from_rr(u_char * response,
                                size_t *response_index,
                                u_char * end,
                                u_char * name_n,
                                u_int16_t * type_h,
                                u_int16_t * set_type_h,
                                u_int16_t * class_h,
                                u_int32_t * ttl_h,
                                size_t * rdata_length_h,
                                size_t *rdata_index);
void            lower_name(u_char rdata[], size_t * index);
void            lower(u_int16_t type_h, u_char * rdata, size_t len);
struct rrset_rr  *copy_rr_rec(u_int16_t type_h, struct rrset_rr *r,
                            int dolower);
int             link_rr(struct rrset_rr **cs, struct rrset_rr *cr);
struct rrset_rec *copy_rrset_rec(struct rrset_rec *rr_set);
struct rrset_rec *copy_rrset_rec_list(struct rrset_rec *rr_set);
#if 0
struct rrset_rec *copy_rrset_rec_list_in_zonecut(struct rrset_rec *rr_set, 
                                                 u_char *zonecut_n);
#endif
int             register_query(struct query_list **q, u_char * name_n,
                               u_int16_t type_h, u_char * zone_n);
void            deregister_queries(struct query_list **q);
void            merge_rrset_recs(struct rrset_rec **dest,
                                 struct rrset_rec *new_info);

#endif                          /* VAL_SUPPORT_H */
