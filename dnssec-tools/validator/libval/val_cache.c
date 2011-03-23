
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
 * Copyright 2005-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
/*
 * DESCRIPTION
 * Contains implementation for storage and retrieval functions for the validator
 * rrset cache.
 */
#include "validator-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#ifndef VAL_NO_THREADS
#include <pthread.h>
#endif

#include <arpa/nameser.h>
#include <validator/resolver.h>
#include <validator/validator.h>
#include <validator/validator-internal.h>
#include "val_support.h"
#include "val_resquery.h"
#include "val_cache.h"

struct zone_ns_map_t {
    u_char        zone_n[NS_MAXCDNAME];
    struct name_server *nslist;
    struct zone_ns_map_t *next;
};

/*
 * we have caches for DNSKEY, DS, NS/glue, answers, and proofs
 * XXX negative cache functionality is currently unimplemented
 */
static struct rrset_rec *unchecked_ns_info = NULL;
static struct rrset_rec *unchecked_answers = NULL;
static struct rrset_rec *unchecked_proofs = NULL;

/*
 * Also maintain mapping between zone and name server, 
 */
static struct zone_ns_map_t *zone_ns_map = NULL;

#ifndef VAL_NO_THREADS

/*
 * provide thread-safe access to each of the
 * various caches
 */
static pthread_rwlock_t ns_rwlock;
static int ns_rwlock_init = -1;
static pthread_rwlock_t ans_rwlock;
static int ans_rwlock_init = -1;
static pthread_rwlock_t proof_rwlock;
static int proof_rwlock_init = -1;
static pthread_rwlock_t map_rwlock;
static int map_rwlock_init = -1;

#define LOCK_INIT(lk, initvar) do {\
    if (0 != initvar) {\
        if (0 != pthread_rwlock_init(lk, NULL))\
	        return VAL_INTERNAL_ERROR; \
        initvar = 0;\
    }\
} while(0)

#define LOCK_SH(lk) do{				\
	if(0 != pthread_rwlock_rdlock(lk))\
		return VAL_INTERNAL_ERROR; \
} while(0)

#define LOCK_EX(lk) do{				\
	if(0 != pthread_rwlock_wrlock(lk))\
		return VAL_INTERNAL_ERROR;	\
} while(0)

#define UNLOCK(lk) do{				\
	if (0 != pthread_rwlock_unlock(lk)) \
		return VAL_INTERNAL_ERROR;	\
} while(0)

#else
#define LOCK_INIT(lk, initvar)
#define LOCK_SH(lk)
#define LOCK_EX(lk)
#define UNLOCK(lk)
#endif

#define IN_BAILIWICK(name, q) \
    ((q) &&\
     (q->qc_zonecut_n? (NULL != namename(name, q->qc_zonecut_n)) :\
      (NULL != namename(q->qc_name_n, name))))

/*
 * Common routine to store data to a specific cache
 * NOTE: This assumes a read lock is alread held by the caller.
 */
static int
stow_info(struct rrset_rec **unchecked_info, struct rrset_rec **new_info, struct val_query_chain *matched_q)
{
    struct rrset_rec *new_rr;
    struct rrset_rec *old, *prev, *trail_new;
    int delete_newrr = 0;

    if (new_info == NULL || unchecked_info == NULL)
        return VAL_NO_ERROR;

    if (matched_q->qc_flags & VAL_QUERY_REFRESH_QCACHE) {
        matched_q->qc_flags ^= VAL_QUERY_REFRESH_QCACHE;
    }

    trail_new = NULL;
    prev = NULL;
    while (*new_info) {
        new_rr = *new_info;
        delete_newrr = 0;
        if (!IN_BAILIWICK(new_rr->rrs_name_n, matched_q)) {
            delete_newrr = 1;
        } else {
          old = *unchecked_info;
          prev = NULL;
          while (old) {
            if (
                old->rrs_type_h == new_rr->rrs_type_h
                && old->rrs_class_h == new_rr->rrs_class_h
                && namecmp(old->rrs_name_n,
                           new_rr->rrs_name_n) == 0) {

                /*
                 * old and new are competitors 
                 */
                if (!(old->rrs_cred < new_rr->rrs_cred ||
                      (old->rrs_cred == new_rr->rrs_cred &&
                       old->rrs_section <= new_rr->rrs_section))) {
                    /*
                     * exchange the two -
                     * copy from new to old: cred, status, section, ans_kind
                     * exchange: data, sig
                     */
                    struct val_rr_rec  *rr_exchange;

                    old->rrs_cred = new_rr->rrs_cred;
                    old->rrs_section = new_rr->rrs_section;
                    old->rrs_ans_kind = new_rr->rrs_ans_kind;
                    rr_exchange = old->rrs_data;
                    old->rrs_data = new_rr->rrs_data;
                    new_rr->rrs_data = rr_exchange;
                    rr_exchange = old->rrs_sig;
                    old->rrs_sig = new_rr->rrs_sig;
                    new_rr->rrs_sig = rr_exchange;
                }

                delete_newrr = 1;
                break;
            } 

            /* look at the next cached record */
            prev = old;
            old = old->rrs_next;
          }
        }

        *new_info = new_rr->rrs_next;
        new_rr->rrs_next = NULL;

        if (delete_newrr) {
            res_sq_free_rrset_recs(&new_rr);
        } else {
            /* add new data to the end of our cache */
            if (prev) {
                prev->rrs_next = new_rr;
            } else {
                *unchecked_info = new_rr;
            }
        }
    }
    return VAL_NO_ERROR;
}

/*
 * retrieve data, if present, from cache
 */
int
get_cached_rrset(struct val_query_chain *matched_q, 
                 struct domain_info **response)
{
    struct rrset_rec **answer_head, *next_answer, *prev;
    struct rrset_rec *new_answer;
    struct timeval  tv;
    pthread_rwlock_t *lk;

    u_int16_t type_h;
    u_int16_t class_h;
    u_char *name_n;

    int look_for_negative;
    int done;

    if (!matched_q || !response)
        return VAL_BAD_ARGUMENT;

    answer_head = NULL;
    *response = NULL;
    name_n = matched_q->qc_name_n;
    type_h = matched_q->qc_type_h;
    class_h = matched_q->qc_class_h;

    gettimeofday(&tv, NULL);

    look_for_negative = 0;
    done = 0;

    while (!done) {

        if (look_for_negative) {
            lk = &proof_rwlock;
            LOCK_INIT(lk, proof_rwlock_init);
            LOCK_SH(lk);
            answer_head = &unchecked_proofs;
        } else if (type_h == ns_t_ns) {
            lk = &ns_rwlock;
            LOCK_INIT(lk, ns_rwlock_init);
            LOCK_SH(lk);
            answer_head = &unchecked_ns_info;
        } else {
            lk = &ans_rwlock;
            LOCK_INIT(lk, ans_rwlock_init);
            LOCK_SH(lk);
            answer_head = &unchecked_answers;
        }

        prev = NULL;
        new_answer = NULL;
        if (answer_head) 
            next_answer = *answer_head;
        else
            next_answer = NULL;
    
        while (next_answer) {

            if (tv.tv_sec < next_answer->rrs_ttl_x &&
                next_answer->rrs_class_h == class_h) {

                /* if matching type or cname indirection */
                if (((next_answer->rrs_type_h == type_h ||
                    (next_answer->rrs_type_h == ns_t_cname &&
                    ALIAS_MATCH_TYPE(type_h))) &&
                    /* and name is an exact match */
                    (namecmp(next_answer->rrs_name_n, name_n) == 0)) ||
                    /* OR */
                    /* DNAME indirection */
                    ((next_answer->rrs_type_h == ns_t_dname &&
                    ALIAS_MATCH_TYPE(type_h)) &&
                    /* and name applies */
                    (NULL != (u_char *) namename(name_n, 
                                    next_answer->rrs_name_n)))) {

                    if (next_answer->rrs_data != NULL) {
                        new_answer = copy_rrset_rec(next_answer);
                        if (new_answer) {
                            /* Adjust the TTL */
                            new_answer->rrs_ttl_h = next_answer->rrs_ttl_x - tv.tv_sec; 
                        }
                        break;
                    }
                } 
            }

            prev = next_answer;
            next_answer = next_answer->rrs_next;
        }

        UNLOCK(lk);

        if (!new_answer && type_h == ns_t_soa && !look_for_negative) {
            /* look for soa in negative cache */
            done = 0;
            look_for_negative = 1;
        } else {
            done = 1;
        }
    }

    /* Construct the response */
    if (new_answer) {
        char *name_p;
        name_p = (char *) MALLOC (NS_MAXDNAME * sizeof(char));
        if (name_p == NULL)
            return VAL_OUT_OF_MEMORY;

        /*
         * Construct a response 
         */
        *response = (struct domain_info *) MALLOC(sizeof(struct domain_info));
        if (*response == NULL) {
            res_sq_free_rrset_recs(&new_answer);
            return VAL_OUT_OF_MEMORY;
        }

        (*response)->di_requested_name_h = name_p;
        (*response)->di_answers = new_answer;
        (*response)->di_proofs = NULL;
        (*response)->di_qnames = 
            (struct qname_chain *) MALLOC(sizeof(struct qname_chain));
        if ((*response)->di_qnames == NULL) {
            free_domain_info_ptrs(*response);
            FREE(*response);
            *response = NULL;
            return VAL_OUT_OF_MEMORY;
        }
        memcpy((*response)->di_qnames->qnc_name_n, name_n,
               wire_name_length(name_n));
        (*response)->di_qnames->qnc_next = NULL;

        if (ns_name_ntop(name_n, name_p, NS_MAXCDNAME) == -1) {
            free_domain_info_ptrs(*response);
            FREE(*response);
            *response = NULL;
            return VAL_NO_ERROR;
        }
        (*response)->di_requested_type_h = matched_q->qc_type_h;
        (*response)->di_requested_class_h = matched_q->qc_class_h;
        (*response)->di_res_error = SR_UNSET;
        matched_q->qc_state = Q_ANSWERED;

        return process_cname_dname_responses( 
                        new_answer->rrs_name_n, 
                        new_answer->rrs_type_h, 
                        new_answer->rrs_data->rr_rdata, 
                        matched_q, &(*response)->di_qnames, 
                        NULL);


    }

    return VAL_NO_ERROR;
}

int
stow_zone_info(struct rrset_rec **new_info, struct val_query_chain *matched_q)
{
    int             rc;
    struct rrset_rec *r;
    int in_bailiwick = 1;
    
    /* Check if all records are in bailiwick */
    r = *new_info;
    while (r) {
        if (!IN_BAILIWICK(r->rrs_name_n, matched_q)) {
            in_bailiwick = 0;
            break;
        }
        r = r->rrs_next; 
    }
    
    /* If not, free the list (save all or nothing) */
    if (!in_bailiwick) {
        while(*new_info) {
            r = (*new_info)->rrs_next;
            (*new_info)->rrs_next = NULL;
            res_sq_free_rrset_recs(new_info);
            *new_info = r;
        }
        return VAL_NO_ERROR;
    }
    
    LOCK_INIT(&ns_rwlock, ns_rwlock_init);
    LOCK_EX(&ns_rwlock);
    rc = stow_info(&unchecked_ns_info, new_info, matched_q);
    UNLOCK(&ns_rwlock);

    return rc;
}

int
stow_answers(struct rrset_rec **new_info, struct val_query_chain *matched_q)
{
    int             rc;

    LOCK_INIT(&ans_rwlock, ans_rwlock_init);
    LOCK_EX(&ans_rwlock);
    rc = stow_info(&unchecked_answers, new_info, matched_q);
    UNLOCK(&ans_rwlock);

    return rc;
}

int
stow_negative_answers(struct rrset_rec **new_info, struct val_query_chain *matched_q)
{
    int             rc;

    LOCK_INIT(&proof_rwlock, proof_rwlock_init);
    LOCK_EX(&proof_rwlock);
    rc = stow_info(&unchecked_proofs, new_info, matched_q);
    UNLOCK(&proof_rwlock);

    return rc;
}

/*
 * Maintain a mapping between the zone and the name server that answered 
 * data for it 
 */
int
store_ns_for_zone(u_char * zonecut_n, struct name_server *resp_server)
{
    struct zone_ns_map_t *map_e;

    if (!zonecut_n || !resp_server)
        return VAL_NO_ERROR;

    LOCK_INIT(&map_rwlock, map_rwlock_init);
    LOCK_EX(&map_rwlock);

    for (map_e = zone_ns_map; map_e; map_e = map_e->next) {

        if (!namecmp(map_e->zone_n, zonecut_n)) {
            struct name_server *nslist = NULL;
            /*
             * add blindly to the list 
             */
            clone_ns_list(&nslist, resp_server);
            nslist->ns_next = map_e->nslist;
            map_e->nslist = nslist;
            break;
        }
    }

    if (!map_e) {
        map_e =
            (struct zone_ns_map_t *) MALLOC(sizeof(struct zone_ns_map_t));
        if (map_e == NULL) {
            UNLOCK(&map_rwlock);
            return VAL_OUT_OF_MEMORY;
        }

        clone_ns_list(&map_e->nslist, resp_server);
        memcpy(map_e->zone_n, zonecut_n, wire_name_length(zonecut_n));
        map_e->next = NULL;

        if (zone_ns_map != NULL)
            map_e->next = zone_ns_map;
        zone_ns_map = map_e;
    }

    UNLOCK(&map_rwlock);

    return VAL_NO_ERROR;
}

static int
free_zone_nslist(void)
{
    struct zone_ns_map_t *map_e;

    LOCK_INIT(&map_rwlock, map_rwlock_init);
    LOCK_EX(&map_rwlock);
    while (zone_ns_map) {
        map_e = zone_ns_map;
        zone_ns_map = zone_ns_map->next;

        if (map_e->nslist)
            free_name_servers(&map_e->nslist);
        FREE(map_e);
    }
    UNLOCK(&map_rwlock);

    return VAL_NO_ERROR;
}

int
get_nslist_from_cache(val_context_t *ctx,
                      struct queries_for_query *matched_qfq,
                      struct queries_for_query **queries,
                      struct name_server **ref_ns_list,
                      u_char **zonecut_n)
{
    /*
     * find closest matching name zone_n 
     */
    struct rrset_rec *nsrrset, *prev;
    u_char       *name_n = NULL;
    u_char       *tname_n = NULL;
    u_char       *p;
    u_int16_t     qtype;
    u_char       *qname_n;
    struct zone_ns_map_t *map_e, *saved_map;
    u_char       *tmp_zonecut_n = NULL;
    struct timeval  tv;

    if (matched_qfq == NULL || queries == NULL || ref_ns_list == NULL)
        return VAL_BAD_ARGUMENT;

    *ref_ns_list = NULL;
    
    /* matched_qfq->qfq_query cannot be NULL */
    qname_n = matched_qfq->qfq_query->qc_name_n;
    qtype = matched_qfq->qfq_query->qc_type_h;

    *zonecut_n = NULL;
    gettimeofday(&tv, NULL);
    
    LOCK_INIT(&map_rwlock, map_rwlock_init);
    LOCK_SH(&map_rwlock);

    /*
     * Check mapping table between zone and nameserver to see if 
     * NS information is available here 
     */
    saved_map = NULL;
    for (map_e = zone_ns_map; map_e; map_e = map_e->next) {

        /*
         * check if zone is within query 
         */
        if (NULL != (p = namename(qname_n, map_e->zone_n))) {
            if (!saved_map || (namecmp(p, saved_map->zone_n) > 0)) {
                saved_map = map_e;
            }
        }
    }

    if (saved_map) {
        clone_ns_list(ref_ns_list, saved_map->nslist);
        *zonecut_n = (u_char *) MALLOC (wire_name_length(saved_map->zone_n) *
                sizeof (u_char));
        if (*zonecut_n == NULL) {
            UNLOCK(&map_rwlock);
            return VAL_OUT_OF_MEMORY;
        } 

        memcpy(*zonecut_n, saved_map->zone_n, wire_name_length(saved_map->zone_n));
        UNLOCK(&map_rwlock);
        return VAL_NO_ERROR;
    }

    UNLOCK(&map_rwlock);

    LOCK_INIT(&ns_rwlock, ns_rwlock_init);
    LOCK_SH(&ns_rwlock);

    tmp_zonecut_n = NULL;
    prev = NULL;
    nsrrset = unchecked_ns_info;
    while (nsrrset) {

        if (tv.tv_sec < nsrrset->rrs_ttl_x &&
            nsrrset->rrs_type_h == ns_t_ns) {

            tname_n = nsrrset->rrs_name_n;

            /*
             * Check if tname_n is within qname_n 
             */
            if (NULL !=
                (p = namename(qname_n, tname_n))) {

                if ((!name_n) ||
                    (wire_name_length(tname_n) >
                     wire_name_length(name_n))) {

                    /*
                     * If type is DS, you don't want an exact match
                     * since that will lead you to the child zone
                     */
                    if ((qtype != ns_t_ds) || (p != qname_n)) {
                        /*
                         * New name is longer than old name 
                         */
                        name_n = tname_n;
                        tmp_zonecut_n = nsrrset->rrs_zonecut_n;
                    }
                }
            }
        }
        prev = nsrrset;
        nsrrset = nsrrset->rrs_next;
    }

    if (name_n) {
        /* only ask for complete name server lists - don't want to fetch glue here */
        bootstrap_referral(ctx, name_n, unchecked_ns_info, matched_qfq, queries,
                       ref_ns_list);
    }

    if (*ref_ns_list && tmp_zonecut_n) {
        *zonecut_n = (u_char *) MALLOC (wire_name_length(tmp_zonecut_n) *
                sizeof (u_char));
        if (*zonecut_n == NULL) {
            UNLOCK(&ns_rwlock);
            return VAL_OUT_OF_MEMORY;
        } 
        memcpy(*zonecut_n, tmp_zonecut_n, wire_name_length(tmp_zonecut_n));
    }
    
    UNLOCK(&ns_rwlock);

    return VAL_NO_ERROR;
}

int
free_validator_cache(void)
{
    LOCK_INIT(&ns_rwlock, ns_rwlock_init);
    LOCK_EX(&ns_rwlock);
    res_sq_free_rrset_recs(&unchecked_ns_info);
    unchecked_ns_info = NULL;
    UNLOCK(&ns_rwlock);
    
    LOCK_INIT(&ans_rwlock, ans_rwlock_init);
    LOCK_EX(&ans_rwlock);
    res_sq_free_rrset_recs(&unchecked_answers);
    unchecked_answers = NULL;
    UNLOCK(&ans_rwlock);
    
    LOCK_INIT(&proof_rwlock, proof_rwlock_init);
    LOCK_EX(&proof_rwlock);
    res_sq_free_rrset_recs(&unchecked_proofs);
    unchecked_proofs = NULL;
    UNLOCK(&proof_rwlock);

    free_zone_nslist();

    return VAL_NO_ERROR;
}

