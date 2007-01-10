
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
#ifndef VAL_NO_THREADS
#include <pthread.h>
#endif

#include <resolver.h>
#include <validator.h>
#include "val_support.h"
#include "val_resquery.h"
#include "val_cache.h"

static struct rrset_rec *unchecked_key_info = NULL;
static struct rrset_rec *unchecked_ds_info = NULL;
static struct rrset_rec *unchecked_ns_info = NULL;
static struct rrset_rec *unchecked_answers = NULL;
#ifndef VAL_NO_THREADS
static struct rrset_rec *unchecked_proofs = NULL;
static pthread_rwlock_t rwlock;
static int      rwlock_init = -1;
#endif

static struct name_server *root_ns = NULL;

struct zone_ns_map_t {
    u_int8_t        zone_n[NS_MAXCDNAME];
    struct name_server *nslist;
    struct zone_ns_map_t *next;
};

static struct zone_ns_map_t *zone_ns_map = NULL;

#ifndef VAL_NO_THREADS
#define LOCK_INIT() do{				\
	if(0 != rwlock_init) {\
		if(0 != pthread_rwlock_init(&rwlock, NULL))\
		return VAL_INTERNAL_ERROR; \
	}\
} while(0)

#define LOCK_SH() do{				\
	if(0 != pthread_rwlock_rdlock(&rwlock))\
		return VAL_INTERNAL_ERROR; \
} while(0)

#define LOCK_EX() do{				\
	if(0 != pthread_rwlock_wrlock(&rwlock))\
		return VAL_INTERNAL_ERROR;	\
} while(0)

/*
 * pthreads doesn't have a way to upgrade a lock, so we have to
 * release the shared lock and hope we get the write lock w/out
 * another process running inbetween. :-/
 */
#define LOCK_UPGRADE() do{				\
	if((0 != pthread_rwlock_unlock(&rwlock)) ||	\
	   (0 != pthread_rwlock_wrlock(&rwlock)))	\
		return VAL_INTERNAL_ERROR;	\
} while(0)

#define LOCK_DOWNGRADE() do{				\
	if((0 != pthread_rwlock_unlock(&rwlock)) ||	\
	   (0 != pthread_rwlock_rdlock(&rwlock)))	\
		return VAL_INTERNAL_ERROR;	\
} while(0)

#define UNLOCK() do{				\
	if (0 != pthread_rwlock_unlock(&rwlock)) \
		return VAL_INTERNAL_ERROR;	\
} while(0)

#else
#define LOCK_INIT()
#define LOCK_SH()
#define LOCK_EX()
#define LOCK_UPGRADE()
#define LOCK_DOWNGRADE()
#define UNLOCK()
#endif

#define IN_BAILIWICK(name, q) \
    ((q) &&\
     (q->qc_zonecut_n? (NULL != namename(name, q->qc_zonecut_n)) :\
      (NULL != namename(q->qc_name_n, name))))

/*
 * NOTE: This assumes a read lock is alread held by the caller.
 */
static int
stow_info(struct rrset_rec **unchecked_info, struct rrset_rec *new_info, struct val_query_chain *matched_q)
{
    struct rrset_rec *new_rr, *prev;
    struct rrset_rec *old;
    struct rrset_rec *trail_new;
    struct rr_rec  *rr_exchange;

    if (new_info == NULL)
        return VAL_NO_ERROR;

    /*
     * Tie the two together 
     */
    prev = NULL;
    old = *unchecked_info;
    while (old) {

        /*
         * Look for duplicates 
         */
        new_rr = new_info;
        trail_new = NULL;
        while (new_rr) {

            if (!IN_BAILIWICK(new_rr->rrs.val_rrset_name_n, matched_q)) {
                /*
                 * delete new 
                 */
                LOCK_UPGRADE();
                if (trail_new == NULL) {
                    new_info = new_rr->rrs_next;
                    if (new_info == NULL) {
                        res_sq_free_rrset_recs(&new_rr);
                        LOCK_DOWNGRADE();
                        return VAL_NO_ERROR;
                    }
                } else
                    trail_new->rrs_next = new_rr->rrs_next;
                new_rr->rrs_next = NULL;
                res_sq_free_rrset_recs(&new_rr);
                LOCK_DOWNGRADE();
                break;

            } else if (old->rrs.val_rrset_type_h == new_rr->rrs.val_rrset_type_h
                && old->rrs.val_rrset_class_h ==
                new_rr->rrs.val_rrset_class_h
                && namecmp(old->rrs.val_rrset_name_n,
                           new_rr->rrs.val_rrset_name_n) == 0) {


                // xxx-audit: dangerous locking
                //     there is a window here. recommend just getting
                //     and exclusive lock all the time...
                /*
                 * caller has a read lock, now we need a write lock...
                 */
                LOCK_UPGRADE();

                /*
                 * old and new are competitors 
                 */
                if (!(old->rrs_cred < new_rr->rrs_cred ||
                      (old->rrs_cred == new_rr->rrs_cred &&
                       old->rrs.val_rrset_section <=
                       new_rr->rrs.val_rrset_section))) {
                    /*
                     * exchange the two -
                     * copy from new to old: cred, status, section, ans_kind
                     * exchange: data, sig
                     */
                    old->rrs_cred = new_rr->rrs_cred;
                    old->rrs.val_rrset_section =
                        new_rr->rrs.val_rrset_section;
                    old->rrs_ans_kind = new_rr->rrs_ans_kind;
                    rr_exchange = old->rrs.val_rrset_data;
                    old->rrs.val_rrset_data = new_rr->rrs.val_rrset_data;
                    new_rr->rrs.val_rrset_data = rr_exchange;
                    rr_exchange = old->rrs.val_rrset_sig;
                    old->rrs.val_rrset_sig = new_rr->rrs.val_rrset_sig;
                    new_rr->rrs.val_rrset_sig = rr_exchange;
                }

                /*
                 * delete new 
                 */
                if (trail_new == NULL) {
                    new_info = new_rr->rrs_next;
                    if (new_info == NULL) {
                        res_sq_free_rrset_recs(&new_rr);
                        LOCK_DOWNGRADE();
                        return VAL_NO_ERROR;
                    }
                } else
                    trail_new->rrs_next = new_rr->rrs_next;
                new_rr->rrs_next = NULL;
                res_sq_free_rrset_recs(&new_rr);

                LOCK_DOWNGRADE();

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
        *unchecked_info = new_info;
    else
        prev->rrs_next = new_info;

    return VAL_NO_ERROR;
}

int
get_cached_rrset(struct val_query_chain *matched_q, 
                 struct domain_info **response)
{
    struct rrset_rec *next_answer, *prev, *new_answer;
    struct timeval  tv;

    u_int16_t type_h;
    u_int16_t class_h;
    u_int8_t *name_n;

    if (!matched_q || !response)
        return VAL_BAD_ARGUMENT;

    *response = NULL;
    name_n = matched_q->qc_name_n;
    type_h = matched_q->qc_type_h;
    class_h = matched_q->qc_class_h;

    LOCK_INIT();

    gettimeofday(&tv, NULL);

    LOCK_SH();
    switch (type_h) {

    case ns_t_ds:
        next_answer = unchecked_ds_info;
        break;

    case ns_t_dnskey:
        next_answer = unchecked_key_info;
        break;

    case ns_t_ns:
        next_answer = unchecked_ns_info;
        break;

    default:
        next_answer = unchecked_answers;
        break;
    }

    prev = NULL;
    new_answer = NULL;
    while (next_answer) {

        if ((tv.tv_sec < next_answer->rrs.val_rrset_ttl_x) &&
            (next_answer->rrs.val_rrset_class_h == class_h)) {

                /* straight answer */
            if (((next_answer->rrs.val_rrset_type_h == type_h ||
                /* or cname */
                 (next_answer->rrs.val_rrset_type_h == ns_t_cname &&
                  type_h != ns_t_any)) &&
                (namecmp(next_answer->rrs.val_rrset_name_n, name_n) == 0)) ||
                /* or DNAME */
                ((next_answer->rrs.val_rrset_type_h == ns_t_dname) &&
                 (NULL != (u_int8_t *) namename(name_n, 
                                    next_answer->rrs.val_rrset_name_n)))) {

                if (next_answer->rrs.val_rrset_data != NULL) {
                    new_answer = copy_rrset_rec(next_answer);
                    break;
                }
            } 
        }

        prev = next_answer;
        next_answer = next_answer->rrs_next;
    }

    UNLOCK();

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
            matched_q->qc_state = Q_ERROR_BASE + SR_CALL_ERROR;
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
                        new_answer->rrs.val_rrset_name_n, 
                        new_answer->rrs.val_rrset_type_h, 
                        new_answer->rrs.val_rrset_data->rr_rdata, 
                        matched_q, &(*response)->di_qnames, 
                        NULL);


    }

    return VAL_NO_ERROR;
}

int
stow_zone_info(struct rrset_rec *new_info, struct val_query_chain *matched_q)
{
    int             rc;
    LOCK_INIT();
    LOCK_SH();
    rc = stow_info(&unchecked_ns_info, new_info, matched_q);
    UNLOCK();

    return rc;
}

int
stow_key_info(struct rrset_rec *new_info, struct val_query_chain *matched_q)
{
    int             rc;

    LOCK_INIT();
    LOCK_SH();
    rc = stow_info(&unchecked_key_info, new_info, matched_q);
    UNLOCK();

    return rc;
}

int
stow_ds_info(struct rrset_rec *new_info, struct val_query_chain *matched_q)
{
    int             rc;

    LOCK_INIT();
    LOCK_SH();
    rc = stow_info(&unchecked_ds_info, new_info, matched_q);
    UNLOCK();

    return rc;
}

int
stow_answers(struct rrset_rec *new_info, struct val_query_chain *matched_q)
{
    int             rc;

    LOCK_INIT();
    LOCK_SH();
    rc = stow_info(&unchecked_answers, new_info, matched_q);
    UNLOCK();

    return rc;
}

int
stow_negative_answers(struct rrset_rec *new_info, struct val_query_chain *matched_q)
{
    int             rc;

    LOCK_INIT();
    LOCK_SH();
    rc = stow_info(&unchecked_proofs, new_info, matched_q);
    UNLOCK();

    return rc;
}

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int
stow_root_info(struct rrset_rec *root_info)
{
    struct name_server *ns_list = NULL;
    struct name_server *pending_glue = NULL;
    int             retval;
    u_char          root_zone_n[NS_MAXCDNAME];
    const char     *root_zone = ".";

    LOCK_INIT();

    LOCK_SH();
    if (NULL != root_ns) {
        UNLOCK();
        return VAL_NO_ERROR;
    }

    if (ns_name_pton(root_zone, root_zone_n, sizeof(root_zone_n)) == -1) {
        UNLOCK();
        return VAL_CONF_PARSE_ERROR;
    }

    if (VAL_NO_ERROR !=
        (retval =
         res_zi_unverified_ns_list(&ns_list, root_zone_n, root_info,
                                   &pending_glue))) {
        UNLOCK();
        return retval;
    }

    /*
     * We are not interested in fetching glue for the root 
     */
    free_name_servers(&pending_glue);


#if 0
    {
    struct name_server *tempns;
    for(tempns = ns_list; tempns; tempns= tempns->ns_next) {
	    printf ("Root name servers for %s :\n", tempns->ns_name_n);
        struct sockaddr_in  *s=(struct sockaddr_in*)(tempns->ns_address[0]);
        printf("%s\n", inet_ntoa(s->sin_addr));	
    }
    }
#endif

    LOCK_UPGRADE();
    root_ns = ns_list;
    UNLOCK();

    /*
     * Don't store the records in the cache 
     */

    return VAL_NO_ERROR;
}

int
get_root_ns(struct name_server **ns)
{
    LOCK_INIT();
    LOCK_SH();

    *ns = NULL;
    /*
     * return a cloned copy 
     */
    clone_ns_list(ns, root_ns);

    UNLOCK();

    return VAL_NO_ERROR;
}

/*
 * Maintain a mapping between the zone and the name server that answered 
 * data for it 
 */
int
store_ns_for_zone(u_int8_t * zonecut_n, struct name_server *resp_server)
{
    struct zone_ns_map_t *map_e;

    if (!zonecut_n || !resp_server)
        return VAL_NO_ERROR;

    LOCK_INIT();
    LOCK_EX();

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
        if (map_e == NULL)
            return VAL_OUT_OF_MEMORY;

        clone_ns_list(&map_e->nslist, resp_server);
        memcpy(map_e->zone_n, zonecut_n, wire_name_length(zonecut_n));
        map_e->next = NULL;

        if (zone_ns_map != NULL)
            map_e->next = zone_ns_map;
        zone_ns_map = map_e;
    }

    UNLOCK();

    return VAL_NO_ERROR;
}

static int
free_zone_nslist(void)
{
    struct zone_ns_map_t *map_e;

    while (zone_ns_map) {
        map_e = zone_ns_map;
        zone_ns_map = zone_ns_map->next;

        if (map_e->nslist)
            free_name_servers(&map_e->nslist);
        FREE(map_e);
    }

    return VAL_NO_ERROR;
}

int
get_nslist_from_cache(val_context_t *ctx,
                      struct val_query_chain *matched_q,
                      struct val_query_chain **queries,
                      struct name_server **ref_ns_list,
                      u_int8_t **zonecut_n)
{
    /*
     * find closest matching name zone_n 
     */
    struct rrset_rec *nsrrset;
    u_int8_t       *name_n = NULL;
    u_int8_t       *tname_n = NULL;
    u_int8_t       *p;
    u_int16_t       qtype;
    u_int8_t       *qname_n;
    struct zone_ns_map_t *map_e, *saved_map;
    u_int8_t       *tmp_zonecut_n = NULL;

    qname_n = matched_q->qc_name_n;
    qtype = matched_q->qc_type_h;

    *zonecut_n = NULL;
    
    LOCK_INIT();
    // xxx-audit: insufficient lock?
    //     bootstrap_referral passes unchecked_ns_info to res_zi_unverified_ns_list,
    //     which modifies the list.. should an EX lock should be used, not SH?
    LOCK_SH();

    /*
     * Check mapping table between zone and nameserver to see if 
     * NS information is available here 
     */
    saved_map = NULL;
    for (map_e = zone_ns_map; map_e; map_e = map_e->next) {

        /*
         * check if zone is within query 
         */
        if (NULL != (p = (u_int8_t *) namename(map_e->zone_n, qname_n))) {
            if (!saved_map || (namecmp(p, saved_map->zone_n) > 0)) {
                saved_map = map_e;
            }
        }
    }

    if (saved_map) {
        clone_ns_list(ref_ns_list, saved_map->nslist);
        *zonecut_n = (u_int8_t *) MALLOC (wire_name_length(saved_map->zone_n) * sizeof (u_int8_t));
        if (*zonecut_n == NULL) {
            UNLOCK();
            return VAL_OUT_OF_MEMORY;
        } 

        memcpy(*zonecut_n, saved_map->zone_n, wire_name_length(saved_map->zone_n));
        UNLOCK();
        return VAL_NO_ERROR;
    }

    tmp_zonecut_n = NULL;
    for (nsrrset = unchecked_ns_info; nsrrset; nsrrset = nsrrset->rrs_next) {

        if (nsrrset->rrs.val_rrset_type_h == ns_t_ns) {
            tname_n = nsrrset->rrs.val_rrset_name_n;

            /*
             * Check if tname_n is within qname_n 
             */
            if (NULL !=
                (p =
                 (u_int8_t *) namename(qname_n, tname_n))) {

                if ((!name_n) ||
                    (wire_name_length(tname_n) >
                     wire_name_length(name_n))) {

                    /*
                     * If type is DS, you don't want an exact match
                     * since that will lead you to the child zone
                     */
                    if ((qtype == ns_t_ds) && (p == qname_n)) {
                        continue;
                    }

                    /*
                     * New name is longer than old name 
                     */
                    name_n = tname_n;
                    tmp_zonecut_n = nsrrset->rrs_zonecut_n;
                }
            }
        }
    }

    if (tmp_zonecut_n) {
        *zonecut_n = (u_int8_t *) MALLOC (wire_name_length(tmp_zonecut_n) * sizeof (u_int8_t));
        if (*zonecut_n == NULL) {
            UNLOCK();
            return VAL_OUT_OF_MEMORY;
        } 
        memcpy(*zonecut_n, tmp_zonecut_n, wire_name_length(tmp_zonecut_n));
    }
    
    bootstrap_referral(name_n, &unchecked_ns_info, matched_q, queries,
                       ref_ns_list);

    UNLOCK();

    return VAL_NO_ERROR;
}

int
free_validator_cache(void)
{
    LOCK_INIT();
    LOCK_EX();
    res_sq_free_rrset_recs(&unchecked_key_info);
    unchecked_key_info = NULL;
    res_sq_free_rrset_recs(&unchecked_ds_info);
    unchecked_ds_info = NULL;
    res_sq_free_rrset_recs(&unchecked_ns_info);
    unchecked_ns_info = NULL;
    res_sq_free_rrset_recs(&unchecked_answers);
    unchecked_answers = NULL;
    res_sq_free_rrset_recs(&unchecked_proofs);
    unchecked_proofs = NULL;
    free_name_servers(&root_ns);
    root_ns = NULL;
    free_zone_nslist();
    UNLOCK();

    return VAL_NO_ERROR;
}

