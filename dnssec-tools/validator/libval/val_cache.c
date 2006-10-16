
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
#include <pthread.h>

#include <resolver.h>
#include <validator.h>
#include "val_support.h"
#include "val_resquery.h"
#include "val_cache.h"
#include "val_log.h"

static struct rrset_rec *unchecked_key_info = NULL;
static struct rrset_rec *unchecked_ds_info = NULL;
static struct rrset_rec *unchecked_ns_info = NULL;
static struct rrset_rec *unchecked_answers = NULL;
static pthread_rwlock_t rwlock;
static int      rwlock_init = -1;

static struct name_server *root_ns = NULL;

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

/*
 * NOTE: This assumes a read lock is alread held by the caller.
 */
static int
stow_info(struct rrset_rec **unchecked_info, struct rrset_rec *new_info)
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
            if (old->rrs.val_rrset_type_h == new_rr->rrs.val_rrset_type_h
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
get_cached_rrset(u_int8_t * name_n, u_int16_t class_h,
                 u_int16_t type_h, struct rrset_rec **cloned_answer)
{
    struct rrset_rec *next_answer, *prev;
    struct timeval    tv;

    LOCK_INIT();

    *cloned_answer = NULL;
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

    /* XXX get_cached_rrset should return a domain_info structure
     * XXX This is to allow a CNAME chain to be returned
     * XXX In such cases, the qname_chain will also have to be tweaked 
     * XXX appropriately
     * XXX Look for a cached CNAME
     */  
    prev = NULL;
    while (next_answer) {

        if ((next_answer->rrs.val_rrset_type_h == type_h) &&
            (next_answer->rrs.val_rrset_class_h == class_h) &&
            (namecmp(next_answer->rrs.val_rrset_name_n, name_n) == 0) &&
            (tv.tv_sec > next_answer->rrs.val_rrset_ttl_x )) {
            if (next_answer->rrs.val_rrset_data != NULL) {
                *cloned_answer = copy_rrset_rec(next_answer);
                break;
            }
        }

        prev = next_answer;
        next_answer = next_answer->rrs_next;
    }
    UNLOCK();
    return VAL_NO_ERROR;
}

int
stow_zone_info(struct rrset_rec *new_info)
{
    int             rc;
    LOCK_INIT();
    LOCK_SH();
    rc = stow_info(&unchecked_ns_info, new_info);
    UNLOCK();

    return rc;
}

int
stow_key_info(struct rrset_rec *new_info)
{
    int             rc;

    LOCK_INIT();
    LOCK_SH();
    rc = stow_info(&unchecked_key_info, new_info);
    UNLOCK();

    return rc;
}

int
stow_ds_info(struct rrset_rec *new_info)
{
    int             rc;

    LOCK_INIT();
    LOCK_SH();
    rc = stow_info(&unchecked_ds_info, new_info);
    UNLOCK();

    return rc;
}

int
stow_answer(struct rrset_rec *new_info)
{
    int             rc;

    LOCK_INIT();
    LOCK_SH();
    rc = stow_info(&unchecked_answers, new_info);
    UNLOCK();

    return rc;
}

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

    LOCK_UPGRADE();
    root_ns = ns_list;
    UNLOCK();

    /*
     * Don't store the records in the cache 
     */

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
    free_name_servers(&root_ns);
    root_ns = NULL;
    UNLOCK();

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


int
get_matching_nslist(struct val_query_chain *matched_q,
                    struct val_query_chain **queries,
                    struct name_server **ref_ns_list)
{
    /*
     * find closest matching name zone_n 
     */
    struct rrset_rec *nsrrset;
    u_int8_t       *name_n = NULL;
    u_int8_t       *qname_n = NULL;
    u_int8_t       *tname_n = NULL;
    u_int8_t       *p;
    u_int16_t       qtype;

    qname_n = matched_q->qc_name_n;
    qtype = matched_q->qc_type_h;

    LOCK_INIT();
    // xxx-audit: insufficient lock?
    //     bootstrap_referral passes unchecked_ns_info to res_zi_unverified_ns_list,
    //     which modifies the list.. should an EX lock should be used, not SH?
    LOCK_SH();

    for (nsrrset = unchecked_ns_info; nsrrset; nsrrset = nsrrset->rrs_next) {

        if (nsrrset->rrs.val_rrset_type_h == ns_t_ns) {
            tname_n = nsrrset->rrs.val_rrset_name_n;

            /*
             * Check if tname_n is within qname_n 
             */
            if (NULL !=
                (p =
                 (u_int8_t *) strstr((char *) qname_n,
                                     (char *) tname_n))) {

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
                }
            }
        }
    }

    bootstrap_referral(name_n, &unchecked_ns_info, matched_q, queries,
                       ref_ns_list);

    UNLOCK();

    return VAL_NO_ERROR;
}
