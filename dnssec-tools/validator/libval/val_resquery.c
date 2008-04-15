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
 * Copyright 2005-2007 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
/*
 * DESCRIPTION
 * Contains resolver functionality in libval 
 */
#include "validator-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>

#include <resolv.h>

#include <validator/resolver.h>
#include <validator/validator.h>
#include <validator/validator-internal.h>
#ifndef NAMESER_HAS_HEADER
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#else
#include "arpa/header.h"
#endif
#endif                          /* NAMESER_HAS_HEADER */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifndef VAL_NO_THREADS
#include <pthread.h>
#endif

#include "val_resquery.h"
#include "val_support.h"
#include "val_cache.h"
#include "val_assertion.h"
#include "val_context.h"

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

/*
 * create a name_server struct from the given address rdata
 */
static int
extract_glue_from_rdata(struct val_rr_rec *addr_rr, struct name_server **ns)
{
    struct sockaddr_in *sock_in;
#ifdef VAL_IPV6
    struct sockaddr_in6 *sock_in6;
#endif

    if ((ns == NULL) || (*ns == NULL))
        return VAL_BAD_ARGUMENT;

    while (addr_rr) {
        int             i;
        struct sockaddr_storage **new_addr = NULL;

        if ((addr_rr->rr_rdata_length_h != 4)
#ifdef VAL_IPV6
            && addr_rr->rr_rdata_length_h != sizeof(struct in6_addr)
#endif
            ) {
            val_log(NULL, LOG_DEBUG, "extract_glue_from_rdata(): Skipping address with bad len=%d.",
                    addr_rr->rr_rdata_length_h);
            addr_rr = addr_rr->rr_next;
            continue;
        }

        CREATE_NSADDR_ARRAY(new_addr, (*ns)->ns_number_of_addresses + 1);
        if (new_addr == NULL) {
            return VAL_OUT_OF_MEMORY;
        }

        for (i = 0; i < (*ns)->ns_number_of_addresses; i++) {
            memcpy(new_addr[i], (*ns)->ns_address[i],
                   sizeof(struct sockaddr_storage));
            FREE((*ns)->ns_address[i]);
        }
        if ((*ns)->ns_address)
            FREE((*ns)->ns_address);
        (*ns)->ns_address = new_addr;

        if (addr_rr->rr_rdata_length_h == 4) {
            sock_in = (struct sockaddr_in *)
                (*ns)->ns_address[(*ns)->ns_number_of_addresses];

            sock_in->sin_family = AF_INET;
            sock_in->sin_port = htons(DNS_PORT);
            memset(sock_in->sin_zero, 0, sizeof(sock_in->sin_zero));
            memcpy(&(sock_in->sin_addr), addr_rr->rr_rdata, sizeof(u_int32_t));
        }
#ifdef VAL_IPV6
        else if (addr_rr->rr_rdata_length_h == sizeof(struct in6_addr)) {
            sock_in6 = (struct sockaddr_in6 *)
                (*ns)->ns_address[(*ns)->ns_number_of_addresses];

            memset(sock_in6, 0, sizeof(sock_in6));
            sock_in6->sin6_family = AF_INET6;
            sock_in6->sin6_port = htons(DNS_PORT);
            memcpy(&(sock_in6->sin6_addr), addr_rr->rr_rdata,
                   sizeof(struct in6_addr));
        }
#endif
        (*ns)->ns_number_of_addresses++;
        addr_rr = addr_rr->rr_next;

    }
    return VAL_NO_ERROR;
}

/*
 * merge the data received from a glue fetch operation into
 * the original query. Also check for glue fetch loops.
 */
static int
merge_glue_in_referral(val_context_t *context,
                       struct queries_for_query *qfq_pc,
                       struct glue_fetch_bucket *bucket,
                       struct queries_for_query **queries)
{
    int             retval;
    struct queries_for_query *glue_qfq = NULL;
    struct val_query_chain *glueptr = NULL;
    struct val_query_chain *pc;
    struct name_server *pending_ns;
    struct name_server *prev_ns;
    char name_p[NS_MAXDNAME];
    u_int8_t flags;

    /*
     * check if we have data to merge 
     */
    if ((queries == NULL) || (qfq_pc == NULL) || (bucket == NULL)) 
        return VAL_BAD_ARGUMENT; 

    pc = qfq_pc->qfq_query; /* Can never be NULL if qfq_pc is not NULL */
    
    /* Nothing to do */
    if ((pc->qc_referral == NULL) || (pc->qc_referral->pending_glue_ns == NULL))
        return VAL_NO_ERROR;
    
    /* For each glue request that we have */
    pending_ns = pc->qc_referral->pending_glue_ns;
    prev_ns = NULL;
    while(pending_ns) {

        ns_name_ntop(pending_ns->ns_name_n, name_p,
                     sizeof(name_p));
        
        /*
         * Identify the query in the query chain 
         */
        flags = qfq_pc->qfq_flags | 
                VAL_QUERY_GLUE_REQUEST;

        if (VAL_NO_ERROR != (retval = 
                    add_to_qfq_chain(context,
                                     queries, pending_ns->ns_name_n, ns_t_a, 
                                     ns_c_in, flags, &glue_qfq))) 
            return retval;

        glueptr = glue_qfq->qfq_query;/* Can never be NULL if glue_qfq is not NULL */
        
        /*
         * Check if glue was obtained 
         */
        if (glueptr->qc_state >= Q_ANSWERED) { 

            struct val_digested_auth_chain *as;
            struct name_server *cur_ns;

            /* Isolate pending_ns from the list */
            if (prev_ns) {
                prev_ns->ns_next = pending_ns->ns_next;
                cur_ns = pending_ns;
                pending_ns = prev_ns->ns_next;
            } else {
                pc->qc_referral->pending_glue_ns = pending_ns->ns_next;
                cur_ns = pending_ns;
                pending_ns = pc->qc_referral->pending_glue_ns;
            }
            
            /* This could be a cname or dname alias; search for the A record */
            for (as=glueptr->qc_ans; as; as=as->_as.val_ac_rrset_next) {
                if (as->_as.ac_data && 
                    (as->_as.ac_data->rrs.val_rrset_type_h == ns_t_a ||
                     as->_as.ac_data->rrs.val_rrset_type_h == ns_t_aaaa))
                    break;
            }
       
            if (!as || 
                glueptr->qc_state != Q_ANSWERED ||
                VAL_NO_ERROR != (retval = 
                    extract_glue_from_rdata(as->_as.ac_data->rrs.val_rrset_data, 
                                            &cur_ns))) { 

                val_log(context, LOG_DEBUG, 
                        "merge_glue_in_referral(): Could not fetch glue for %s", 
                        name_p);
                /* free this name server */
                free_name_server(&cur_ns);

            } else  {
                
                /* store this name server in the merged_ns list */
                cur_ns->ns_next = pc->qc_referral->merged_glue_ns;
                pc->qc_referral->merged_glue_ns = cur_ns;
                val_log(context, LOG_DEBUG,
                        "merge_glue_in_referral(): successfully fetched glue for %s", 
                        name_p);
            }
        } else {

            /* check if we have a loop */
            int i;
            for (i=0; i<bucket->qfq_count; i++) {
                if (bucket->qfq[i] == glue_qfq) {
                    /* loop detected */
                    val_log(context, LOG_DEBUG, 
                            "merge_glue_in_referral(): Loop detected while fetching glue for %s",
                            name_p);
                    glueptr->qc_state = Q_REFERRAL_ERROR;
                    break; 
                } 
            }
            if (i == bucket->qfq_count) {
                /* add this glueptr to the bucket */
                if ((bucket->qfq_count+1) == MAX_GLUE_FETCH_DEPTH) {
                    /* too many dependencies */
                    val_log(context, LOG_DEBUG, 
                            "merge_glue_in_referral(): Too many glue requests in dependency chain for %s",
                            name_p);
                    glueptr->qc_state = Q_REFERRAL_ERROR;
                } else {
                    bucket->qfq[i] = glue_qfq;
                    bucket->qfq_count++;
                }
            }
            
            prev_ns = pending_ns;
            pending_ns = pending_ns->ns_next;
        }
    }

    /* Check if there was more glue to fetch */
    if (pc->qc_referral->pending_glue_ns == NULL) {

        if (pc->qc_referral->merged_glue_ns == NULL) {
            /* couldn't find any answers for the glue fetch requests */
            val_log(context, LOG_DEBUG, "merge_glue_in_referral(): No good answer for glue fetch");
            pc->qc_state = Q_REFERRAL_ERROR;
        } else {
            /* continue referral using the fetched glue records */
            
            if (pc->qc_ns_list) {
                free_name_servers(&pc->qc_ns_list);
                pc->qc_ns_list = NULL;
            }
            pc->qc_ns_list = pc->qc_referral->merged_glue_ns;
            pc->qc_referral->merged_glue_ns = NULL;

            /* save learned zone information */
            if (VAL_NO_ERROR != (retval = 
                        stow_zone_info(pc->qc_referral->learned_zones, pc))) {
                return retval;
            }
            pc->qc_referral->learned_zones = NULL;

            if (pc->qc_respondent_server) {
                free_name_server(&pc->qc_respondent_server);
                pc->qc_respondent_server = NULL;
            }
            if (pc->qc_zonecut_n != NULL) {
                FREE(pc->qc_zonecut_n);
                pc->qc_zonecut_n = NULL;
            }

            pc->qc_state = Q_INIT;
            
        }
    }

    return VAL_NO_ERROR;
}

/*
 * Check queries in list for missing glue
 * Merge any glue that is available into the relevant query
 * Set *data_missing if some query in the list still remains
 * unanswered
 */
int
fix_glue(val_context_t * context,
         struct queries_for_query **queries,
         int *data_missing)
{
    struct queries_for_query *next_q;
    struct glue_fetch_bucket *depn_bucket = NULL;
    int    retval;
    char   name_p[NS_MAXDNAME];
    int i;

    retval = VAL_NO_ERROR;
   
    if (context == NULL || queries == NULL || data_missing == NULL)
        return VAL_BAD_ARGUMENT;

    if (*data_missing == 0)
        return VAL_NO_ERROR;

    *data_missing = 0;
    for (next_q = *queries; next_q; next_q = next_q->qfq_next) {
        if (next_q->qfq_query->qc_state < Q_ANSWERED) {
            *data_missing = 1;
        }
        if (next_q->qfq_query->qc_state == Q_WAIT_FOR_GLUE) {
            struct glue_fetch_bucket *b;

            if (-1 == ns_name_ntop(next_q->qfq_query->qc_name_n, name_p, sizeof(name_p)))
                snprintf(name_p, sizeof(name_p), "unknown/error");

            /* 
             * check for a glue fetch loop 
             */
            /* first, find  the dependency bucket */
            for (b = depn_bucket; b; b=b->next_bucket) {
               for (i=0; i<b->qfq_count; i++) {
                   if (b->qfq[i] == next_q)
                       break;
               }
               if (i < b->qfq_count)
                   break;
            }

            if (b == NULL) {
                /* create a new bucket if one does not exist */
                b = (struct glue_fetch_bucket *) MALLOC (sizeof (struct glue_fetch_bucket));
                if (b == NULL)
                    goto err;
                memset(b->qfq, 0, MAX_GLUE_FETCH_DEPTH);
                b->qfq_count = 1;
                b->qfq[0] = next_q;
                /* add to head of list */
                b->next_bucket = depn_bucket;
                depn_bucket = b;
            }
            /* 
             * next, check if the glue for this query is already in the bucket 
             * or check if the glue was returned 
             */
            if (VAL_NO_ERROR != (retval =
                        merge_glue_in_referral(context,
                                               next_q,
                                               b,
                                               queries))) {
                goto err;
            }

            if (next_q->qfq_query->qc_state != Q_INIT &&
                       next_q->qfq_query->qc_state != Q_WAIT_FOR_GLUE) {
                val_log(context, LOG_DEBUG,
                        "fix_glue(): could not fetch glue for {%s %d %d} referral", name_p,
                        next_q->qfq_query->qc_class_h, next_q->qfq_query->qc_type_h);
            }
        }
    }

err:
    /* free up depn_bucket */
    while(depn_bucket) {
        struct glue_fetch_bucket *temp = depn_bucket;

        depn_bucket = depn_bucket->next_bucket;
        FREE(temp);
    }

    return retval;
}

/*
 * Identify the referral name servers from the rrsets 
 * returned in the response. The glue may be missing,
 * in which case we save the incomplete name server information
 * in "pending glue"
 */ 
int
res_zi_unverified_ns_list(struct name_server **ns_list,
                          u_int8_t * zone_name,
                          struct rrset_rec *unchecked_zone_info,
                          struct name_server **pending_glue)
{
    struct rrset_rec *unchecked_set;
    struct rrset_rec *trailer;
    struct val_rr_rec  *ns_rr;
    struct name_server *temp_ns;
    struct name_server *ns;
    struct name_server *pending_glue_last;
    struct name_server *trail_ns;
    struct name_server *outer_trailer;
    struct name_server *tail_ns;
    size_t          name_len;
    int             retval;

    if ((ns_list == NULL) || (pending_glue == NULL))
        return VAL_BAD_ARGUMENT;

    *ns_list = NULL;
    trailer = NULL;

    /*
     * Look through the unchecked_zone stuff for NS records 
     */
    unchecked_set = unchecked_zone_info;
    while (unchecked_set != NULL) {
        if (unchecked_set->rrs.val_rrset_type_h == ns_t_ns &&
            (namecmp(zone_name, unchecked_set->rrs.val_rrset_name_n) == 0))
        {
            if ((*ns_list == NULL) || (trailer == NULL)) {
                ns_rr = unchecked_set->rrs.val_rrset_data;
                while (ns_rr) {
                    /*
                     * Create the structure for the name server 
                     */
                    temp_ns = (struct name_server *)
                        MALLOC(sizeof(struct name_server));
                    if (temp_ns == NULL) {
                        /*
                         * Since we're in trouble, free up just in case 
                         */
                        free_name_servers(ns_list);
                        return VAL_OUT_OF_MEMORY;
                    }

                    /*
                     * Make room for the name and insert the name 
                     */
                    name_len = wire_name_length(ns_rr->rr_rdata);
                    if (name_len > sizeof(temp_ns->ns_name_n)) {
                        free_name_servers(ns_list);
                        return VAL_OUT_OF_MEMORY;
                    }
                    memcpy(temp_ns->ns_name_n, ns_rr->rr_rdata, name_len);

                    /*
                     * Initialize the rest of the fields 
                     */
                    temp_ns->ns_tsig = NULL;
                    temp_ns->ns_security_options = ZONE_USE_NOTHING;
                    temp_ns->ns_status = SR_ZI_STATUS_LEARNED;

                    temp_ns->ns_retrans = RES_TIMEOUT;
                    temp_ns->ns_retry = RES_RETRY;
                    temp_ns->ns_options = RES_DEFAULT;
                    /* Ensure that recursion is disabled by default */
                    if (temp_ns->ns_options & RES_RECURSE)
                        temp_ns->ns_options ^= RES_RECURSE;

                    temp_ns->ns_next = NULL;
                    temp_ns->ns_address = NULL;
                    temp_ns->ns_number_of_addresses = 0;
                    /*
                     * Add the name server record to the list 
                     */
                    if (*ns_list == NULL)
                        *ns_list = temp_ns;
                    else {
                        /*
                         * Preserving order in case of round robin 
                         */
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

    /*
     * Now, we need the addresses 
     */
    /*
     * This is ugly - loop through unchecked data for address records,
     * then through the name server records to find a match,
     * then through the (possibly multiple) addresses under the A set
     */

    unchecked_set = unchecked_zone_info;
    while (unchecked_set != NULL) {
        if (unchecked_set->rrs.val_rrset_type_h == ns_t_a ||
            unchecked_set->rrs.val_rrset_type_h == ns_t_aaaa) {
            /*
             * If the owner name matches the name in an *ns_list entry...
             */
            trail_ns = NULL;
            ns = *ns_list;
            while (ns) {
                if (namecmp
                    (unchecked_set->rrs.val_rrset_name_n,
                     ns->ns_name_n) == 0) {
                    struct name_server *old_ns = ns;
                    /*
                     * Found that address set is for an NS 
                     */
                    if (VAL_NO_ERROR !=
                        (retval =
                         extract_glue_from_rdata(unchecked_set->rrs.
                                                 val_rrset_data, &ns)))
                        return retval;
                    if (old_ns != ns) {
                        /*
                         * ns was realloc'd 
                         */
                        if (trail_ns)
                            trail_ns->ns_next = ns;
                        else
                            *ns_list = ns;
                    }
                    ns = NULL;  /* Force dropping out from the loop */
                } else {
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
    pending_glue_last = NULL;
    while (ns) {
        if (ns->ns_number_of_addresses == 0) {
            if (outer_trailer) {
                outer_trailer->ns_next = ns->ns_next;

                /*
                 * Add ns to the end of the pending_glue list 
                 */
                if (*pending_glue == NULL) {
                    *pending_glue = ns;
                    pending_glue_last = *pending_glue;
                } else {
                    pending_glue_last->ns_next = ns;
                    pending_glue_last = ns;
                }
                ns->ns_next = NULL;

                /*
                 * move to the next element 
                 */
                ns = outer_trailer->ns_next;
            } else {
                *ns_list = ns->ns_next;

                /*
                 * Add ns to the end of the pending_glue list 
                 */
                if (*pending_glue == NULL) {
                    *pending_glue = ns;
                    pending_glue_last = *pending_glue;
                } else {
                    pending_glue_last->ns_next = ns;
                    pending_glue_last = ns;
                }
                ns->ns_next = NULL;

                /*
                 * Move to the next element 
                 */
                ns = *ns_list;
            }
        } else {                /* There is at least one address */

            outer_trailer = ns;
            ns = ns->ns_next;
        }
    }


    return VAL_NO_ERROR;
}

/*
 * Identify the name servers where the query needs to be sent to 
 */
int
find_nslist_for_query(val_context_t * context,
                      struct queries_for_query *next_qfq,
                      struct queries_for_query **queries)
{
    /*
     * See if we can get an answer from a closer NS (from cache) 
     */
    struct name_server *ref_ns_list;
    int             ret_val;
    struct val_query_chain *next_q;

    if (next_qfq == NULL)
        return VAL_BAD_ARGUMENT;
    
    next_q = next_qfq->qfq_query; /* Can never be NULL if next_qfq is not NULL */

    ref_ns_list = NULL;

    /* forget existing name server information */
    if (next_q->qc_zonecut_n)
        FREE(next_q->qc_zonecut_n);
    next_q->qc_zonecut_n = NULL;
    if (next_q->qc_ns_list != NULL) 
        free_name_servers(&next_q->qc_ns_list);
    next_q->qc_ns_list = NULL;

    ret_val = get_nslist_from_cache(context, next_qfq, queries, &ref_ns_list, &next_q->qc_zonecut_n);
    
    if ((ret_val == VAL_NO_ERROR) && (next_q->qc_zonecut_n)) {
        if (ref_ns_list == NULL) {
            FREE(next_q->qc_zonecut_n);
            next_q->qc_zonecut_n = NULL;
        } else {
            next_q->qc_ns_list = ref_ns_list;
            return VAL_NO_ERROR;
        } 
    } 

    if (context->nslist != NULL) {
        /* 
         * if we have a default name server in our resolv.conf file, send
         *  to that name server
         */
        clone_ns_list(&(next_q->qc_ns_list), context->nslist);
    } else {
        /*
         * work downward from root 
         */
        if (context->root_ns == NULL) {
            /*
             * No root hints; should not happen here 
             */
            val_log(context, LOG_WARNING, 
                    "find_nslist_for_query(): Trying to answer query recursively, but no root hints file found.");
            return VAL_CONF_NOT_FOUND;
        }
        clone_ns_list(&next_q->qc_ns_list, context->root_ns);
        next_q->qc_zonecut_n = (u_int8_t *) MALLOC(sizeof(u_int8_t));
        if (next_q->qc_zonecut_n == NULL) {
            return VAL_OUT_OF_MEMORY;
        }
        *(next_q->qc_zonecut_n) = (u_int8_t) '\0';
    }
    return VAL_NO_ERROR;
}

/*
 * Identify next name servers in referral chain, 
 * issue queries for for missing glue
 */
int
bootstrap_referral(val_context_t *context,
                   u_int8_t * referral_zone_n,
                   struct rrset_rec **learned_zones,
                   struct queries_for_query *matched_qfq,
                   struct queries_for_query **queries,
                   struct name_server **ref_ns_list,
                   int no_partial)
{
    struct name_server *pending_glue;
    int             ret_val;
    struct queries_for_query *added_q = NULL;
    struct val_query_chain *matched_q;
    u_int8_t flags;

    if ((context == NULL) || (learned_zones == NULL) || (matched_qfq == NULL) ||
        (queries == NULL) || (ref_ns_list == NULL))
        return VAL_BAD_ARGUMENT;

    *ref_ns_list = NULL;
    matched_q = matched_qfq->qfq_query; /* Can never be NULL if matched_qfq is not NULL */

    /*
     *  If we received a referral for the root, use our 
     *  pre-parsed root.hints information 
     */
    if (!namecmp(referral_zone_n, (u_int8_t *)"\0")) {
        if (context->root_ns == NULL) {
            /*
             * No root hints; should not happen here 
             */
            val_log(context, LOG_WARNING, 
                    "bootstrap_referral(): referral to root, but no root hints file found.");
            matched_q->qc_state = Q_REFERRAL_ERROR;
            return VAL_NO_ERROR;
        }
        clone_ns_list(ref_ns_list, context->root_ns);
        matched_q->qc_state = Q_INIT;
        /*
         * forget about learned zones 
         */
        res_sq_free_rrset_recs(learned_zones);
        *learned_zones = NULL;
        return VAL_NO_ERROR;
    }
    
    if ((ret_val =
         res_zi_unverified_ns_list(ref_ns_list, referral_zone_n,
                                   *learned_zones, &pending_glue))
        != VAL_NO_ERROR) {
        /*
         * Get an NS list for the referral zone 
         */
        if (ret_val == VAL_OUT_OF_MEMORY)
            return ret_val;
    }

    if (pending_glue != NULL) {
        /*
         * Don't fetch glue if we're already fetching glue 
         */
        if (matched_q->qc_referral &&
            (matched_q->qc_referral->pending_glue_ns != NULL ||
             matched_q->qc_referral->merged_glue_ns != NULL)) { 

            free_name_servers(&pending_glue);
            free_name_servers(ref_ns_list);
            *ref_ns_list = NULL;
            val_log(context, LOG_DEBUG, "bootstrap_referral(): Already fetching glue; not fetching again");
            matched_q->qc_state = Q_REFERRAL_ERROR;
            return VAL_NO_ERROR;
        }

        /* if we don't want partial referrals, return NULL */
        if (no_partial) {
            free_name_servers(&pending_glue);
            free_name_servers(ref_ns_list);
            *ref_ns_list = NULL;
            return VAL_NO_ERROR;
        }

        /*
         * Create a new referral if one does not exist 
         */
        if (matched_q->qc_referral == NULL) {
            ALLOCATE_REFERRAL_BLOCK(matched_q->qc_referral);
        } 
            
        matched_q->qc_referral->pending_glue_ns = pending_glue;
        matched_q->qc_referral->merged_glue_ns = *ref_ns_list;
        *ref_ns_list = NULL;
        
        /*
         * Create a query for glue for pending_ns 
         */
        flags = matched_qfq->qfq_flags |
                VAL_QUERY_GLUE_REQUEST;

        for (; pending_glue; pending_glue=pending_glue->ns_next) {

            
            if (VAL_NO_ERROR != (ret_val = add_to_qfq_chain(context,
                                       queries, pending_glue->ns_name_n, ns_t_a,
                                       ns_c_in, flags, &added_q)))
                return ret_val;

            /* use known name servers first */
            if (added_q && 
                added_q->qfq_query->qc_state == Q_INIT &&
                added_q->qfq_query->qc_ns_list == NULL &&
                matched_q->qc_referral->merged_glue_ns != NULL) {
               
                clone_ns_list(&added_q->qfq_query->qc_ns_list, 
                              matched_q->qc_referral->merged_glue_ns);
            }
        }
        
        matched_q->qc_state = Q_WAIT_FOR_GLUE;
    } else if (*ref_ns_list != NULL) {
        matched_q->qc_state = Q_INIT;
    } 

    return VAL_NO_ERROR;
}

/*
 * Clean up delegation_info structure
 */
void
free_referral_members(struct delegation_info *del)
{
    if (del == NULL)
        return;

    if (del->queries != NULL) {
        deregister_queries(&del->queries);
        del->queries = NULL;
    }
    if (del->answers != NULL) {
        res_sq_free_rrset_recs(&del->answers);
        del->answers = NULL;
    }
    if (del->qnames) {
        free_qname_chain(&del->qnames);
        del->qnames = NULL;
    }
    if (del->pending_glue_ns) {
        free_name_servers(&del->pending_glue_ns);
        del->pending_glue_ns = NULL;
    }
    if (del->merged_glue_ns) {
        free_name_servers(&del->merged_glue_ns);
        del->merged_glue_ns = NULL;
    }
    if (del->learned_zones) {
        res_sq_free_rrset_recs(&del->learned_zones);
        del->learned_zones = NULL;
    }

}


/*
 * wrapper around the additional query logic for aliases and
 * referrals.
 */
static int
follow_referral_or_alias_link(val_context_t * context,
                              int alias_chain,
                              u_int8_t * zone_n,
                              struct queries_for_query *matched_qfq,
                              struct rrset_rec **learned_zones,
                              struct qname_chain **qnames,
                              struct queries_for_query **queries,
                              struct rrset_rec **answers)
{
    int             ret_val;
    struct name_server *ref_ns_list;
    int             len;
    u_int8_t       *referral_zone_n;
    struct queries_for_query *added_q = NULL;
    struct val_query_chain *matched_q;
    u_int16_t       tzonestatus;
    u_int32_t       ttl_x = 0;

    if ((matched_qfq == NULL)  || (qnames == NULL) ||
        (learned_zones == NULL) || (queries == NULL) || (answers == NULL))
        return VAL_BAD_ARGUMENT;
    
    ref_ns_list = NULL;
    referral_zone_n = zone_n;
    matched_q = matched_qfq->qfq_query; /* Can never be NULL if matched_qfq is not NULL */

    if (matched_q->qc_respondent_server) {
        free_name_server(&matched_q->qc_respondent_server);
        matched_q->qc_respondent_server = NULL;
    }
    if (matched_q->qc_ns_list) {
        free_name_servers(&matched_q->qc_ns_list);
        matched_q->qc_ns_list = NULL;
    }

    if (matched_q->qc_referral == NULL) {
        ALLOCATE_REFERRAL_BLOCK(matched_q->qc_referral);
    } else if (alias_chain && matched_q->qc_referral->queries) {
        /* free up the old set of registered queries and start afresh */
        deregister_queries(&matched_q->qc_referral->queries);
        matched_q->qc_referral->queries = NULL;
    } 

    /*
     * Consume qnames 
     */
    if (matched_q->qc_referral->qnames == NULL)
        matched_q->qc_referral->qnames = *qnames;
    else if (*qnames) {
        struct qname_chain *t_q;
        for (t_q = *qnames; t_q->qnc_next; t_q = t_q->qnc_next);
        t_q->qnc_next = matched_q->qc_referral->qnames;
        matched_q->qc_referral->qnames = *qnames;
    }
    *qnames = NULL;

    /*
     * Consume answers
     */
    merge_rrset_recs(&matched_q->qc_referral->answers, *answers);
    *answers = NULL;

    matched_q->qc_state = Q_INIT;

    if (alias_chain) {
        /* don't believe any of the cname hints that were provided */
        res_sq_free_rrset_recs(learned_zones);
        *learned_zones = NULL;

        /*
         * find the referral_zone_n and ref_ns_list 
         */
        if (VAL_NO_ERROR !=
            find_nslist_for_query(context, matched_qfq, queries)) {
            val_log(context, LOG_DEBUG, 
                    "follow_referral_or_alias_link(): Cannot find name servers to send query for alias");
            matched_q->qc_state = Q_REFERRAL_ERROR;
            goto query_err;
        }
    } else {

        if (VAL_NO_ERROR != (ret_val =
                                 bootstrap_referral(context,
                                                    referral_zone_n,
                                                    learned_zones,
                                                    matched_qfq,
                                                    queries,
                                                    &ref_ns_list,
                                                    0))) /* ok to fetch glue here */
            return ret_val;

        if (matched_q->qc_state == Q_WAIT_FOR_GLUE) {
            matched_q->qc_referral->learned_zones = *learned_zones;        
        } else if (VAL_NO_ERROR != (ret_val = stow_zone_info(*learned_zones, matched_q))) {
            res_sq_free_rrset_recs(learned_zones);
            return ret_val;
        }
        *learned_zones = NULL; /* consumed */

        if (ref_ns_list == NULL &&
            (matched_q->qc_state != Q_WAIT_FOR_GLUE)) {
            /*
             * nowhere to look 
             */
            val_log(context, LOG_DEBUG, "follow_referral_or_alias_link(): Missing glue");
            matched_q->qc_state = Q_MISSING_GLUE;
            goto query_err;
        }

        {
            char            debug_name1[NS_MAXDNAME];
            char            debug_name2[NS_MAXDNAME];
            memset(debug_name1, 0, 1024);
            memset(debug_name2, 0, 1024);
            ns_name_ntop(matched_q->qc_name_n, debug_name1,
                     sizeof(debug_name1));
            ns_name_ntop(referral_zone_n, debug_name2, sizeof(debug_name2));
            val_log(context, LOG_DEBUG, "follow_referral_or_alias_link(): QUERYING '%s.' (referral to %s)",
                    debug_name1, debug_name2);
        }

        /*
         * Register the request name and zone with our referral monitor
         */
        if ((matched_q->qc_state != Q_WAIT_FOR_GLUE) &&
            register_query
            (&matched_q->qc_referral->queries, matched_q->qc_name_n,
            matched_q->qc_type_h, referral_zone_n) == ITS_BEEN_DONE) {
            /*
             * If this request has already been made then Referral Error
             */
            val_log(context, LOG_DEBUG, "follow_referral_or_alias_link(): Referral loop encountered");
            matched_q->qc_state = Q_REFERRAL_ERROR;
            goto query_err;
        }

        if (!(matched_qfq->qfq_flags & VAL_QUERY_DONT_VALIDATE)) {
            u_int8_t *tp = NULL;
            int diff_name = 0;

            if (VAL_NO_ERROR != (ret_val =
                get_zse(context, referral_zone_n, matched_qfq->qfq_flags, 
                        &tzonestatus, NULL, &ttl_x))) { 
                return ret_val;
            }
            SET_MIN_TTL(matched_q->qc_ttl_x, ttl_x);

            ttl_x = 0;
            if (VAL_NO_ERROR != (ret_val = 
                find_trust_point(context, referral_zone_n, 
                                 &tp, &ttl_x))) {
                return ret_val;
            }
            SET_MIN_TTL(matched_q->qc_ttl_x, ttl_x);

            if (tp) {
                diff_name = (namecmp(tp, referral_zone_n) != 0);
                FREE(tp);
            } 

            if (tzonestatus == VAL_AC_WAIT_FOR_TRUST) {
            
                /*
                 * Fetch DNSSEC meta-data in parallel 
                 */
                /*
                 * If we expect DNSSEC meta-data to be returned
                 * in the additional section of the response, we
                 * should modify the way in which we ask for the DNSKEY
                 * (the DS query logic should not be changed) as 
                 * follows:
                 *  - invoke the add_to_qfq_chain logic only if we are 
                 *    below the trust point (see the DS fetching logic below)
                 *  - instead of querying for the referral_zone_n/DNSKEY
                 *    query for the DNSKEY in the current zone 
                 *    (matched_q->qc_zonecut_n)
                 */
            
                if(VAL_NO_ERROR != 
                    (ret_val = add_to_qfq_chain(context, queries, 
                                            referral_zone_n, ns_t_dnskey,
                                            ns_c_in, matched_qfq->qfq_flags, &added_q)))
                    return ret_val;

                /* fetch DS only if are below the trust point */    
                if (diff_name) {
                
                    if (VAL_NO_ERROR != 
                        (ret_val = add_to_qfq_chain(context, queries, 
                                                    referral_zone_n, ns_t_ds,
                                                    ns_c_in, matched_qfq->qfq_flags, 
                                                    &added_q)))
                        return ret_val;
                } 
            }
        }
        /*
         * Store the current referral value in the query 
         */
        if (matched_q->qc_zonecut_n != NULL) {
            FREE(matched_q->qc_zonecut_n);
            matched_q->qc_zonecut_n = NULL;
        }
        if (referral_zone_n != NULL) {
            len = wire_name_length(referral_zone_n);
            matched_q->qc_zonecut_n =
                (u_int8_t *) MALLOC(len * sizeof(u_int8_t));
            if (matched_q->qc_zonecut_n == NULL)
                return VAL_OUT_OF_MEMORY;
            memcpy(matched_q->qc_zonecut_n, referral_zone_n, len);
        }
        matched_q->qc_ns_list = ref_ns_list;
    }

  query_err:
    if (matched_q->qc_state > Q_ERROR_BASE) {
        free_referral_members(matched_q->qc_referral);
        /*
         * don't free qc_referral itself 
         */
    }

    return VAL_NO_ERROR;
}


#define SAVE_RR_TO_LIST(respondent_server, listtype, name_n, type_h,    \
                        set_type_h, class_h, ttl_h, hptr, rdata,        \
                        rdata_len_h, from_section, authoritive, zonecut_n) \
    do {                                                                \
        struct rrset_rec *rr_set;                                       \
        int ret_val;                                                    \
        rr_set = find_rr_set (respondent_server, listtype, name_n, type_h, \
                              set_type_h, class_h, ttl_h, hptr, rdata,  \
                              from_section, authoritive, zonecut_n);    \
        if (rr_set==NULL) {                                             \
            ret_val = VAL_OUT_OF_MEMORY;                                \
        }                                                               \
        else {                                                          \
            if (type_h != ns_t_rrsig) {                                 \
                /* Add this record to its chain of val_rr_rec's. */         \
                ret_val = add_to_set(rr_set,rdata_len_h,rdata);         \
            } else  {                                                   \
                /* Add this record to the sig of rrset_rec. */          \
                ret_val = add_as_sig(rr_set,rdata_len_h,rdata);         \
            }                                                           \
        }                                                               \
        if (ret_val != VAL_NO_ERROR) {                                  \
            res_sq_free_rrset_recs(&learned_keys);                      \
            res_sq_free_rrset_recs(&learned_zones);                     \
            res_sq_free_rrset_recs(&learned_ds);                        \
            FREE(rdata);                                                \
            return ret_val;                                             \
        }                                                               \
    } while (0)

#define FIX_ZONECUT(the_rrset, zonecut_n, retval) do {                  \
        struct rrset_rec *cur_rrset;                                    \
        int len = wire_name_length(zonecut_n);                          \
        retval = VAL_NO_ERROR;                                          \
        for (cur_rrset = the_rrset; cur_rrset;                          \
                cur_rrset=cur_rrset->rrs_next){                         \
            if (cur_rrset->rrs_zonecut_n)                               \
                FREE(cur_rrset->rrs_zonecut_n);                         \
            cur_rrset->rrs_zonecut_n =                                  \
                    (u_int8_t *) MALLOC(len * sizeof(u_int8_t));        \
            if (cur_rrset->rrs_zonecut_n == NULL) {                     \
                retval = VAL_OUT_OF_MEMORY;                             \
                break;                                                  \
            } else {                                                    \
                memcpy(cur_rrset->rrs_zonecut_n, zonecut_n, len);       \
            }                                                           \
        }                                                               \
    } while (0)

/*
 * Check if CNAME or DNAME chain are invalid or contain a loop
 */
int
process_cname_dname_responses(u_int8_t *name_n, 
                              u_int16_t type_h, 
                              u_int8_t *rdata, 
                              struct val_query_chain *matched_q,
                              struct qname_chain **qnames,
                              int *referral_error)
{
    u_int8_t        temp_name[NS_MAXCDNAME];
    u_int8_t       *p;
    int ret_val;

    if (!name_n || !rdata || !matched_q || 
            !qnames || !(*qnames) )
       return VAL_BAD_ARGUMENT; 
    
    if (referral_error)
        *referral_error = 0;
    
    if (type_h == ns_t_cname &&
        matched_q->qc_type_h != ns_t_cname &&
        matched_q->qc_type_h != ns_t_rrsig &&
        matched_q->qc_type_h != ns_t_any &&
        namecmp((*qnames)->qnc_name_n, name_n) == 0) {
        
        /*
         * add the target 
         */
        if ((ret_val = add_to_qname_chain(qnames, rdata)) != VAL_NO_ERROR)
            return ret_val; 
        if (!matched_q->qc_referral)
            ALLOCATE_REFERRAL_BLOCK(matched_q->qc_referral);
            
        if (register_query(&matched_q->qc_referral->queries,
                           rdata,
                           matched_q->qc_type_h,
                           matched_q->qc_zonecut_n) == ITS_BEEN_DONE) {
            /*
             * If this request has already been made then Referral Error
             */
            matched_q->qc_state = Q_REFERRAL_ERROR;
            if (referral_error)
                *referral_error = 1;
            return VAL_NO_ERROR;
        }
        matched_q->qc_state = Q_INIT;
    }

    if (type_h == ns_t_dname &&
        matched_q->qc_type_h != ns_t_dname &&
        ((matched_q->qc_type_h != ns_t_any &&
         matched_q->qc_type_h != ns_t_rrsig)||
        namecmp((*qnames)->qnc_name_n, name_n) != 0) &&
        NULL != (p = (u_int8_t *) namename((*qnames)->qnc_name_n, name_n))) {

        u_int8_t       *qname_n = (*qnames)->qnc_name_n;
        int             len1 = p - qname_n;
        int             len2 = wire_name_length(rdata);
        if (len1 + len2 > sizeof(temp_name)) {
            matched_q->qc_state = Q_REFERRAL_ERROR;
            if (referral_error)
                *referral_error = 1;
            return VAL_NO_ERROR;
        }
        if (len1 > 0) {
            /*
             * add the DNAME owner name 
             */
            if ((ret_val = add_to_qname_chain(qnames, name_n)) != VAL_NO_ERROR)
                return ret_val; 
            if (!matched_q->qc_referral)
                ALLOCATE_REFERRAL_BLOCK(matched_q->qc_referral);

            if (register_query(&matched_q->qc_referral->queries,
                               name_n,
                               matched_q->qc_type_h,
                               matched_q->qc_zonecut_n) == ITS_BEEN_DONE) {
                /*
                 * If this request has already been made then Referral Error
                 */
                matched_q->qc_state = Q_REFERRAL_ERROR;
                if (referral_error)
                    *referral_error = 1;
                return VAL_NO_ERROR;
            }
        }
        /*
         * add the target 
         */
        memcpy(temp_name, qname_n, len1);
        memcpy(&temp_name[len1], rdata, len2);
        if ((ret_val = add_to_qname_chain(qnames,
                                        temp_name)) != VAL_NO_ERROR) {
           return ret_val; 
        }

        matched_q->qc_state = Q_INIT;
    }

    if (*qnames) {

        if (namecmp(matched_q->qc_name_n, (*qnames)->qnc_name_n))
            /*
             * Keep the current query name as the last name in the chain 
             */
            memcpy(matched_q->qc_name_n, (*qnames)->qnc_name_n,
                   wire_name_length((*qnames)->qnc_name_n));
    }

    return VAL_NO_ERROR;
}

/*
 * Create error rrset_rec structure
 */
int
prepare_empty_nxdomain(struct rrset_rec **answers,
                       struct name_server *respondent_server,
                       const u_int8_t * query_name_n,
                       u_int16_t query_type_h, u_int16_t query_class_h,
                       u_int8_t       *hptr)
{
    size_t          length = wire_name_length(query_name_n);

    if (answers == NULL || length == 0)
        return VAL_BAD_ARGUMENT;

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
    if (hptr) {
        (*answers)->rrs.val_msg_header =
            (u_int8_t *) MALLOC(sizeof(HEADER) * sizeof(u_int8_t));
        if ((*answers)->rrs.val_msg_header == NULL) {
            FREE((*answers)->rrs.val_rrset_name_n);
            FREE(*answers);
            *answers = NULL;
            return VAL_OUT_OF_MEMORY;
        }
        memcpy((*answers)->rrs.val_msg_header, hptr, sizeof(HEADER));
        (*answers)->rrs.val_msg_headerlen = sizeof(HEADER);
    } else {
        (*answers)->rrs.val_msg_header = NULL;
        (*answers)->rrs.val_msg_headerlen = 0;
    }
    (*answers)->rrs.val_rrset_type_h = query_type_h;
    (*answers)->rrs.val_rrset_class_h = query_class_h;
    (*answers)->rrs.val_rrset_ttl_h = 0;
    (*answers)->rrs_cred = SR_CRED_UNSET;
    (*answers)->rrs.val_rrset_section = VAL_FROM_UNSET;
    if ((respondent_server) &&
        (respondent_server->ns_number_of_addresses > 0)) {
        (*answers)->rrs.val_rrset_server =
            (struct sockaddr *) MALLOC(sizeof(struct sockaddr_storage));
        if ((*answers)->rrs.val_rrset_server == NULL) {
            FREE((*answers)->rrs.val_rrset_name_n);
            FREE(*answers);
            *answers = NULL;
            return VAL_OUT_OF_MEMORY;
        }
        memcpy((*answers)->rrs.val_rrset_server,
               respondent_server->ns_address[0],
               sizeof(struct sockaddr_storage));
    } else {
        (*answers)->rrs.val_rrset_server = NULL;
    }
    (*answers)->rrs.val_rrset_data = NULL;
    (*answers)->rrs.val_rrset_sig = NULL;
    (*answers)->rrs_next = NULL;

    return VAL_NO_ERROR;
}

/*
 * The main routine for processing response data
 *  
 * RRsets in the answer and authority sections are extracted as is any
 * referral information present in the additional section of the response. Any
 * DS or DNSKEY information is also cached for future use. 
 * The validator follows any referrals or aliases that are returned as part of
 * the response and issues queries to fetch any missing glue. Information gathered
 * as part of following referrals are maintained separately within the val_query_chain
 * structure. Once the referral operation completes, all information within
 * this entry are merged into the validator cache.
 * 
 * The validator keeps track of nameservers that it actually used while following
 * referrals.  These are re-used in future requests for data in the same zone.
 */
static int
digest_response(val_context_t * context,
                struct queries_for_query *matched_qfq,
                struct queries_for_query **queries,
                u_int8_t * response_data,
                u_int32_t response_length, struct domain_info *di_response)
{
    u_int16_t       question, answer, authority, additional;
    u_int16_t       rrs_to_go;
    int             i;
    int             response_index;
    u_int8_t        name_n[NS_MAXCDNAME];
    u_int16_t       type_h;
    u_int16_t       set_type_h;
    u_int16_t       class_h;
    u_int32_t       ttl_h;
    u_int16_t       rdata_len_h;
    int             rdata_index;
    int             authoritive;
    u_int8_t       *rdata;
    u_int8_t       *hptr;
    int             ret_val;
    int             nothing_other_than_alias;
    int             from_section;
    struct rrset_rec *learned_zones = NULL;
    struct rrset_rec *learned_keys = NULL;
    struct rrset_rec *learned_ds = NULL;
    struct rrset_rec *learned_answers = NULL;
    struct rrset_rec *learned_proofs = NULL;

    const u_int8_t *query_name_n;
    u_int16_t       query_type_h;
    u_int16_t       query_class_h;
    u_int16_t       tzonestatus;
    u_int8_t       *rrs_zonecut_n = NULL;
    int             referral_seen = FALSE;
    u_int8_t        referral_zone_n[NS_MAXCDNAME];
    int             auth_nack = 0;
    int             proof_seen = 0;
    HEADER         *header;
    u_int8_t       *end;
    int             qnamelen, tot;
    struct name_server *ns = NULL;
    int len;
    struct qname_chain **qnames;
    int             zonecut_was_modified = 0;
    u_int32_t ttl_x = 0;
    struct val_query_chain *matched_q;
    struct name_server *respondent_server;

    if ((matched_qfq == NULL) || (queries == NULL) ||
        (di_response == NULL) || (response_data == NULL))
        return VAL_BAD_ARGUMENT;

    matched_q = matched_qfq->qfq_query; /* Can never be NULL if matched_qfq is not NULL */
    respondent_server = matched_q->qc_respondent_server;
    
    qnames = &(di_response->di_qnames);
    header = (HEADER *) response_data;
    end = (u_int8_t *) ((u_int32_t) response_data + response_length);

    query_name_n = matched_q->qc_name_n;
    query_type_h = matched_q->qc_type_h;
    query_class_h = matched_q->qc_class_h;
    *qnames = NULL;
    di_response->di_answers = NULL; 
    di_response->di_proofs = NULL;
    hptr = NULL;
    rdata = NULL;

    question = ntohs(header->qdcount);
    answer = ntohs(header->ancount);
    authority = ntohs(header->nscount);
    additional = ntohs(header->arcount);
    if (answer == 0)
        nothing_other_than_alias = 0;
    else
        nothing_other_than_alias = 1;

    /*
     *  Skip question section 
     */

    if (response_length <= sizeof(HEADER)) {
        response_index = 0;
    } else {
        qnamelen = wire_name_length(&response_data[sizeof(HEADER)]);
        tot = sizeof(HEADER) + qnamelen + sizeof(u_int32_t);
        if (tot <= response_length) {
            hptr = response_data;
            response_index = tot;
        } else
            response_index = 0;
    }

    rrs_to_go = answer + authority + additional;

    /*
     * Add the query name to the chain of acceptable names 
     */
    if ((ret_val =
         add_to_qname_chain(qnames, query_name_n)) != VAL_NO_ERROR)
        return ret_val;

    if (rrs_to_go == 0 /*&& header->rcode == ns_r_nxdomain */ ) {
        /*
         * We got a response with no records 
         * Create a dummy answer record to handle this.  
         */
        matched_q->qc_state = Q_ANSWERED;
        return prepare_empty_nxdomain(&di_response->di_proofs, respondent_server,
                                      query_name_n, query_type_h, query_class_h, hptr);
    }

    /*
     * Extract zone cut from the query chain element if it exists 
     */
    rrs_zonecut_n = matched_q->qc_zonecut_n;

    for (i = 0; i < rrs_to_go; i++) {

        rdata = NULL;

        /*
         * Determine what part of the response I'm reading 
         */

        if (i < answer)
            from_section = VAL_FROM_ANSWER;
        else if (i < answer + authority)
            from_section = VAL_FROM_AUTHORITY;
        else
            from_section = VAL_FROM_ADDITIONAL;

        /*
         * Response_index points to the beginning of an RR 
         * Grab the uncompressed name, type, class, ttl, rdata_len 
         * If the type is a signature, get the type_covered 
         * Leave a pointer to the rdata 
         * Advance the response_index 
         */

        if ((ret_val =
             extract_from_rr(response_data, &response_index, end, name_n,
                             &type_h, &set_type_h, &class_h, &ttl_h,
                             &rdata_len_h,
                             &rdata_index)) != VAL_NO_ERROR) {
            goto done;
        }

        authoritive = (header->aa == 1)
            && qname_chain_first_name(*qnames, name_n);

        /*
         * response[rdata_index] is the first byte of the RDATA of the
         * record.  The data may contain domain names in compressed format,
         * so they need to be expanded.  This is type-dependent...
         */
        if ((ret_val =
             decompress(&rdata, response_data, rdata_index, end, type_h,
                        &rdata_len_h)) != VAL_NO_ERROR) {
            goto done;
        }

        /*
         * Check if the only RRsets in the answer section are CNAMEs/DNAMEs
         */
        if (nothing_other_than_alias && (i < answer)) {
            nothing_other_than_alias =
                ((set_type_h == ns_t_cname) || (set_type_h == ns_t_dname));
            /*
             * check if we had explicitly asked for this alias 
             */
            if (nothing_other_than_alias) {
                if ((((query_type_h == ns_t_cname)
                      && (set_type_h == ns_t_cname))
                     || ((query_type_h == ns_t_dname)
                         && (set_type_h == ns_t_dname))
                     || (query_type_h == ns_t_any)
                     || (query_type_h == ns_t_rrsig))
                    && (!namecmp(name_n, (*qnames)->qnc_name_n)))
                    nothing_other_than_alias = 0;
            }
        }

        auth_nack = (from_section == VAL_FROM_AUTHORITY)
            && ((set_type_h == ns_t_nsec)
#ifdef LIBVAL_NSEC3
                || (set_type_h == ns_t_nsec3)
#endif
                || (set_type_h == ns_t_soa));

        proof_seen = (proof_seen) ? 1 : auth_nack;      /* save the auth_nack status */


        if (from_section == VAL_FROM_ANSWER) {
            int referral_error = 0;

            SAVE_RR_TO_LIST(respondent_server, &learned_answers, name_n, type_h,
                            set_type_h, class_h, ttl_h, hptr, rdata,
                            rdata_len_h, from_section, authoritive,
                            rrs_zonecut_n);

            /* process CNAMEs or DNAMEs if they exist */
            if ((VAL_NO_ERROR != (ret_val = 
                    process_cname_dname_responses(name_n, type_h, rdata, 
                                                  matched_q, qnames, 
                                                  &referral_error))) || 
                    (referral_error)) {
                if (referral_error) 
                    val_log(context, LOG_DEBUG, "disgest_response(): CNAME/DNAME error or loop encountered");

                goto done;
            }


        } else if (auth_nack) {
            SAVE_RR_TO_LIST(respondent_server, &learned_proofs, name_n, type_h,
                            set_type_h, class_h, ttl_h, hptr, rdata,
                            rdata_len_h, from_section, authoritive,
                            rrs_zonecut_n);
        }

        if (set_type_h == ns_t_soa) {
            /*
             * If there is an SOA RRset, use its owner name as the zone-cut 
             * we need this if the parent is also authoritative for the child or if
             * recursion is enabled on the parent zone.
             * Although we may end up "fixing" the zone cut for even out-of-zone
             * data (think of out-of-bailiwick glue), these records will not
             * be saved because of the anti-pollution rules.
             */
            if (zonecut_was_modified) {
                if (namecmp(rrs_zonecut_n, name_n)) {
                    /*
                     * Multiple NS records;
                     */
                    val_log(context, LOG_DEBUG, "digest_response(): Ambiguous referral zonecut");
                    matched_q->qc_state =
                        Q_CONFLICTING_ANSWERS;
                    ret_val = VAL_NO_ERROR;
                    goto done;
                }
            } else {
                zonecut_was_modified = 1;
                /* update the zonecut information */
                if (matched_q->qc_zonecut_n)
                    FREE(matched_q->qc_zonecut_n);
                len = wire_name_length(name_n);
                matched_q->qc_zonecut_n = 
                    (u_int8_t *) MALLOC (len * sizeof(u_int8_t));
                if (matched_q->qc_zonecut_n == NULL)
                    goto done;    
                memcpy (matched_q->qc_zonecut_n, name_n, len);
                rrs_zonecut_n = matched_q->qc_zonecut_n;
                /*
                 * go back to all the rrsets that we created 
                 * and fix the zonecut info 
                 */
                FIX_ZONECUT(learned_answers, rrs_zonecut_n, ret_val);
                if (ret_val != VAL_NO_ERROR)
                    goto done;
                FIX_ZONECUT(learned_proofs, rrs_zonecut_n, ret_val);
                if (ret_val != VAL_NO_ERROR)
                    goto done;
                FIX_ZONECUT(learned_zones, rrs_zonecut_n, ret_val);
                if (ret_val != VAL_NO_ERROR)
                    goto done;
                FIX_ZONECUT(learned_keys, rrs_zonecut_n, ret_val);
                if (ret_val != VAL_NO_ERROR)
                    goto done;
                FIX_ZONECUT(learned_ds, rrs_zonecut_n, ret_val);
                if (ret_val != VAL_NO_ERROR)
                    goto done;
            }
        } else if (set_type_h == ns_t_dnskey) {
            SAVE_RR_TO_LIST(respondent_server, &learned_keys, name_n,
                            type_h, set_type_h, class_h, ttl_h, hptr,
                            rdata, rdata_len_h, from_section,
                            authoritive, rrs_zonecut_n);
        } else if (set_type_h == ns_t_ds) {
            SAVE_RR_TO_LIST(respondent_server, &learned_ds, name_n, type_h,
                            set_type_h, class_h, ttl_h, hptr, rdata,
                            rdata_len_h, from_section, authoritive,
                            rrs_zonecut_n);
        } else if ((set_type_h == ns_t_ns) ||
            ((set_type_h == ns_t_a)
             && (from_section == VAL_FROM_ADDITIONAL))) {

            if ((set_type_h == ns_t_ns) && !proof_seen) {

                if ((answer == 0) && (from_section == VAL_FROM_AUTHORITY)) {
                    /*
                     * This is a referral 
                     */
                    if (referral_seen == FALSE) {
                        memcpy(referral_zone_n, name_n,
                               wire_name_length(name_n));
                        referral_seen = TRUE;
                    } else if (namecmp(referral_zone_n, name_n) != 0) {
                        /*
                         * Multiple NS records; Malformed referral notice 
                         */
                        val_log(context, LOG_DEBUG, "digest_response(): Ambiguous referral zonecut");
                        matched_q->qc_state =
                                Q_REFERRAL_ERROR;
                        ret_val = VAL_NO_ERROR;
                        goto done;
                    }

                } else if ((rrs_zonecut_n == NULL || 
                            NULL != namename(name_n, rrs_zonecut_n)) && 
                        /* ns owner is more specific than current zonecut  AND */
                           ((nothing_other_than_alias && /* cname  OR */ 
                            (from_section == VAL_FROM_AUTHORITY)) ||
                           ((answer != 0) && /* complete answer */
                            !nothing_other_than_alias &&
                            (from_section != VAL_FROM_ADDITIONAL)))) {

                    /* This is zonecut information */

                    /*
                     * Use the NS rrset owner name as the zone-cut 
                     */
                    if (zonecut_was_modified) {
                        if (namecmp(rrs_zonecut_n, name_n)) {
                            /*
                             * Multiple NS records;
                             */
                            val_log(context, LOG_DEBUG, "digest_response(): Ambiguous referral zonecut");
                            matched_q->qc_state =
                                Q_CONFLICTING_ANSWERS;
                            ret_val = VAL_NO_ERROR;
                            goto done;
                        }
                    } else {
                        /* update the zonecut information */
                        if (matched_q->qc_zonecut_n)
                            FREE(matched_q->qc_zonecut_n);
                        len = wire_name_length(name_n);
                        matched_q->qc_zonecut_n = 
                            (u_int8_t *) MALLOC (len * sizeof(u_int8_t));
                        if (matched_q->qc_zonecut_n == NULL)
                            goto done;    
                        memcpy (matched_q->qc_zonecut_n, name_n, len);
                        rrs_zonecut_n = matched_q->qc_zonecut_n;
                        zonecut_was_modified = 1;
                        /*
                         * go back to all the rrsets that we created 
                         * and fix the zonecut info 
                         * we need this if the parent is also authoritative 
                         * for the child or if recursion is enabled on the 
                         * parent zone.
                         * Although we may end up "fixing" the zone cut for 
                         * even out-of-zone data (think of out-of-bailiwick glue), 
                         * these records will not be saved because of the 
                         * anti-pollution rules.
                         */
                        FIX_ZONECUT(learned_answers, rrs_zonecut_n, ret_val);
                        if (ret_val != VAL_NO_ERROR)
                            goto done;
                        FIX_ZONECUT(learned_proofs, rrs_zonecut_n, ret_val);
                        if (ret_val != VAL_NO_ERROR)
                            goto done;
                        FIX_ZONECUT(learned_zones, rrs_zonecut_n, ret_val);
                        if (ret_val != VAL_NO_ERROR)
                            goto done;
                        FIX_ZONECUT(learned_keys, rrs_zonecut_n, ret_val);
                        if (ret_val != VAL_NO_ERROR)
                            goto done;
                        FIX_ZONECUT(learned_ds, rrs_zonecut_n, ret_val);
                        if (ret_val != VAL_NO_ERROR)
                            goto done;
                    }

                }
            }

            /* 
             * The zonecut information for name servers is 
             * their respective owner name 
             */
            SAVE_RR_TO_LIST(respondent_server, &learned_zones, name_n,
                            type_h, set_type_h, class_h, ttl_h, hptr,
                            rdata, rdata_len_h, from_section,
                            authoritive, name_n);
        }

        FREE(rdata);
        rdata = NULL;
    }

    if (referral_seen || nothing_other_than_alias) {
        struct rrset_rec *cloned_answers;
        cloned_answers = copy_rrset_rec_list(learned_answers);

        if (VAL_NO_ERROR != (ret_val =
            follow_referral_or_alias_link(context,
                                          nothing_other_than_alias,
                                          referral_zone_n, matched_qfq,
                                          &learned_zones, qnames,
                                          queries, &cloned_answers))) {
            res_sq_free_rrset_recs(&cloned_answers);
            goto done;
        }
        cloned_answers = NULL; /* consumed */
        learned_zones = NULL; /* consumed */

    } else {

        /* we no longer need learned_zones */
        res_sq_free_rrset_recs(&learned_zones);

        /*
         * if we hadn't enabled EDNS0 but we got a response for a zone 
         * where DNSSEC is enabled, retry with EDNS0 enabled
         * This can occur if a name server a name server is 
         * authoritative for the parent zone as well as the 
         * child zone, or if one of the name servers reached while 
         * following referrals is also recursive
         */
        
        if (VAL_NO_ERROR != (ret_val =
                get_zse(context, matched_q->qc_name_n, 
                        matched_qfq->qfq_flags, &tzonestatus, NULL, &ttl_x))) { 
            goto done;
        }
        SET_MIN_TTL(matched_q->qc_ttl_x, ttl_x);
        
        if (tzonestatus == VAL_AC_WAIT_FOR_TRUST
            && matched_q->qc_respondent_server
            && !(matched_qfq->qfq_flags & VAL_QUERY_DONT_VALIDATE)
            && !(matched_q->qc_respondent_server->
                 ns_options & RES_USE_DNSSEC)) {

            free_name_server(&matched_q->qc_respondent_server);
            matched_q->qc_respondent_server = NULL;
            matched_q->qc_trans_id = -1;
            matched_q->qc_state = Q_INIT;
            val_log(context, LOG_DEBUG,
                    "digest_response(): EDNS0 was not used; re-issuing query");
            val_log(context, LOG_DEBUG, "digest_response(): Setting D0 bit and using EDNS0");
            for (ns = matched_q->qc_ns_list; ns; ns = ns->ns_next)
                ns->ns_options |= RES_USE_DNSSEC;
            ret_val = VAL_NO_ERROR;
            goto done;
        }

        di_response->di_answers = copy_rrset_rec_list(learned_answers);
        di_response->di_proofs = copy_rrset_rec_list(learned_proofs);
        
        /*
         * Check if this is the response to a referral request 
         */
        if (matched_q->qc_referral != NULL) {

            /*
             * Consume answers
             */
            merge_rrset_recs(&matched_q->qc_referral->answers, di_response->di_answers);
            di_response->di_answers = matched_q->qc_referral->answers;
            matched_q->qc_referral->answers = NULL;

            /*
             * Consume qnames
             */
            if (*qnames == NULL)
                *qnames = matched_q->qc_referral->qnames;
            else if (matched_q->qc_referral->qnames) {
                struct qname_chain *t_q;
                for (t_q = *qnames; t_q->qnc_next; t_q = t_q->qnc_next);
                t_q->qnc_next = matched_q->qc_referral->qnames;
            }
            matched_q->qc_referral->qnames = NULL;

            /*
             * Note that we don't free qc_referral here 
             */
            free_referral_members(matched_q->qc_referral);
        } 

        matched_q->qc_state = Q_ANSWERED;
        ret_val = VAL_NO_ERROR;

        /*
         * if we were fetching glue here, save a copy as zone info 
         */
        if ((matched_qfq->qfq_flags & VAL_QUERY_GLUE_REQUEST) && (answer != 0) 
                && !proof_seen && !nothing_other_than_alias) {
            struct rrset_rec *gluedata = copy_rrset_rec(learned_answers);
            if (VAL_NO_ERROR != (ret_val = stow_zone_info(gluedata, matched_q))) {
                res_sq_free_rrset_recs(&gluedata);
                goto done;
            }
        }
    }

    if (VAL_NO_ERROR != (ret_val = stow_answers(learned_answers, matched_q))) {
        goto done;
    }

    if (VAL_NO_ERROR != (ret_val = stow_negative_answers(learned_proofs, matched_q))) {
        goto done;
    }

    if (VAL_NO_ERROR != (ret_val = stow_key_info(learned_keys, matched_q))) {
        goto done;
    }

    if (VAL_NO_ERROR != (ret_val = stow_ds_info(learned_ds, matched_q))) {
        goto done;
    }


    return ret_val;

  done:
    if (rdata)
        FREE(rdata);
    res_sq_free_rrset_recs(&learned_answers);
    res_sq_free_rrset_recs(&learned_proofs);
    res_sq_free_rrset_recs(&learned_zones);
    res_sq_free_rrset_recs(&learned_keys);
    res_sq_free_rrset_recs(&learned_ds);
    return ret_val;
}
/*
 * This is the interface between libval and libsres for sending queries
 */
int
val_resquery_send(val_context_t * context,
                  struct queries_for_query *matched_qfq)
{
    char            name_p[NS_MAXDNAME];
    char            name_buf[INET6_ADDRSTRLEN + 1];
    int             ret_val;
    struct name_server *tempns;
    struct val_query_chain *matched_q;

    /*
     * Get a (set of) answer(s) from the default NS's.
     * If nslist is NULL, read the cached zones and name servers
     * in context to create the nslist
     */
    struct name_server *nslist;
    int ends0_size;

    if ((matched_qfq == NULL) || 
            (matched_qfq->qfq_query->qc_ns_list == NULL)) {
        return VAL_BAD_ARGUMENT;
    }
    matched_q = matched_qfq->qfq_query; /* Can never be NULL if matched_qfq is not NULL */
    nslist = matched_q->qc_ns_list;

    if (ns_name_ntop(matched_q->qc_name_n, name_p, sizeof(name_p)) == -1) {
        return VAL_BAD_ARGUMENT;
    }

    val_log(context, LOG_DEBUG, "val_resquery_send(): Sending query for %s to:", name_p);
    for (tempns = nslist; tempns; tempns = tempns->ns_next) {
        val_log(context, LOG_DEBUG, "    %s",
                val_get_ns_string((struct sockaddr *)tempns->ns_address[0],
                                  name_buf, sizeof(name_buf)));
    }
    val_log(context, LOG_DEBUG, "val_resquery_send(): End of Sending query for %s", name_p);

    ends0_size = (context && context->g_opt)? context->g_opt->edns0_size : EDNS_UDP_SIZE;
    if ((ret_val =
         query_send(name_p, matched_q->qc_type_h, matched_q->qc_class_h,
                    nslist, ends0_size, &(matched_q->qc_trans_id))) == SR_UNSET)
        return VAL_NO_ERROR;

    /*
     * ret_val contains a resolver error 
     */
    matched_q->qc_state = Q_QUERY_ERROR;
    return VAL_NO_ERROR;
}

/*
 * This is the interface between libval and libsres for receiving responses 
 */
int
val_resquery_rcv(val_context_t * context,
                 struct queries_for_query *matched_qfq,
                 struct domain_info **response,
                 struct queries_for_query **queries,
                 fd_set *pending_desc,
                 struct timeval *closest_event)
{
    struct name_server *server = NULL;
    u_int8_t       *response_data = NULL;
    u_int32_t       response_length = 0;
    char            name_p[NS_MAXDNAME];
    struct val_query_chain *matched_q;

    int             ret_val;

    if ((matched_qfq == NULL) || (response == NULL) || (queries == NULL) || (pending_desc == NULL))
        return VAL_BAD_ARGUMENT;

    matched_q = matched_qfq->qfq_query; /* Can never be NULL if matched_qfq is not NULL */
    *response = NULL;
    ret_val = response_recv(&(matched_q->qc_trans_id), pending_desc, closest_event,
                            &server, &response_data, &response_length);
    if (ret_val == SR_NO_ANSWER_YET)
        return VAL_NO_ERROR;

    matched_q->qc_respondent_server = server;

    if (ret_val != SR_UNSET) {
        if (response_data)
            FREE(response_data);
        matched_q->qc_state = Q_RESPONSE_ERROR;
        return VAL_NO_ERROR;
    }

    if (ns_name_ntop(matched_q->qc_name_n, name_p, sizeof(name_p)) == -1) {
        matched_q->qc_state = Q_RESPONSE_ERROR;
        if (response_data)
            FREE(response_data);
        return VAL_NO_ERROR;
    }

    *response = (struct domain_info *) MALLOC(sizeof(struct domain_info));
    if (*response == NULL) {
        if (response_data)
            FREE(response_data);
        return VAL_OUT_OF_MEMORY;
    }

    /*
     * Initialize the response structure 
     */
    (*response)->di_answers = NULL;
    (*response)->di_proofs = NULL;
    (*response)->di_qnames = NULL;
    (*response)->di_requested_type_h = matched_q->qc_type_h;
    (*response)->di_requested_class_h = matched_q->qc_class_h;

    if (((*response)->di_requested_name_h = STRDUP(name_p)) == NULL) {
        FREE(*response);
        *response = NULL;
        if (response_data)
            FREE(response_data);
        return VAL_OUT_OF_MEMORY;
    }

    if ((ret_val = digest_response(context, matched_qfq,
                                   queries, response_data, response_length,
                                   *response) != VAL_NO_ERROR)) {
        free_domain_info_ptrs(*response);
        FREE(*response);
        *response = NULL;
        FREE(response_data);
        return ret_val;
    }

    if (matched_q->qc_state > Q_ERROR_BASE)
        (*response)->di_res_error = matched_q->qc_state;
    else
        (*response)->di_res_error = SR_UNSET;


    FREE(response_data);
    /*
     * What happens when an empty NXDOMAIN is returned? 
     */
    /*
     * What happens when an empty NOERROR is returned? 
     */

    return VAL_NO_ERROR;
}

