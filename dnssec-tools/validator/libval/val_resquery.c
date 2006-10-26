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
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>

#include <resolv.h>

#include <resolver.h>
#include <validator.h>
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

#include "val_resquery.h"
#include "val_support.h"
#include "val_cache.h"
#include "val_assertion.h"
#include "val_log.h"

#define ITS_BEEN_DONE   0
#define IT_HASNT        1
#define IT_WONT         (-1)

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

#define STRIP_LABEL(name, newname) do {\
	int label_len;\
	label_len = name[0];\
	if (label_len == 0) {\
		return VAL_NO_ERROR;\
	}\
	newname = name + label_len + 1;\
} while(0)

#define ALLOCATE_REFERRAL_BLOCK(ref) do{ \
		ref = (struct delegation_info *) MALLOC (sizeof(struct delegation_info)); \
		if (ref == NULL) \
			return VAL_OUT_OF_MEMORY; \
		ref->queries = NULL; \
		ref->qnames = NULL; \
		ref->pending_glue_ns = NULL; \
		ref->glueptr = NULL; \
} while(0)


/*
 *
 * returns
 *         ITS_BEEN_DONE
 *         IT_HASNT
 *         IT_WONT
 */
static int
register_query(struct query_list **q, u_int8_t * name_n, u_int32_t type_h,
               u_int8_t * zone_n)
{
    if ((q == NULL) || (name_n == NULL) || (zone_n == NULL))
        return IT_WONT;

    if (*q == NULL) {
        *q = (struct query_list *) MALLOC(sizeof(struct query_list));
        if (*q == NULL) {
            return IT_WONT;     /* Out of memory */
        }
        memcpy((*q)->ql_name_n, name_n, wire_name_length(name_n));
        memcpy((*q)->ql_zone_n, zone_n, wire_name_length(zone_n));
        (*q)->ql_type_h = type_h;
        (*q)->ql_next = NULL;
    } else {
        struct query_list *cur_q = (*q);

        while (cur_q->ql_next != NULL) {
            if (namecmp(cur_q->ql_zone_n, zone_n) == 0
                && namecmp(cur_q->ql_name_n, name_n) == 0)
                return ITS_BEEN_DONE;
            cur_q = cur_q->ql_next;
        }
        if (namecmp(cur_q->ql_zone_n, zone_n) == 0
            && namecmp(cur_q->ql_name_n, name_n) == 0)
            return ITS_BEEN_DONE;
        cur_q->ql_next =
            (struct query_list *) MALLOC(sizeof(struct query_list));
        if (cur_q->ql_next == NULL) {
            return IT_WONT;     /* Out of memory */
        }
        cur_q = cur_q->ql_next;
        memcpy(cur_q->ql_name_n, name_n, wire_name_length(name_n));
        memcpy(cur_q->ql_zone_n, zone_n, wire_name_length(zone_n));
        cur_q->ql_type_h = type_h;
        cur_q->ql_next = NULL;
    }
    return IT_HASNT;
}

static void
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

int
extract_glue_from_rdata(struct rr_rec *addr_rr, struct name_server **ns)
{
    struct sockaddr_in *sock_in;

    if ((ns == NULL) || (*ns == NULL))
        return VAL_BAD_ARGUMENT;

    while (addr_rr) {
        int i;
        struct sockaddr_storage **new_addr = NULL;

        CREATE_NSADDR_ARRAY(new_addr, (*ns)->ns_number_of_addresses+1);
        if (new_addr == NULL) {
            return VAL_OUT_OF_MEMORY;
        }
            
        for(i=0; i< (*ns)->ns_number_of_addresses; i++) {
            memcpy(new_addr[i], (*ns)->ns_address[i], sizeof(struct sockaddr_storage)); 
        }
        for(i=0; i<(*ns)->ns_number_of_addresses; i++) {
            FREE((*ns)->ns_address[i]);
        }
        if ((*ns)->ns_address)
            FREE((*ns)->ns_address);
        (*ns)->ns_address = new_addr;

        sock_in = (struct sockaddr_in *)
            (*ns)->ns_address[(*ns)->ns_number_of_addresses];

        sock_in->sin_family = AF_INET;
        sock_in->sin_port = htons(DNS_PORT);
        memset(sock_in->sin_zero, 0, sizeof(sock_in->sin_zero));
        memcpy(&(sock_in->sin_addr), addr_rr->rr_rdata, sizeof(u_int32_t));

        (*ns)->ns_number_of_addresses++;
        addr_rr = addr_rr->rr_next;

    }
    return VAL_NO_ERROR;
}

void
merge_glue_in_referral(struct val_query_chain *pc,
                       struct val_query_chain **queries)
{
    int             retval;
    struct val_query_chain *glueptr;
    struct name_server *pending_ns;

    if ((queries == NULL) || (pc == NULL) || (pc->qc_referral == NULL) ||
        (pc->qc_referral->glueptr == NULL))
        return;                 // xxx-check: log message?

    glueptr = pc->qc_referral->glueptr;

    /*
     * Check if glue was obtained 
     */
    if ((glueptr->qc_state == Q_ANSWERED) &&
        (glueptr->qc_ans != NULL) &&
        (glueptr->qc_ans->_as.ac_data != NULL)) {

        if (glueptr->qc_ans->_as.ac_data->rrs.val_rrset_type_h != ns_t_a) {
            pc->qc_state = Q_ERROR_BASE + SR_REFERRAL_ERROR;
        } else if (VAL_NO_ERROR !=
                   (retval =
                    extract_glue_from_rdata(glueptr->qc_ans->_as.ac_data->
                                            rrs.val_rrset_data,
                                            &pc->qc_referral->
                                            pending_glue_ns))) {
            glueptr->qc_state = Q_ERROR_BASE + SR_RCV_INTERNAL_ERROR;
        } else {
            if (pc->qc_ns_list) {
                free_name_servers(&pc->qc_ns_list);
                pc->qc_ns_list = NULL;
            }
            if (pc->qc_respondent_server) {
                free_name_server(&pc->qc_respondent_server);
                pc->qc_respondent_server = NULL;
            }
            if (pc->qc_zonecut_n != NULL) {
                FREE(pc->qc_zonecut_n);
                pc->qc_zonecut_n = NULL;
            }

            pending_ns = pc->qc_referral->pending_glue_ns;
            pc->qc_referral->pending_glue_ns = NULL;

            /*
             * forget about the name servers that don't have any glue 
             */
            if (pending_ns->ns_next)
                free_name_servers(&pending_ns->ns_next);
            pending_ns->ns_next = NULL;

            pc->qc_ns_list = pending_ns;
            pc->qc_state = Q_INIT;
            pc->qc_referral->glueptr = NULL;
        }
    }

    if (glueptr->qc_state > Q_ERROR_BASE) {

        /*
         * look for next ns to send our glue request to 
         */
        if (pc->qc_referral->pending_glue_ns == NULL)
            pending_ns = NULL;
        else {
            pending_ns = pc->qc_referral->pending_glue_ns->ns_next;
            free_name_server(&pc->qc_referral->pending_glue_ns);
            pc->qc_referral->pending_glue_ns = pending_ns;
        }
        if (pending_ns == NULL) {
            pc->qc_state = Q_ERROR_BASE + SR_MISSING_GLUE;
        } else {
            add_to_query_chain(queries, pending_ns->ns_name_n, ns_t_a,
                               ns_c_in);
            pc->qc_referral->glueptr = *queries;
            pc->qc_referral->glueptr->qc_glue_request = 1;
        }
    }
}

int
res_zi_unverified_ns_list(struct name_server **ns_list,
                          u_int8_t * zone_name,
                          struct rrset_rec *unchecked_zone_info,
                          struct name_server **pending_glue)
{
    /*
     * Look through the unchecked_zone stuff for answers 
     */
    struct rrset_rec *unchecked_set;
    struct rrset_rec *trailer;
    struct rr_rec  *ns_rr;
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

    unchecked_set = unchecked_zone_info;
    while (unchecked_set != NULL) {
        if (unchecked_set->rrs.val_rrset_type_h == ns_t_ns &&
            (namecmp(zone_name, unchecked_set->rrs.val_rrset_name_n) == 0))
        {
            if ((*ns_list != NULL) && (trailer != NULL)) {
                /*
                 * We've hit a duplicate, remove it from the list 
                 */
                /*
                 * Now that I'm thinking about it, I may remove duplicates
                 * during the stowage of the zone information.
                 * If so, this code may never get executed.
                 */
                // xxx-audit: dereference of unitialized ptr
                //     the first time through this loop, trailer is
                //     uninitialized.
                trailer->rrs_next = unchecked_set->rrs_next;
                unchecked_set->rrs_next = NULL;
                res_sq_free_rrset_recs(&unchecked_set);
                unchecked_set = trailer;
            } else {
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
     * 
     * There is no suppport for an IPv6 NS address yet.
     */

    unchecked_set = unchecked_zone_info;
    while (unchecked_set != NULL) {
        if (unchecked_set->rrs.val_rrset_type_h == ns_t_a) {
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

void
free_referral_members(struct delegation_info *del)
{
    if (del == NULL)
        return;

    if (del->queries != NULL) {
        deregister_queries(&del->queries);
        del->queries = NULL;
    }
    if (del->qnames) {
        free_qname_chain(&del->qnames);
        del->qnames = NULL;
    }
    if (del->pending_glue_ns) {
        free_name_servers(&del->pending_glue_ns);
        del->pending_glue_ns = NULL;
    }

    del->glueptr = NULL;
}

int
bootstrap_referral(u_int8_t * referral_zone_n,
                   struct rrset_rec **learned_zones,
                   struct val_query_chain *matched_q,
                   struct val_query_chain **queries,
                   struct name_server **ref_ns_list)
{
    struct name_server *pending_glue;
    int             ret_val;

    if ((learned_zones == NULL) || (matched_q == NULL) ||
        (queries == NULL) || (ref_ns_list == NULL))
        return VAL_BAD_ARGUMENT;

    *ref_ns_list = NULL;

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
    if (*ref_ns_list == NULL) {

        /*
         * Don't fetch glue if we're already fetching glue 
         */
        if ((matched_q->qc_referral) &&
            (matched_q->qc_referral->glueptr != NULL)) {
            free_name_servers(&pending_glue);
            matched_q->qc_state = Q_ERROR_BASE + SR_REFERRAL_ERROR;
        }
        /*
         * didn't find any referral with glue, look for one now 
         */
        else if (pending_glue) {
            /*
             * Create a new referral if one does not exist 
             */
            if (matched_q->qc_referral == NULL) {
                ALLOCATE_REFERRAL_BLOCK(matched_q->qc_referral);
            }

            /*
             * Create a query for glue for pending_ns 
             */
            matched_q->qc_referral->pending_glue_ns = pending_glue;
            add_to_query_chain(queries, pending_glue->ns_name_n, ns_t_a,
                               ns_c_in);
            matched_q->qc_referral->glueptr = *queries;
            matched_q->qc_referral->glueptr->qc_glue_request = 1;
            matched_q->qc_state = Q_WAIT_FOR_GLUE;
        } else {
            /*
             * nowhere to look 
             */
            matched_q->qc_state = Q_ERROR_BASE + SR_MISSING_GLUE;
        }
    } else {
        /*
         * forget about the name servers that don't have any glue 
         */
        free_name_servers(&pending_glue);
        matched_q->qc_state = Q_INIT;
    }

    return VAL_NO_ERROR;
}

static int
do_referral(val_context_t * context,
            u_int8_t * referral_zone_n,
            struct val_query_chain *matched_q,
            struct rrset_rec **answers,
            struct rrset_rec **learned_zones,
            struct qname_chain **qnames, struct val_query_chain **queries)
{
    int             ret_val;
    struct name_server *ref_ns_list;
    int             len;
    struct rrset_rec *ref_rrset;

    if ((matched_q == NULL) || (answers == NULL) || (qnames == NULL) ||
        (learned_zones == NULL) || (queries == NULL))
        return VAL_BAD_ARGUMENT;

    ref_ns_list = NULL;
    
    /*
     * Register the request name and zone with our referral monitor 
     */
    /*
     * If this request has already been made then Referral Error 
     */

    if (matched_q->qc_referral == NULL) {
        ALLOCATE_REFERRAL_BLOCK(matched_q->qc_referral);
    }

    /*
     * Update the qname chain 
     */

    ref_rrset = *answers;
    while (ref_rrset) {
        if (ref_rrset->rrs.val_rrset_type_h == ns_t_cname
            && namecmp(matched_q->qc_name_n,
                       ref_rrset->rrs.val_rrset_name_n) == 0) {
            if ((ret_val =
                 add_to_qname_chain(qnames,
                                    ref_rrset->rrs.val_rrset_data->
                                    rr_rdata)) != VAL_NO_ERROR) {
                free_qname_chain(qnames);
                return ret_val;
            }
        }
        ref_rrset = ref_rrset->rrs_next;
    }

    /*
     * save qnames to the val_query_chain structure 
     */
    if (matched_q->qc_referral->qnames == NULL)
        matched_q->qc_referral->qnames = *qnames;
    else if (*qnames) {
        struct qname_chain *t_q;
        for (t_q = *qnames; t_q->qnc_next; t_q = t_q->qnc_next);
        t_q->qnc_next = matched_q->qc_referral->qnames;
        matched_q->qc_referral->qnames = *qnames;
    }

    if (register_query
        (&matched_q->qc_referral->queries, matched_q->qc_name_n,
         matched_q->qc_type_h, referral_zone_n) == ITS_BEEN_DONE) {
        matched_q->qc_state = Q_ERROR_BASE + SR_REFERRAL_ERROR;
    } else {
        if (VAL_NO_ERROR != (ret_val = bootstrap_referral(referral_zone_n,
                                                          learned_zones,
                                                          matched_q,
                                                          queries,
                                                          &ref_ns_list)))
            return ret_val;
    }


    {
        char            debug_name1[NS_MAXDNAME];
        char            debug_name2[NS_MAXDNAME];
        memset(debug_name1, 0, 1024);
        memset(debug_name2, 0, 1024);
        ns_name_ntop(matched_q->qc_name_n, debug_name1,
                     sizeof(debug_name1));
        ns_name_ntop(referral_zone_n, debug_name2, sizeof(debug_name2));
        val_log(context, LOG_DEBUG, "QUERYING: '%s.' (referral to %s)",
                debug_name1, debug_name2);
    }


    if (matched_q->qc_respondent_server) {
        free_name_server(&matched_q->qc_respondent_server);
        matched_q->qc_respondent_server = NULL;
    }
    if (matched_q->qc_ns_list) {
        free_name_servers(&matched_q->qc_ns_list);
        matched_q->qc_ns_list = NULL;
    }

    if (matched_q->qc_zonecut_n != NULL) {
        FREE(matched_q->qc_zonecut_n);
        matched_q->qc_zonecut_n = NULL;
    }

    /*
     * Store the current referral value in the query 
     */
    if (referral_zone_n != NULL) {
        len = wire_name_length(referral_zone_n);
        matched_q->qc_zonecut_n =
            (u_int8_t *) MALLOC(len * sizeof(u_int8_t));
        if (matched_q->qc_zonecut_n == NULL)
            return VAL_OUT_OF_MEMORY;
        memcpy(matched_q->qc_zonecut_n, referral_zone_n, len);
    }

    if (matched_q->qc_state > Q_ERROR_BASE) {
        free_referral_members(matched_q->qc_referral);
        /*
         * don't free qc_referral itself 
         */
    }

    matched_q->qc_ns_list = ref_ns_list;

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
                /* Add this record to its chain of rr_rec's. */         \
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

static int
digest_response(val_context_t * context,
                struct val_query_chain *matched_q,
                struct name_server *respondent_server,
                struct val_query_chain **queries,
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
    int             nothing_other_than_cname;
    int             from_section;
    struct rrset_rec *learned_zones = NULL;
    struct rrset_rec *learned_keys = NULL;
    struct rrset_rec *learned_ds = NULL;

    const u_int8_t *query_name_n;
    u_int16_t       query_type_h;
    u_int16_t       query_class_h;
    u_int8_t       *rrs_zonecut_n = NULL;
    int             referral_seen = FALSE;
    u_int8_t        referral_zone_n[NS_MAXCDNAME];
    int             auth_nack;
    HEADER         *header;
    u_int8_t       *end;
    int             qnamelen, tot;
    struct name_server *ns = NULL;

    struct rrset_rec **proofs;
    struct rrset_rec **answers;
    struct qname_chain **qnames;

    if ((matched_q == NULL) ||
        (queries == NULL) ||
        (di_response == NULL) || (response_data == NULL))
        return VAL_BAD_ARGUMENT;

    answers = &(di_response->di_answers);
    proofs = &(di_response->di_proofs);
    qnames = &(di_response->di_qnames);
    header = (HEADER *) response_data;
    end = (u_int8_t *) ((u_int32_t) response_data + response_length);

    query_name_n = matched_q->qc_name_n;
    query_type_h = matched_q->qc_type_h;
    query_class_h = matched_q->qc_class_h;
    *answers = NULL;
    *qnames = NULL;
    hptr = NULL;
    rdata = NULL;

    question = ntohs(header->qdcount);
    answer = ntohs(header->ancount);
    authority = ntohs(header->nscount);
    additional = ntohs(header->arcount);
    nothing_other_than_cname = 1; 

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
         * We got an response with no records and the NXDOMAIN code
         * in the RCODE section of the header.
         * 
         * Create a dummy answer record to handle this.  
         */
        return prepare_empty_nxdomain(answers, query_name_n, query_type_h,
                                      query_class_h);
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
                             &rdata_len_h, &rdata_index)) != VAL_NO_ERROR) {
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
         * Check if the only RRset in the answer section is a CNAME
         */
        if (nothing_other_than_cname && (i < answer)) {
            nothing_other_than_cname = (set_type_h == ns_t_cname);
            /* check if we had explicitly asked for this cname */
            if (nothing_other_than_cname) {
                if (((query_type_h == ns_t_cname) ||
                     (query_type_h == ns_t_any) ||
                     (query_type_h == ns_t_rrsig)) && 
                        (!namecmp(name_n, query_name_n))) 
                    nothing_other_than_cname = 0;
            }
        }

        auth_nack = (from_section == VAL_FROM_AUTHORITY)
            && ((set_type_h == ns_t_nsec)
#ifdef LIBVAL_NSEC3
                || (set_type_h == ns_t_nsec3)
#endif
                || (set_type_h == ns_t_soa));

        if (from_section == VAL_FROM_ANSWER || auth_nack) {

            if (type_h == ns_t_cname &&
                query_type_h != ns_t_cname &&
                query_type_h != ns_t_any &&
                namecmp((*qnames)->qnc_name_n, name_n) == 0)
                if ((ret_val =
                     add_to_qname_chain(qnames, rdata)) != VAL_NO_ERROR)
                    goto done; 
        }

        if (from_section == VAL_FROM_ANSWER) {
            SAVE_RR_TO_LIST(respondent_server, answers, name_n, type_h,
                            set_type_h, class_h, ttl_h, hptr, rdata, 
                            rdata_len_h, from_section, authoritive, 
                            rrs_zonecut_n);
        } else if (auth_nack) {
            SAVE_RR_TO_LIST(respondent_server, proofs, name_n, type_h,
                            set_type_h, class_h, ttl_h, hptr, rdata, 
                            rdata_len_h, from_section, authoritive, 
                            rrs_zonecut_n);
        } else if ((answer == 0) 
                   && ((set_type_h == ns_t_ns) 
                       || ((set_type_h == ns_t_a) 
                           && (from_section == VAL_FROM_ADDITIONAL)))) {
            /*
             * XXX although we could get a referral if this was a CNAME
             * XXX dont case the alias information for now
             * XXX nothing_other_than_cname would be 1 here 
             */
            
            /*
             * This is a referral 
             */
            
            if (set_type_h == ns_t_ns) {
                if (referral_seen == FALSE) {
                    memcpy(referral_zone_n, name_n, wire_name_length(name_n));
                    referral_seen = TRUE;
                } else if (namecmp(referral_zone_n, name_n) != 0) {
                    /*
                     * Multiple NS records; Malformed referral notice 
                     */
                    matched_q->qc_state = Q_ERROR_BASE + SR_REFERRAL_ERROR;
                    ret_val = VAL_NO_ERROR;
                    goto done;
                }
            }
            /*
             * This record belongs in the zone_info chain 
             */
            SAVE_RR_TO_LIST(respondent_server, &learned_zones, name_n,
                            type_h, set_type_h, class_h, ttl_h, hptr,
                            rdata, rdata_len_h, from_section, 
                            authoritive, rrs_zonecut_n);
        }

        if (set_type_h == ns_t_dnskey) {
            SAVE_RR_TO_LIST(respondent_server, &learned_keys, name_n,
                            type_h, set_type_h, class_h, ttl_h, hptr, 
                            rdata, rdata_len_h, from_section, 
                            authoritive, rrs_zonecut_n);
        } else if (set_type_h == ns_t_ds) {
            SAVE_RR_TO_LIST(respondent_server, &learned_ds, name_n, type_h,
                            set_type_h, class_h, ttl_h, hptr, rdata, 
                            rdata_len_h, from_section, authoritive, 
                            rrs_zonecut_n);
        } 
            
        /*
         * XXX Save the RRSIGs for additional data in the zone_info chain 
         */
        FREE(rdata);
        rdata = NULL;
    }

    if (referral_seen) {
        ret_val = do_referral(context, referral_zone_n, matched_q,
                              answers, &learned_zones, qnames, queries);
        /*
         * stow zones only if we actually followed referrals 
         */
        if (VAL_NO_ERROR != (ret_val = stow_zone_info(learned_zones))) {
            goto done; 
        }
        /*
         * all of these are consumed inside do_referral 
         */
        *answers = NULL;
        *qnames = NULL;
        learned_zones = NULL;
    }
    /*
     * Check if this is the response to a referral request 
     */
    else {

        /*
         * if we hadn't enabled EDNS0 but we got a response for a zone 
         * where DNSSEC is enabled, retry with EDNS0 enabled
         * This can occur if a name server a name server is 
         * authoritative for the parent zone as well as the 
         * child zone, or if one of the name servers reached while 
         * following referrals is also recursive
         */ 
        if ((VAL_A_WAIT_FOR_TRUST == is_trusted_zone(context, matched_q->qc_name_n)) &&
            matched_q->qc_respondent_server && 
            !(matched_q->qc_respondent_server->ns_options & RES_USE_DNSSEC)) {

            free_name_server(&matched_q->qc_respondent_server);
            matched_q->qc_respondent_server = NULL;
            matched_q->qc_trans_id = -1; 
            matched_q->qc_state = Q_INIT; 
            val_log(context, LOG_DEBUG, "EDNS0 was not used but it should have been");
            val_log(context, LOG_DEBUG, "Setting D0 bit and using EDNS0");
            for (ns = matched_q->qc_ns_list; ns; ns = ns->ns_next)
                ns->ns_options |= RES_USE_DNSSEC; 
            ret_val = VAL_NO_ERROR;
            goto done;
        }
        
        if (matched_q->qc_referral != NULL) {

            /*
             * Consume qnames and learned_zones 
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
    }


    /*
     * if we were fetching glue here, save a copy as zone info 
     */
    if (matched_q->qc_glue_request) {
        struct rrset_rec *gluedata = copy_rrset_rec(*answers);
        if (VAL_NO_ERROR != (ret_val = stow_zone_info(gluedata))) {
            res_sq_free_rrset_recs(&gluedata);
            goto done;
        }
    }

    if (VAL_NO_ERROR != (ret_val = stow_key_info(learned_keys))) {
        goto done; 
    }

    if (VAL_NO_ERROR != (ret_val = stow_ds_info(learned_ds))) {
        goto done; 
    }

    return ret_val;

done:
    if (rdata)
        FREE(rdata);
    res_sq_free_rrset_recs(&learned_zones);
    res_sq_free_rrset_recs(&learned_keys);
    res_sq_free_rrset_recs(&learned_ds);
    return ret_val;
}

int
val_resquery_send(val_context_t * context,
                  struct val_query_chain *matched_q)
{
    char            name_p[NS_MAXDNAME];
    int             ret_val;
    struct name_server *tempns;

    /*
     * Get a (set of) answer(s) from the default NS's.
     * If nslist is NULL, read the cached zones and name servers
     * in context to create the nslist
     */
    struct name_server *nslist;

    if ((matched_q == NULL) || (matched_q->qc_ns_list == NULL)) {
        return VAL_BAD_ARGUMENT;
    }
    nslist = matched_q->qc_ns_list;

    if (ns_name_ntop(matched_q->qc_name_n, name_p, sizeof(name_p)) == -1) {
        matched_q->qc_state = Q_ERROR_BASE + SR_CALL_ERROR;
        return VAL_NO_ERROR;
    }

    val_log(context, LOG_DEBUG, "Sending query for %s to:", name_p);
    for (tempns = nslist; tempns; tempns = tempns->ns_next) {
        struct sockaddr_in *s =
            (struct sockaddr_in *) (tempns->ns_address[0]);
        val_log(context, LOG_DEBUG, "    %s", inet_ntoa(s->sin_addr));
    }
    val_log(context, LOG_DEBUG, "End of Sending query for %s", name_p);

    if ((ret_val =
         query_send(name_p, matched_q->qc_type_h, matched_q->qc_class_h,
                    nslist, &(matched_q->qc_trans_id))) == SR_UNSET)
        return VAL_NO_ERROR;

    /*
     * ret_val contains a resolver error 
     */
    matched_q->qc_state = Q_ERROR_BASE + ret_val;
    return VAL_NO_ERROR;
}

int
val_resquery_rcv(val_context_t * context,
                 struct val_query_chain *matched_q,
                 struct domain_info **response,
                 struct val_query_chain **queries)
{
    struct name_server *server = NULL;
    u_int8_t       *response_data = NULL;
    u_int32_t       response_length = 0;
    char            name_p[NS_MAXDNAME];

    int             ret_val;

    if ((matched_q == NULL) || (response == NULL) || (queries == NULL))
        return VAL_BAD_ARGUMENT;

    *response = NULL;
    ret_val = response_recv(&(matched_q->qc_trans_id), &server,
                            &response_data, &response_length);
    if (ret_val == SR_NO_ANSWER_YET)
        return VAL_NO_ERROR;

    matched_q->qc_respondent_server = server;

    if (ret_val != SR_UNSET) {
        if (response_data)
            FREE(response_data);
        matched_q->qc_state = Q_ERROR_BASE + ret_val;
        return VAL_NO_ERROR;
    }

    if (ns_name_ntop(matched_q->qc_name_n, name_p, sizeof(name_p)) == -1) {
        matched_q->qc_state = Q_ERROR_BASE + SR_RCV_INTERNAL_ERROR;
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

    if ((ret_val = digest_response(context, matched_q,
                                   matched_q->qc_respondent_server,
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


/*
 * find the zonecut for this name and type 
 */
int
find_next_zonecut(val_context_t *ctx, struct rrset_rec *rrset,
                  u_int8_t * curzone_n, u_int8_t ** name_n)
{
    u_int8_t       *qname;
    int             retval;
    struct val_result_chain *results;
    val_context_t *context = NULL;
    int            len;
    struct val_rrset *soa_rrset = NULL;
    
    if (name_n == NULL)
        return VAL_BAD_ARGUMENT;

    *name_n = NULL;
    qname = NULL;

    if (rrset != NULL) {
        qname = rrset->rrs.val_rrset_name_n;

        if ((rrset->rrs.val_rrset_type_h == ns_t_soa)
            || (rrset->rrs.val_rrset_type_h == ns_t_dnskey)) {
            int             len =
                wire_name_length(rrset->rrs.val_rrset_name_n);
            *name_n = (u_int8_t *) MALLOC(len * sizeof(u_int8_t));
            if (*name_n == NULL)
                return VAL_OUT_OF_MEMORY;
            memcpy(*name_n, rrset->rrs.val_rrset_name_n, len);
            return VAL_NO_ERROR;
        } else if (rrset->rrs.val_rrset_sig != NULL) {
            /* the signer name is the zone cut */
            u_int8_t       *signby_name_n;
            signby_name_n = &rrset->rrs.val_rrset_sig->rr_rdata[SIGNBY];
            int             len = wire_name_length(signby_name_n);
            *name_n = (u_int8_t *) MALLOC(len * sizeof(u_int8_t));
            if (*name_n == NULL)
                return VAL_OUT_OF_MEMORY;
            memcpy(*name_n, signby_name_n, len);
            return VAL_NO_ERROR;
        }

        if (rrset->rrs_zonecut_n != NULL) {
            int             len = wire_name_length(rrset->rrs_zonecut_n);
            *name_n = (u_int8_t *) MALLOC(len * sizeof(u_int8_t));
            if (*name_n == NULL)
                return VAL_OUT_OF_MEMORY;
            memcpy(*name_n, rrset->rrs_zonecut_n, len);
            return VAL_NO_ERROR;
        }

        if (rrset->rrs.val_rrset_type_h == ns_t_ds) {
            STRIP_LABEL(rrset->rrs.val_rrset_name_n, qname);
        }
    } else if (curzone_n != NULL) {
        /*
         * Strip the label from here and try again 
         */
        STRIP_LABEL(curzone_n, qname);
    }

    if (qname == NULL)
        return VAL_NO_ERROR;

    /*
     * query for the SOA and return the zone cut.
     * create a context if we don't already have one.
     */
    if (ctx == NULL) {
        if (VAL_NO_ERROR != (retval = val_create_context(NULL, &context)))
            return EAI_FAIL;
    } else
        context = (val_context_t *) ctx;

    retval = val_resolve_and_check(context, qname, ns_c_in, ns_t_soa,
                                   VAL_FLAGS_DONT_VALIDATE, &results);
    if (VAL_NO_ERROR == retval) {

        struct val_result_chain *res;
        for (res = results; res; res = res->val_rc_next) {
            int i;
            if((res->val_rc_answer == NULL) || (res->val_rc_answer->val_ac_rrset == NULL)) {
                if (res->val_rc_proof_count == 0)
                    continue;
                for (i=0; i< res->val_rc_proof_count; i++) { 
                    if (res->val_rc_proofs[i]->val_ac_rrset->val_rrset_type_h == ns_t_soa) {
                        break;
                    }
                }
                if (i == res->val_rc_proof_count)
                    continue;
                soa_rrset = res->val_rc_proofs[i]->val_ac_rrset; 
            }
            else if (res->val_rc_answer->val_ac_rrset->val_rrset_type_h ==
                ns_t_soa) {
                soa_rrset = res->val_rc_answer->val_ac_rrset; 
            }
           
            if (soa_rrset) { 
                /*
                 * Store zonecut information in the rrset 
                 */
                len = wire_name_length(soa_rrset->val_rrset_name_n);
                *name_n = (u_int8_t *) MALLOC(len * sizeof(u_int8_t));
                if (*name_n == NULL) {
                    retval = VAL_OUT_OF_MEMORY;
                    goto done;
                }
                memcpy(*name_n, soa_rrset->val_rrset_name_n, len);

                retval = VAL_NO_ERROR;
                break;
            }
        }
    }

  done:
    val_free_result_chain(results);

    if ((ctx == NULL) && context)
        val_free_context(context);
    
    return retval;
}
