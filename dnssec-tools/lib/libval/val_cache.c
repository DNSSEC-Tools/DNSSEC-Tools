
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
#include <pthread.h>

#include <resolver.h>
#include <validator.h>
#include "val_support.h"
#include "val_resquery.h"
#include "val_cache.h"

static struct rrset_rec *unchecked_key_info = NULL;
static struct rrset_rec *unchecked_ds_info = NULL;
static struct rrset_rec *unchecked_answers = NULL;
static pthread_rwlock_t rwlock=PTHREAD_RWLOCK_INITIALIZER;

static struct name_server *root_ns = NULL;

#define LOCK_SH() do{				\
	if(0 != pthread_rwlock_rdlock(&rwlock))\
		return INTERNAL_ERROR; \
} while(0);

#define LOCK_EX() do{				\
	if(0 != pthread_rwlock_wrlock(&rwlock))\
		return INTERNAL_ERROR;	\
} while(0);

#define UNLOCK() do{				\
	if (0 != pthread_rwlock_unlock(&rwlock)) \
		return INTERNAL_ERROR;	\
} while(0);

static int stow_info (struct rrset_rec **unchecked_info, struct rrset_rec *new_info)
{
    struct rrset_rec *new, *prev;
    struct rrset_rec *old;
    struct rrset_rec *trail_new;
    struct rr_rec *rr_exchange;
                                                                                                                          
    if (new_info == NULL) return NO_ERROR;
                                                                                                                          
    /* Tie the two together */
                        
	LOCK_SH();
	prev = NULL; 
    old = *unchecked_info; 
    while (old) {

		/* Look for duplicates */
		new = new_info;
		trail_new = NULL;
       	while (new) {
    	    if (old->rrs_type_h == new->rrs_type_h &&
                old->rrs_class_h == new->rrs_class_h &&
                namecmp (old->rrs_name_n, new->rrs_name_n)==0) {

				UNLOCK();	
				LOCK_EX();

    	        /* old and new are competitors */
	            if (!(old->rrs_cred < new->rrs_cred ||
   	                     (old->rrs_cred == new->rrs_cred &&
   	                         old->rrs_section <= new->rrs_section))) {
   	            	/*
   	                     exchange the two -
   	                         copy from new to old:
   	                             cred, status, section, ans_kind
   		                         exchange:
   	                             data, sig
   	            	*/
   	            	old->rrs_cred = new->rrs_cred;
   	                old->rrs_section = new->rrs_section;
   	                old->rrs_ans_kind = new->rrs_ans_kind;
   	                rr_exchange = old->rrs_data;
   	                old->rrs_data = new->rrs_data;
   	                new->rrs_data = rr_exchange;
   		            rr_exchange = old->rrs_sig;
       	            old->rrs_sig = new->rrs_sig;
       	            new->rrs_sig = rr_exchange;
       	        }

       		    /* delete new */
				if (trail_new == NULL) {
					new_info = new->rrs_next;
					if (new_info == NULL) {
						UNLOCK();
						return NO_ERROR;
					}
				}
				else
	           	    trail_new->rrs_next = new->rrs_next;
           	    new->rrs_next = NULL;
           	    res_sq_free_rrset_recs (&new);

				UNLOCK();
				LOCK_SH();

				break;
           	}
			else {
				trail_new = new; 
				new = new->rrs_next;
			}
		}	

		prev = old;
		old = old->rrs_next;
    }
	if(prev == NULL)
		*unchecked_info = new_info;
	else
		prev->rrs_next = new_info;

	UNLOCK();                    
	return NO_ERROR;
}

int get_cached_rrset(u_int8_t *name_n, u_int16_t class_h, 
		u_int16_t type_h, struct rrset_rec **cloned_answer)
{
	struct rrset_rec *next_answer, *prev;

	*cloned_answer = NULL;
    switch(type_h) {
                                                                                                                             
    	case ns_t_ds:
        	next_answer = unchecked_ds_info; 
            break;
                                                                                                                             
        case ns_t_dnskey:
            next_answer = unchecked_key_info; 
            break;

		case ns_t_ns:
			next_answer = unchecked_answers;
			break;
                                                                                                                         
        default:
            next_answer = unchecked_answers; 
            break;
    }

	prev = NULL; 
	LOCK_SH();
    while(next_answer)  {
        
        if ((next_answer->rrs_type_h == type_h) &&
        	(next_answer->rrs_class_h == class_h) &&
            (namecmp(next_answer->rrs_name_n, name_n) == 0)) {
            	if (next_answer->rrs_data != NULL) {
					*cloned_answer = copy_rrset_rec(next_answer);
                	break;
				}
        }

		prev = next_answer;
        next_answer = next_answer->rrs_next;
    }
	UNLOCK();
	return NO_ERROR;
}

int stow_zone_info(struct rrset_rec *new_info)
{
	return stow_info(&unchecked_answers, new_info);
}


int stow_key_info(struct rrset_rec *new_info)
{
	return stow_info(&unchecked_key_info, new_info);
}

int stow_ds_info(struct rrset_rec *new_info)
{
	return stow_info(&unchecked_ds_info, new_info);
}

int stow_answer(struct rrset_rec *new_info)
{
	return stow_info(&unchecked_answers, new_info);
}

int stow_root_info(struct rrset_rec *root_info)
{
	struct name_server *ns_list = NULL;
	struct name_server *pending_glue = NULL;
	int retval;
	u_char root_zone_n[NS_MAXCDNAME];
	char *root_zone = ".";

   	if (ns_name_pton(root_zone, root_zone_n, NS_MAXCDNAME-1) == -1)
    	return CONF_PARSE_ERROR; 

	if (NO_ERROR != (retval = res_zi_unverified_ns_list(&ns_list, root_zone_n, root_info, &pending_glue)))
		return retval;
	/* We are not interested in fetching glue for the root */
	free_name_servers(&pending_glue);

	LOCK_EX();
	root_ns = ns_list;
	UNLOCK();

	/* store the records in the cache */
	return stow_info(&unchecked_answers, root_info);
}

int free_validator_cache()
{
	LOCK_EX();
	res_sq_free_rrset_recs(&unchecked_key_info);
	unchecked_key_info = NULL;
	res_sq_free_rrset_recs(&unchecked_ds_info);
	unchecked_ds_info = NULL;
	res_sq_free_rrset_recs(&unchecked_answers);
	unchecked_answers = NULL;
	UNLOCK();

	return NO_ERROR;
}

int get_root_ns(struct name_server **ns)
{
	LOCK_SH();

	*ns = NULL;
	/* return a cloned copy */
	clone_ns_list(ns, root_ns);

	UNLOCK();

	return NO_ERROR;
}
