
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/nameser.h>

#include <resolver.h>
#include <res_errors.h>
#include <support.h>
#include <res_query.h>

#include "val_support.h"

static struct rrset_rec *unchecked_zone_info = NULL;
static struct rrset_rec *unchecked_key_info = NULL;
static struct rrset_rec *unchecked_ds_info = NULL;
static struct rrset_rec *unchecked_answers = NULL;

static void stow_info (struct rrset_rec **unchecked_info, struct rrset_rec *new_info)
{
    struct rrset_rec *new;
    struct rrset_rec *old;
    struct rrset_rec *trail_new;
    struct rr_rec *rr_exchange;
                                                                                                                          
    if (new_info == NULL) return;
                                                                                                                          
    /* Tie the two together */
                                                                                                                          
    if (*unchecked_info == NULL)
        *unchecked_info = new_info;
    else
    {
        old = *unchecked_info;
        while (old->rrs_next) old = old->rrs_next;
        old->rrs_next = new_info;
    }
                                                                                                                          
    /* Remove duplicated data */
                                                                                                                          
    old = *unchecked_info;
    while (old)
    {
        trail_new = old;
        new = old->rrs_next;
        while (new)
        {
            if (old->rrs_type_h == new->rrs_type_h &&
                    old->rrs_class_h == new->rrs_class_h &&
                    namecmp (old->rrs_name_n, new->rrs_name_n)==0)
            {
                /* old and new are competitors */
                if (!(old->rrs_cred < new->rrs_cred ||
                        (old->rrs_cred == new->rrs_cred &&
                            old->rrs_section <= new->rrs_section)))
                {
                    /*
                        exchange the two -
                            copy from new to old:
                                cred, status, section, ans_kind
                            exchange:
                                data, sig
                    */
                    old->rrs_cred = new->rrs_cred;
                    old->rrs_status = new->rrs_status;
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
                trail_new->rrs_next = new->rrs_next;
                new->rrs_next = NULL;
                res_sq_free_rrset_recs (&new);
                new = trail_new->rrs_next;
            }
            else
            {
                trail_new = new;
                new = new->rrs_next;
            }
        }
        old = old->rrs_next;
    }
}


void stow_zone_info(struct rrset_rec *new_info)
{
	stow_info(&unchecked_zone_info, new_info);
}
struct rrset_rec* get_cached_zones()
{
	return unchecked_zone_info;	
}


void stow_key_info(struct rrset_rec *new_info)
{
	stow_info(&unchecked_key_info, new_info);
}
struct rrset_rec* get_cached_keys()
{
	return unchecked_key_info;	
}

void stow_ds_info(struct rrset_rec *new_info)
{
	stow_info(&unchecked_ds_info, new_info);
}
struct rrset_rec* get_cached_ds()
{
	return unchecked_ds_info;	
}

void stow_answer(struct rrset_rec *new_info)
{
	stow_info(&unchecked_answers, new_info);
}
struct rrset_rec* get_cached_answers()
{
	return unchecked_answers;	
}
