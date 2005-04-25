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
#include "val_zone.h"
#include "res_squery.h"
#include "val_log.h"

#define DNS_PORT    53


void *weird_al_realloc (void *old, size_t new_size)
{
    void    *new;
                                                                                                                          
    if (new_size>0)
    {
        new = MALLOC (new_size);
        if (new==NULL) return new;
        memset (new, 0, new_size);
        if (old) memcpy (new, old, new_size);
    }
    if (old) FREE (old);
                                                                                                                          
    return new;
}

int res_zi_unverified_ns_list(val_context_t *context, struct name_server **ns_list,
			u_int8_t *zone_name, struct res_policy *respol, 
			struct rrset_rec *unchecked_zone_info)
{
    /* Look through the unchecked_zone stuff for answers */
    struct rrset_rec    *unchecked_set;
    struct rrset_rec    *trailer;
    struct rrset_rec    *addr_rrs;
    struct rr_rec       *addr_rr;
    struct rr_rec       *ns_rr;
    struct name_server  *temp_ns;
    struct name_server  *ns;
    struct name_server  *trail_ns;
    struct name_server  *outer_trailer;
    struct name_server  *tail_ns;
    size_t              name_len;
    size_t              new_ns_size;
    struct sockaddr_in  *sock_in;
                                                                                                                          
    *ns_list = NULL;
                                                                                                                          
    unchecked_set = unchecked_zone_info;
    while (unchecked_set != NULL)
    {
        if (unchecked_set->rrs_type_h == ns_t_ns &&
                (namecmp(zone_name, unchecked_set->rrs_name_n) == 0))
        {
            if (*ns_list != NULL)
            {
                /* We've hit a duplicate, remove it from the list */
                /*
                    Now that I'm thinking about it, I may remove duplicates
                    during the stowage of the zone information.
                    If so, this code may never get executed.
                */
                trailer->rrs_next = unchecked_set->rrs_next;
                unchecked_set->rrs_next = NULL;
                res_sq_free_rrset_recs (&unchecked_set);
                unchecked_set = trailer;
            }
            else
            {
                ns_rr = unchecked_set->rrs_data;
                while (ns_rr)
                {
                    /* Create the structure for the name server */
                    temp_ns = (struct name_server *)
                                    MALLOC(sizeof(struct name_server));
                    if (temp_ns == NULL)
                    {
                        /* Since we're in trouble, free up just in case */
                        free_name_servers (ns_list);
                        return SR_MEMORY_ERROR;
                    }
                                                                                                                          
                    /* Make room for the name and insert the name */
                    name_len = wire_name_length (ns_rr->rr_rdata);
                    temp_ns->ns_name_n = (u_int8_t *)MALLOC(name_len);
                    if (temp_ns->ns_name_n==NULL)
                    {
                        free_name_servers (ns_list);
                        return SR_MEMORY_ERROR;
                    }
                    memcpy (temp_ns->ns_name_n, ns_rr->rr_rdata, name_len);
                                                                                                                          
                    /* Initialize the rest of the fields */
                    temp_ns->ns_tsig_key = NULL;
                    temp_ns->ns_security_options = ZONE_USE_NOTHING;
                    temp_ns->ns_status = SR_ZI_STATUS_LEARNED;
                    temp_ns->ns_next = NULL;
                    temp_ns->ns_number_of_addresses = 0;
                    /* Add the name server record to the list */
                    if (*ns_list == NULL)
                        *ns_list = temp_ns;
                    else
                    {
                        /* Preserving order in case of round robin */
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
                                                                                                                          
    /* Now, we need the addresses */
    /*
        This is ugly - loop through unchecked data for address records,
        then through the name server records to find a match,
        then through the (possibly multiple) addresses under the A set
                                                                                                                          
        There is no suppport for an IPv6 NS address yet.
    */
                                                                                                                          
    unchecked_set = unchecked_zone_info;
     while (unchecked_set != NULL)
    {
        if (unchecked_set->rrs_type_h == ns_t_a)
        {
            /* If the owner name matches the name in an *ns_list entry...*/
            trail_ns = NULL;
            ns = *ns_list;
            while (ns)
            {
                if (namecmp(unchecked_set->rrs_name_n,ns->ns_name_n)==0)
                {
                    /* Found that address set is for an NS */
                    addr_rr = unchecked_set->rrs_data;
                    while (addr_rr)
                    {
                        if (ns->ns_number_of_addresses > 0)
                        {
                            /* Have to grow the ns structure */
                            /* Determine the new size */
                            new_ns_size = sizeof (struct name_server)
                                            + ns->ns_number_of_addresses
                                                * sizeof (struct sockaddr);
                                                                                                                          
                            /*
                                Realloc the ns's structure to be able to
                                add a struct sockaddr
                            */
                            ns = (struct name_server *)
                                weird_al_realloc(ns, new_ns_size);
                                                                                                                          
                            if (ns==NULL) return SR_MEMORY_ERROR;
                                                                                                                          
                            /* Inform the others who know about the old ns */
                                                                                                                          
                            if (trail_ns)
                                trail_ns->ns_next = ns;
                            else
                                *ns_list = ns;
                        }
                        sock_in = (struct sockaddr_in *)
                            &ns->ns_address[ns->ns_number_of_addresses];
                                                                                                                          
                        sock_in->sin_family = AF_INET;
                        sock_in->sin_port = htons (DNS_PORT);
                        memset (sock_in->sin_zero,0,sizeof(sock_in->sin_zero));
                        memcpy (&(sock_in->sin_addr), addr_rr->rr_rdata,
                                                        sizeof(u_int32_t));
                                                                                                                          
                        ns->ns_number_of_addresses++;
                        addr_rr = addr_rr->rr_next;
                    }
                    ns = NULL; /* Force dropping out from the loop */
                }
                else
                {
                    trail_ns = ns;
                    ns = ns->ns_next;
                }
            }
        }
        unchecked_set = unchecked_set->rrs_next;
    }

    /* One more loop to look for NS's w/o addresses */
                                                                                                                          
    ns = *ns_list;
    outer_trailer = NULL;
                                                                                                                          
    while (ns)
    {
        if (ns->ns_number_of_addresses==0)
        {
            int                 ret_val;
            struct domain_info  di;
			char ns_name[MAXDNAME];
                                                                                                                          
            /* Would be good to look locally in the verified stuff first */
                                                                                                                          
            /* Do a unverified lookup of the desired name */
                                                                                                                          
            di.di_requested_name_h = NULL;
            di.di_rrset = NULL;
            di.di_error_message = NULL;
			di.di_qnames = NULL;
                                                                                                                          
            /* Probably should select another NS list for this */
                                                                                                                          
			if(ns_name_ntop(ns->ns_name_n, ns_name, MAXDNAME-1) == -1)
				return -1;
{
val_log ("QUERYING: '%s.' (getting unchecked address hints)\n",
ns_name);

}
            ret_val = res_squery (context, ns_name, ns_t_a, ns_c_in,
                        respol, &di);
                                                                                                                          
            /* If answer is good, then use the A records to build the
                address(es) */
                                                                                                                          
            if (ret_val == SR_UNSET)
            {
                addr_rrs = di.di_rrset;
                while (addr_rrs && addr_rrs->rrs_type_h != ns_t_a)
                    addr_rrs = addr_rrs->rrs_next;
                                                                                                                          
                if (addr_rrs)
                {
                    addr_rr = addr_rrs->rrs_data;
                    while (addr_rr)
                    {
                        /* Convert the rdata into a sockaddr_in */
                        if (ns->ns_number_of_addresses > 0)
                        {
                            /* Have to grow the ns structure */
                            /* Determine the new size */
                            new_ns_size = sizeof (struct name_server)
                                            + ns->ns_number_of_addresses
                                                * sizeof (struct sockaddr);
                                                                                                                          
                            /*
                                Realloc the ns's structure to be able to
                                add a struct sockaddr
                            */
                            ns = (struct name_server *)
                                weird_al_realloc(ns, new_ns_size);
                                                                                                                          
                            if (ns==NULL) return SR_MEMORY_ERROR;
                                                                                                                          
                            /* Inform the others who know about the old ns */
                                                                                                                          
                            if (trail_ns)
                                trail_ns->ns_next = ns;
                            else
                                *ns_list = ns;
                        } /* Added more space */
                                                                                                                          
                        sock_in = (struct sockaddr_in *)
                            &ns->ns_address[ns->ns_number_of_addresses];
                                                                                                                          
                        sock_in->sin_family = AF_INET;
                        sock_in->sin_port = htons (DNS_PORT);
                        memset (sock_in->sin_zero,0,sizeof(sock_in->sin_zero));
                        memcpy (&(sock_in->sin_addr), addr_rr->rr_rdata,
                                                        sizeof(u_int32_t));
                                                                                                                          
                        ns->ns_number_of_addresses++;
                        addr_rr = addr_rr->rr_next;
                    } /* For each RR */
                } /* If there was a set */
            } /* The answer was useable */
            free_domain_info_ptrs (&di);
        }
        /* If we still don't have an address, forget it */
        if (ns->ns_number_of_addresses==0)
        {
            if (outer_trailer)
            {
                outer_trailer->ns_next = ns->ns_next;
                free_name_server (&ns);
                ns = outer_trailer->ns_next;
            }
            else
            {
                *ns_list = ns->ns_next;
                free_name_server (&ns);
                if (*ns_list) ns = (*ns_list)->ns_next;
            }
        }
        else /* There is at least one address */
        {
            outer_trailer = ns;
            ns = ns->ns_next;
        }
    }
                                                                                                                          
    return SR_UNSET;
}

