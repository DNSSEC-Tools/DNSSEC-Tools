/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the implementation file for a validating gethostbyname function.
 * Applications should be able to use this with minimal change.
 */

#include <stdio.h>
#include <resolver.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <arpa/nameser.h>

#include "val_errors.h"
#include "val_gethostbyname.h"
#include "val_query.h"
#include "val_log.h"

/* Converts data in the domain_info structure into a hostent structure */
static struct hostent *get_hostent_from_response (struct domain_info *response)
{
    struct hostent *hentry = NULL;
    struct rrset_rec *rrset = NULL;
    int address_found = 0;
    int cname_found = 0;
    char dname[MAXDNAME];

    if (!response) {
	val_h_errno = NETDB_INTERNAL;
	return NULL;
    }

    hentry = (struct hostent*) malloc (sizeof(struct hostent));
    bzero(hentry, sizeof(struct hostent));
    hentry->h_aliases = (char **) malloc (sizeof(char*));
    hentry->h_aliases[0] = 0;

    hentry->h_addr_list = (char **) malloc (sizeof(char*));
    hentry->h_addr_list[0] = 0;
    
    rrset = response->di_rrset;

    while (rrset) {
	struct rr_rec *rr = rrset->rrs_data;

	if (rrset->rrs_status != RRSIG_VERIFIED) {
	    rrset = rrset->rrs_next;
	    continue;
	}

	while (rr) {

	    if (rrset->rrs_type_h == ns_t_cname) {
		val_log("val_gethostbyname: type of record = CNAME\n");
		cname_found = 1;
		bzero(dname, MAXDNAME);
		if (ns_name_ntop(rrset->rrs_name_n, dname, MAXDNAME) < 0) {
		    FREE_HOSTENT(hentry);
		    return NULL;
		}
		if (hentry->h_aliases) {
		    if (hentry->h_aliases[0]) free (hentry->h_aliases[0]);
		    free (hentry->h_aliases);
		}
		hentry->h_aliases = (char **) malloc (2 * sizeof(char *)); /* CNAME is a singleton RR */
		hentry->h_aliases[0] = (char *) malloc ((strlen(dname) + 1) * sizeof (char));
		memcpy(hentry->h_aliases[0], dname, strlen(dname) + 1);
		hentry->h_aliases[1] = 0;

		if (!hentry->h_name) {
		    bzero(dname, MAXDNAME);
		    if (ns_name_ntop(rr->rr_rdata, dname, MAXDNAME) < 0) {
			FREE_HOSTENT(hentry);
			return NULL;
		    }
		    hentry->h_name = (char *) malloc ((strlen(dname) + 1)* sizeof(char));
		    memcpy(hentry->h_name, dname, strlen(dname) + 1);
		}
	    }
	    else if (rrset->rrs_type_h == ns_t_a) {
		val_log("val_gethostbyname: type of record = A\n");

		bzero(dname, MAXDNAME);
		if (ns_name_ntop(rrset->rrs_name_n, dname, MAXDNAME) < 0) {
		    FREE_HOSTENT(hentry);
		    return NULL;
		}
		
		if (!hentry->h_name) {
		    hentry->h_name = (char *) malloc ((strlen(dname) + 1) * sizeof(char));
		    memcpy(hentry->h_name, dname, strlen(dname) + 1);
		}
		
		if (strcasecmp (hentry->h_name, dname) == 0) {
		    int l = 0;
		    int i;
		    char ** new_addr_list;

		    hentry->h_length = rr->rr_rdata_length_h; /* What if previous address was of type AAAA? */
		    hentry->h_addrtype = AF_INET;
		    
		    if ((hentry->h_addr_list != NULL) && (hentry->h_addr_list[0] != 0)) {
			while(hentry->h_addr_list[l] != 0) {
			    l++;
			}
		    }

		    new_addr_list = (char **) malloc ((l+2) * sizeof(char *));
		    for (i=0; i<l; i++) {
			new_addr_list[i] = hentry->h_addr_list[i];
		    }

		    new_addr_list[l] = (char *) malloc (rr->rr_rdata_length_h * sizeof(char));
		    memcpy(new_addr_list[l], rr->rr_rdata, rr->rr_rdata_length_h);
		    new_addr_list[l+1] = 0;

		    if (hentry->h_addr_list) free (hentry->h_addr_list);

		    hentry->h_addr_list = new_addr_list;

		    address_found = 1;
		}
	    }
	    else if (rrset->rrs_type_h == ns_t_aaaa) {
		val_log("val_gethostbyname: type of record = AAAA\n");
		/* XXX TODO: Fill in the AF_INET6 address in hentry */
		hentry->h_addrtype = AF_INET6;
		address_found = 1;
	    }

	    rr = rr->rr_next;
	}
	// else ignore the rrset and move on to the next
	rrset = rrset->rrs_next;
    }

    /* XXX TODO: If some address were AF_INET and some were AF_INET6,
     * convert the AF_INET addresses to AF_INET6
     */
    
    if (address_found) {
	val_h_errno = NETDB_SUCCESS;
    }
    else if (cname_found) {
	val_h_errno = NO_DATA;
    }
    else {
	if (hentry) FREE_HOSTENT(hentry);
	hentry = NULL;
	val_h_errno = HOST_NOT_FOUND;
    }

    return hentry;
}


/*
 * Returns the entry from the host database for host with name if
 * the DNSSEC validation was successful.
 * If successful, *dnssec_status will contain VALIDATE_SUCCESS
 * If there is a failure, *dnssec_status will contain the validator
 * error code.
 */
struct hostent *val_gethostbyname ( const char *name, int *dnssec_status )
{
    struct hostent* hentry = NULL;
    struct in_addr ip4_addr;
    struct in6_addr ip6_addr;

    if (!name || !dnssec_status) {
	return NULL;
    }

    bzero(&ip4_addr, sizeof(struct in_addr));
    bzero(&ip6_addr, sizeof(struct in6_addr));

    if (inet_pton(AF_INET, name, &ip4_addr) > 0) {
	hentry = (struct hostent*) malloc (sizeof(struct hostent));
	bzero(hentry, sizeof(struct hostent));
	hentry->h_name = strdup(name);
	hentry->h_aliases = (char **) malloc (sizeof(char *));
	hentry->h_aliases[0] = 0;
	hentry->h_addrtype = AF_INET;
	hentry->h_length = sizeof(struct in_addr);
	hentry->h_addr_list = (char **) malloc (2 * sizeof(char *));
	hentry->h_addr_list[0] = (char *) malloc(sizeof(struct in_addr));
	memcpy(hentry->h_addr_list[0], &ip4_addr, sizeof(struct in_addr));
	hentry->h_addr_list[1] = 0;
	*dnssec_status = VALIDATE_SUCCESS;
	val_h_errno = NETDB_SUCCESS;
	return hentry;
    }
    else if (inet_pton(AF_INET6, name, &ip6_addr) > 0) {
	hentry = (struct hostent*) malloc (sizeof(struct hostent));
	bzero(hentry, sizeof(struct hostent));
	hentry->h_name = strdup(name);
	hentry->h_aliases = (char **) malloc (sizeof(char *));
	hentry->h_aliases[0] = 0;
	hentry->h_addrtype = AF_INET6;
	hentry->h_length = sizeof(struct in6_addr);
	hentry->h_addr_list = (char **) malloc (2 * sizeof(char *));
	hentry->h_addr_list[0] = (char *) malloc(sizeof(struct in6_addr));
	memcpy(hentry->h_addr_list[0], &ip6_addr, sizeof(struct in6_addr));
	hentry->h_addr_list[1] = 0;
	val_h_errno = NETDB_SUCCESS;
	*dnssec_status = VALIDATE_SUCCESS;
	return hentry;
    }
    else {
	struct domain_info response;
	bzero(&response, sizeof(struct domain_info));

	if (_val_query (name, ns_c_in, ns_t_a, &response, dnssec_status) < 0) {
	    free_domain_info_ptrs(&response);
	    val_h_errno = HOST_NOT_FOUND;
	    return NULL;
	}
	else {
	    /* Extract validated answers from response */
	    hentry = get_hostent_from_response (&response);
	    free_domain_info_ptrs(&response);
	    return hentry;
	}
    }
}
