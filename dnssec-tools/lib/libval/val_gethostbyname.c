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
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <arpa/nameser.h>

#include <validator.h>
#include <resolver.h>
#include "val_parse.h"
#include "val_gethostbyname.h"
#include "val_log.h"

#define ETC_HOSTS_CONF "/etc/host.conf"
#define ETC_HOSTS      "/etc/hosts"
#define MAXLINE 4096
#define MAX_ALIAS_COUNT 2048

/**
 * hostent_dnssec_wrapper: A wrapper struct around struct hostent to
 *                         store the result of DNSSEC validation.
 *     hentry: Contains the hostent structure
 *     dnssec_status: Contains the result of DNSSEC validation.
 *                If DNSSEC validation is successful, it will
 *                contain VALIDATE_SUCCESS.  If there is a
 *                failure, it will contain the validator error code.
 */
struct hostent_dnssec_wrapper {
	struct hostent hentry;
	int dnssec_status;
};

int val_get_hostent_dnssec_status (const struct hostent *hentry)
{
	struct hostent_dnssec_wrapper *hw = NULL;

	if (hentry) {
		hw = (struct hostent_dnssec_wrapper *) hentry;
		return hw->dnssec_status;
	}
	else {
		return INTERNAL_ERROR;
	}
}


/* Duplicate a hostent structure.  Performs a deep copy.
 */
struct hostent* val_duphostent (const struct hostent *hentry)
{
	struct hostent_dnssec_wrapper *oldhw = NULL;
	struct hostent_dnssec_wrapper *newhw = NULL;
	int i = 0;
	int aliascount=0;
	int addrcount=0;

	
	if (!hentry)
		return NULL;

	oldhw = (struct hostent_dnssec_wrapper *) hentry;
	newhw = (struct hostent_dnssec_wrapper *) malloc (sizeof (struct hostent_dnssec_wrapper));
	bzero(newhw, sizeof (struct hostent_dnssec_wrapper));

	newhw->hentry.h_addrtype = hentry->h_addrtype;
	newhw->hentry.h_length = hentry->h_length;
	newhw->dnssec_status = oldhw->dnssec_status;

	if (hentry->h_name)
		newhw->hentry.h_name = strdup(hentry->h_name);

	if (hentry->h_aliases) {

		for (i=0; hentry->h_aliases[i] != 0; i++) {
			aliascount++;
		}
		aliascount++;

		newhw->hentry.h_aliases = (char **) malloc (aliascount * sizeof (char*));
		bzero(newhw->hentry.h_aliases, aliascount * sizeof(char*));

		for (i=0; hentry->h_aliases[i] != 0; i++) {
			if (hentry->h_aliases[i])
				newhw->hentry.h_aliases[i] = strdup(hentry->h_aliases[i]);
		}
	}
	
	if (hentry->h_addr_list) {

		for (i=0; hentry->h_addr_list[i] != 0; i++) {
			addrcount++;
		}
		addrcount++;
		
		newhw->hentry.h_addr_list = (char **) malloc (addrcount * sizeof (char *));
		bzero(newhw->hentry.h_addr_list, addrcount * sizeof (char *));
		
		for (i=0; hentry->h_addr_list[i] != 0; i++) {
			if (hentry->h_addr_list[i])
				newhw->hentry.h_addr_list[i] = strdup(hentry->h_addr_list[i]);
		}
	}

	return (struct hostent *) newhw;
}

/* A function to free memory allocated by val_gethostbyname */
void val_freehostent (struct hostent *hentry)
{
	if (hentry) {
		int i = 0;
		if (hentry->h_name) free (hentry->h_name);
		if (hentry->h_aliases) {
			i = 0;
			for (i=0; hentry->h_aliases[i] != 0; i++) {
				if (hentry->h_aliases[i]) free (hentry->h_aliases[i]);
			}
			if (hentry->h_aliases[i]) free (hentry->h_aliases[i]);
			free (hentry->h_aliases);
		}
		if (hentry->h_addr_list) {
			i = 0;
			for (i=0; hentry->h_addr_list[i] != 0; i++) {
				if (hentry->h_addr_list[i]) free (hentry->h_addr_list[i]);
			}
			if (hentry->h_addr_list[i]) free (hentry->h_addr_list[i]);
			free (hentry->h_addr_list);
		}
		free (hentry);
	}
}


/* Read the ETC_HOSTS file and check if it contains the given name.
 */
static struct hostent *get_hostent_from_etc_hosts (const char *name)
{
	struct hosts *hs = parse_etc_hosts (name);
	struct hostent *hentry = NULL;
	struct hostent_dnssec_wrapper *hentry_wrapper = NULL;
	
	/* XXX: todo what if hs has more than one element ? */
	while (hs) {
		struct hosts *h_prev = NULL;
		struct in_addr ip4_addr;
		char addr_buf[INET_ADDRSTRLEN];
		int i, alias_count;
		
		bzero(&ip4_addr, sizeof(struct in_addr));
		
		if (inet_pton(AF_INET, hs->address, &ip4_addr) <= 0) {
			
			/* not a valid address ... skip this line */
			val_log("\t...error in address format: %s\n", hs->address);
			h_prev = hs;
			hs = hs->next;
			FREE_HOSTS(h_prev);
			continue;
		}
		else {
			val_log("\t...type of address is IPv4\n");
			val_log("Address is: %s\n",
				inet_ntop(AF_INET, &ip4_addr, addr_buf, INET_ADDRSTRLEN));
		}
		
		hentry_wrapper = (struct hostent_dnssec_wrapper*) malloc (sizeof(struct hostent_dnssec_wrapper));
		bzero(hentry_wrapper, sizeof(struct hostent_dnssec_wrapper));
		hentry = (struct hostent *) & (hentry_wrapper->hentry);
		
		hentry->h_name = (char *) strdup(hs->canonical_hostname);
		alias_count = 0;
		while (hs->aliases[alias_count]) {
			alias_count++;
		}
		alias_count++;
		hentry->h_aliases = (char **) malloc ((alias_count) * sizeof(char *));
		
		for (i=0; i<alias_count; i++) {
			hentry->h_aliases[i] = (char *) (hs->aliases[i]);
		}
		free(hs->aliases);
		hs->aliases = (char **) malloc (sizeof(char *));
		hs->aliases[0] = NULL;
		
		
		hentry->h_addrtype = AF_INET;
		hentry->h_length = sizeof(struct in_addr);
		hentry->h_addr_list = (char **) malloc (2 * sizeof(char *));
		hentry->h_addr_list[0] = (char *) malloc(sizeof(struct in_addr));
		memcpy(hentry->h_addr_list[0], &ip4_addr, sizeof(struct in_addr));
		hentry->h_addr_list[1] = 0;
		
		hs = hs->next;
		h_prev = hs;
		FREE_HOSTS(h_prev);
		return hentry;
	}
	
	return NULL;
	
}


/* Converts data in the rrset_rec structure into a hostent structure */
static struct hostent *get_hostent_from_response (struct rrset_rec *rrset, int *h_errnop)
{
	struct hostent *hentry = NULL;
	struct hostent_dnssec_wrapper *hentry_wrapper = NULL;
	int address_found = 0;
	int cname_found = 0;
	char dname[MAXDNAME];
	
	if (!rrset) {
		return NULL;
	}
	
	hentry_wrapper = (struct hostent_dnssec_wrapper*) malloc (sizeof(struct hostent_dnssec_wrapper));
	bzero(hentry_wrapper, sizeof(struct hostent_dnssec_wrapper));
	hentry = (struct hostent *) & (hentry_wrapper->hentry);
	hentry->h_aliases = (char **) malloc (sizeof(char*));
	hentry->h_aliases[0] = 0;
	
	hentry->h_addr_list = (char **) malloc (sizeof(char*));
	hentry->h_addr_list[0] = 0;
	
	while (rrset) {
		struct rr_rec *rr = rrset->rrs_data;
		
		while (rr) {
			
			if (rrset->rrs_type_h == ns_t_cname) {
				val_log("val_gethostbyname: type of record = CNAME\n");
				cname_found = 1;
				bzero(dname, MAXDNAME);
				if (ns_name_ntop(rrset->rrs_name_n, dname, MAXDNAME) < 0) {
					val_freehostent(hentry);
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
						val_freehostent(hentry);
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
					val_freehostent(hentry);
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
#if 0
			else if (rrset->rrs_type_h == ns_t_aaaa) {
				val_log("val_gethostbyname: type of record = AAAA\n");
				/* XXX TODO: Fill in the AF_INET6 address in hentry */
				hentry->h_addrtype = AF_INET6;
				address_found = 1;
			}
#endif
			rr = rr->rr_next;
		}
		// else ignore the rrset and move on to the next
		rrset = rrset->rrs_next;
	}
	
#if 0
	/* XXX TODO: If some address were AF_INET and some were AF_INET6,
	 * convert the AF_INET addresses to AF_INET6
	 */
#endif
	
	if (address_found) {
		*h_errnop = NETDB_SUCCESS;
	}
	else if (cname_found) {
		*h_errnop = NO_DATA;
	}
	else {
		if (hentry) val_freehostent(hentry);
		hentry = NULL;
		*h_errnop = HOST_NOT_FOUND;
	}
	
	return hentry;
}


/*
 * Returns the entry from the host database for host.
 * If successful, dnssec_status will contain VALIDATE_SUCCESS
 * If there is a failure, dnssec_status will contain the validator
 * error code.  The dnssec_status can be accessed by the
 * function get_hostent_dnssec_status()
 */
struct hostent *val_x_gethostbyname ( const val_context_t *ctx, const char *name, int *h_errnop )
{
	struct hostent* hentry = NULL;
	struct hostent_dnssec_wrapper *hentry_wrapper = NULL;
	struct in_addr ip4_addr;
#if 0
	struct in6_addr ip6_addr;
#endif
	
	if (!name || !h_errnop) {
		return NULL;
	}
	
	bzero(&ip4_addr, sizeof(struct in_addr));
#if 0
	bzero(&ip6_addr, sizeof(struct in6_addr));
#endif
	
	if (inet_pton(AF_INET, name, &ip4_addr) > 0) {
		hentry_wrapper = (struct hostent_dnssec_wrapper*) malloc (sizeof(struct hostent_dnssec_wrapper));
		bzero(hentry_wrapper, sizeof(struct hostent_dnssec_wrapper));
		hentry = (struct hostent *) & (hentry_wrapper->hentry);
		hentry->h_name = strdup(name);
		hentry->h_aliases = (char **) malloc (sizeof(char *));
		hentry->h_aliases[0] = 0;
		hentry->h_addrtype = AF_INET;
		hentry->h_length = sizeof(struct in_addr);
		hentry->h_addr_list = (char **) malloc (2 * sizeof(char *));
		hentry->h_addr_list[0] = (char *) malloc(sizeof(struct in_addr));
		memcpy(hentry->h_addr_list[0], &ip4_addr, sizeof(struct in_addr));
		hentry->h_addr_list[1] = 0;
		hentry_wrapper->dnssec_status = VALIDATE_SUCCESS;
		*h_errnop = NETDB_SUCCESS;
		return hentry;
	}
#if 0
	else if (inet_pton(AF_INET6, name, &ip6_addr) > 0) {
		hentry_wrapper = (struct hostent_dnssec_wrapper*) malloc (sizeof(struct hostent_dnssec_wrapper));
		bzero(hentry_wrapper, sizeof(struct hostent_dnssec_wrapper));
		hentry = (struct hostent *) & (hentry_wrapper->hentry);
		hentry->h_name = strdup(name);
		hentry->h_aliases = (char **) malloc (sizeof(char *));
		hentry->h_aliases[0] = 0;
		hentry->h_addrtype = AF_INET6;
		hentry->h_length = sizeof(struct in6_addr);
		hentry->h_addr_list = (char **) malloc (2 * sizeof(char *));
		hentry->h_addr_list[0] = (char *) malloc(sizeof(struct in6_addr));
		memcpy(hentry->h_addr_list[0], &ip6_addr, sizeof(struct in6_addr));
		hentry->h_addr_list[1] = 0;
		hentry_wrapper->dnssec_status = VALIDATE_SUCCESS;
		*h_errnop = NETDB_SUCCESS;
		return hentry;
	}
#endif
	else {
		
		int retval;
		struct query_chain *queries = NULL;
		struct assertion_chain *assertions = NULL;
		struct val_result *results = NULL;
		u_char name_n[MAXCDNAME];
		val_context_t *context;
		int dnssec_status = INTERNAL_ERROR;
		
		/* First check the ETC_HOSTS file
		 * XXX: TODO check the order in the ETC_HOST_CONF file
		 */
		hentry = get_hostent_from_etc_hosts (name);
		
		if (hentry != NULL) {
			hentry_wrapper = (struct hostent_dnssec_wrapper *) hentry;
			hentry_wrapper->dnssec_status = VALIDATE_SUCCESS; /* ??? or locally trusted ??? */
			*h_errnop = NETDB_SUCCESS;
			return hentry;
		}
		
		
		if (ctx == NULL)
			get_context(NULL, &context);
		else
			context = ctx;   
		
		hentry = NULL;
		
		if (((retval = ns_name_pton(name, name_n, MAXCDNAME-1)) != -1)
		    && (NO_ERROR == (retval = resolve_n_check(context, name_n, ns_t_a, ns_c_in, 0,
							      &queries, &assertions, &results)))) {
			
			if(results->status == VALIDATE_SUCCESS) 
				hentry = get_hostent_from_response(results->as->ac_data, h_errnop);
			
			if (hentry) {
				hentry_wrapper = (struct hostent_dnssec_wrapper *) hentry;
				hentry_wrapper->dnssec_status = results->status;
			}
		}
		
		if(hentry == NULL)
			*h_errnop = HOST_NOT_FOUND;
		else
			*h_errnop = NETDB_SUCCESS;
		
		free_query_chain(&queries);
		free_assertion_chain(&assertions);
		free_result_chain(&results);
		
		if((ctx == NULL) && context)
			destroy_context(context);
		
		return hentry;
		
	}	
}

/*
 * Returns the entry from the host database for host.
 * If successful, dnssec_status will contain VALIDATE_SUCCESS
 * If there is a failure, dnssec_status will contain the validator
 * error code.  The dnssec_status can be accessed by the
 * function get_hostent_dnssec_status()
 */
struct hostent *val_gethostbyname ( const char *name, int *h_errnop )
{
	return val_x_gethostbyname( NULL, name, h_errnop );
}
