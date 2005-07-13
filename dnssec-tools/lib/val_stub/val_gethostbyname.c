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
#include "validator.h"
#include "val_assertion.h"
#include "val_support.h"
#include "val_context.h"

#define ETC_HOSTS_CONF "/etc/host.conf"
#define ETC_HOSTS      "/etc/hosts"
#define MAXLINE 4096
#define MAX_ALIAS_COUNT 2048

/* Read the ETC_HOSTS file and check if it contains the given
 * name
 */
static struct hostent *get_hostent_from_etc_hosts (const char *name)
{
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    int read;
    char white[] = " \t\n";
    char fileentry[MAXLINE];

    fp = fopen (ETC_HOSTS, "r");
    if (fp == NULL) {
	return NULL;
    }

    while ((read = getline (&line, &len, fp)) != -1) {
	char *buf = NULL;
	char *cp = NULL;
	char addr_buf[INET6_ADDRSTRLEN];
	char *domain_name = NULL;
	int matchfound = 0;
#if 0
	int is_ipv6_addr = 0;
#endif
	char *alias_list[MAX_ALIAS_COUNT];
	int alias_index = 0;
	struct in_addr ip4_addr;
#if 0
	struct in6_addr ip6_addr;
#endif

	if ((read > 0) && (line[0] == '#')) continue;

	/* ignore characters after # */
	cp = (char *) strtok_r (line, "#", &buf);
	
	if (!cp) continue;

	memset(fileentry, 0, MAXLINE);
	memcpy(fileentry, cp, strlen(cp));

	/* read the ip address */
	cp = (char *) strtok_r (fileentry, white, &buf);
	if (!cp) continue;

	bzero(&ip4_addr, sizeof(struct in_addr));
#if 0
	bzero(&ip6_addr, sizeof(struct in6_addr));
#endif
	val_log("parsing address `%s'", cp);
	memset(addr_buf, 0, INET6_ADDRSTRLEN);
	if (inet_pton(AF_INET, cp, &ip4_addr) <= 0) {

#if 0
	    /* not an ipv4 address... try ipv6 */
	    if (inet_pton (AF_INET6, cp, &ip6_addr) <= 0) {
#endif
		/* not a valid address ... skip this line */
		val_log("\t...error in address format\n");
		continue;
#if 0
	    }

	    val_log("\t...type of address is IPv6\n");
	    val_log("Address is: %s\n", inet_ntop(AF_INET6, &ip6_addr, addr_buf, INET6_ADDRSTRLEN));
	    is_ipv6_addr = 1;
#endif
	}
	else {
	    val_log("\t...type of address is IPv4\n");
	    val_log("Address is: %s\n", inet_ntop(AF_INET, &ip4_addr, addr_buf, INET_ADDRSTRLEN));
	}

	/* read the full domain name */
	cp = (char *) strtok_r (NULL, white, &buf);
	if (!cp) continue;

	domain_name = cp;

	if (strcasecmp(cp, name) == 0) {
	    matchfound = 1;
	}

	/* read the aliases */
	memset(alias_list, 0, MAX_ALIAS_COUNT);
	alias_index = 0;
	while ((cp = (char *) strtok_r (NULL, white, &buf)) != NULL) {
	    alias_list[alias_index++] = cp;
	    if ((!matchfound) && (strcasecmp(cp, name) == 0)) {
		matchfound = 1;
	    }
	}

	/* match input name with the full domain name and aliases */
	if (matchfound) {
	    int i;
	    struct hostent *hentry = (struct hostent*) malloc (sizeof(struct hostent));

	    bzero(hentry, sizeof(struct hostent));

	    hentry->h_name = (char *) strdup(domain_name);
	    hentry->h_aliases = (char **) malloc ((alias_index + 1) * sizeof(char *));

	    for (i=0; i<alias_index; i++) {
		hentry->h_aliases[i] = (char *) strdup(alias_list[i]);
	    }

	    hentry->h_aliases[alias_index] = 0;

#if 0
	    /* check if the address is an IPv6 address */
	    if (is_ipv6_addr) {
		hentry->h_addrtype = AF_INET6;
		hentry->h_length = sizeof(struct in6_addr);
		hentry->h_addr_list = (char **) malloc (2 * sizeof(char *));
		hentry->h_addr_list[0] = (char *) malloc(sizeof(struct in6_addr));
		memcpy(hentry->h_addr_list[0], &ip6_addr, sizeof(struct in6_addr));
		hentry->h_addr_list[1] = 0;
	    }
	    else {
#endif
		hentry->h_addrtype = AF_INET;
		hentry->h_length = sizeof(struct in_addr);
		hentry->h_addr_list = (char **) malloc (2 * sizeof(char *));
		hentry->h_addr_list[0] = (char *) malloc(sizeof(struct in_addr));
		memcpy(hentry->h_addr_list[0], &ip4_addr, sizeof(struct in_addr));
		hentry->h_addr_list[1] = 0;
#if 0
	    }
#endif
	    return hentry;
	}
    }

    return NULL;
}

/* Converts data in the rrset_rec structure into a hostent structure */
static struct hostent *get_hostent_from_response (struct rrset_rec *rrset)
{
    struct hostent *hentry = NULL;
    int address_found = 0;
    int cname_found = 0;
    char dname[MAXDNAME];

    if (!rrset) {
	val_h_errno = NETDB_INTERNAL;
	return NULL;
    }

    hentry = (struct hostent*) malloc (sizeof(struct hostent));
    bzero(hentry, sizeof(struct hostent));
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
 * Returns the entry from the host database for host.
 * If successful, *dnssec_status will contain VALIDATE_SUCCESS
 * If there is a failure, *dnssec_status will contain the validator
 * error code.
 */
struct hostent *val_gethostbyname ( const char *name, int *dnssec_status )
{
    struct hostent* hentry = NULL;
    struct in_addr ip4_addr;
#if 0
    struct in6_addr ip6_addr;
#endif

    if (!name || !dnssec_status) {
	return NULL;
    }

    bzero(&ip4_addr, sizeof(struct in_addr));
#if 0
    bzero(&ip6_addr, sizeof(struct in6_addr));
#endif

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
#if 0
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
#endif
    else {
	struct domain_info response;

	/* First check the ETC_HOSTS file
	 * XXX: TODO check the order in the ETC_HOST_CONF file
	 */
	hentry = get_hostent_from_etc_hosts (name);

	if (hentry != NULL) {
	    *dnssec_status = VALIDATE_SUCCESS; /* ??? */
	    val_h_errno = VALIDATE_SUCCESS;
	    return hentry;
	}
	
	/*
	 * Try DNS
	 */
	bzero(&response, sizeof(struct domain_info));

	if (_val_query (name, ns_c_in, ns_t_a, &response, dnssec_status) < 0) {
	    free_domain_info_ptrs(&response);
	    val_h_errno = HOST_NOT_FOUND;
	    return NULL;
	}
	else {
	    /* Extract validated answers from response */
	    hentry = get_hostent_from_response (response.di_rrset);
	    free_domain_info_ptrs(&response);
	    return hentry;
	}
    }
}

/*
 * Returns the entry from the host database for host.
 * If successful, *dnssec_status will contain VALIDATE_SUCCESS
 * If there is a failure, *dnssec_status will contain the validator
 * error code.
 */
struct hostent *val_x_gethostbyname ( val_context_t *ctx, const char *name, int *dnssec_status)
{
    struct hostent* hentry = NULL;
    struct in_addr ip4_addr;
#if 0
    struct in6_addr ip6_addr;
#endif

    if (!name || !dnssec_status) {
	return NULL;
    }

    bzero(&ip4_addr, sizeof(struct in_addr));
#if 0
    bzero(&ip6_addr, sizeof(struct in6_addr));
#endif

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
#if 0
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
#endif
    else {

	/* First check the ETC_HOSTS file
	 * XXX: TODO check the order in the ETC_HOST_CONF file
	 */
	hentry = get_hostent_from_etc_hosts (name);

	if (hentry != NULL) {
	    *dnssec_status = VALIDATE_SUCCESS; /* ??? */
	    val_h_errno = VALIDATE_SUCCESS;
	    return hentry;
	}


    int retval;
    struct query_chain *queries = NULL;
    struct assertion_chain *assertions = NULL;
    struct val_result *results = NULL;
	u_char name_n[MAXCDNAME];
	val_context_t *context;

	if (ctx == NULL)
		context = get_context(NULL);
	else
		context = ctx;   
                                                                                                                          
    hentry = NULL;
    
	if (((retval = ns_name_pton(name, name_n, MAXCDNAME-1)) != -1)
		&& (NO_ERROR == (retval = add_to_query_chain(&queries, name_n, ns_t_a, ns_c_in)))
        && (NO_ERROR == (retval = resolve_n_check(context, name_n, ns_t_a, ns_c_in, 0,
                                            &queries, &assertions, &results)))) {
                                                                                                                             
        if(results->status == VALIDATE_SUCCESS) 
            hentry = get_hostent_from_response(results->as->ac_data);

        *dnssec_status = results->status;
    }
    else
        *dnssec_status = retval;
                                                                                                                             
    if(hentry == NULL)
        val_h_errno = HOST_NOT_FOUND;
    else
        val_h_errno = NETDB_SUCCESS;
                                                                                                                             
    free_query_chain(&queries);
    free_assertion_chain(&assertions);
    free_result_chain(&results);
                                                                                                                             
    if((ctx == NULL) && context)
        destroy_context(context);
                                                                                                                             
    return hentry;

	}	
}

