/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the implementation file for a validating getaddrinfo function.
 * Applications should be able to use this in place of getaddrinfo with
 * minimal change.
 */

#include "val_api.h"
#include "val_getaddrinfo.h"

struct addrinfo *get_addrinfo_from_etc_hosts (const char *nodename,
					      const char *servname,
					      const struct addrinfo *hints)
{
} /* get_addrinfo_from_etc_hosts() */

struct addrinfo *get_addrinfo_from_response (struct rrset_rec *rrset,
					     const char *servname,
					     const struct addrinfo *hints)
{
} /* get_addrinfo_from_response() */

struct int val_getaddrinfo ( const char *nodename, const char *servname,
			     const struct addrinfo *hints,
			     struct addrinfo **res, int *dnssec_status )
{
	struct in_addr ip4_addr;
	struct in6_addr ip6_addr;

	if ((nodename == NULL) && (servname == NULL)) {
		return EAI_NONAME;
	}

	if (dnssec_status == NULL) {
		/* XXX: Is this the appropriate response? */
		return EAI_FAIL;
	}

	bzero(&ip4_addr, sizeof(struct in_addr));
	bzero(&ip6_addr, sizeof(struct in6_addr));

	if (inet_pton(AF_INET, nodename, &ip4_addr) > 0) {
		return 0;
	}
	else if (inet_pton(AF_INET6, nodename, &ip6_addr) > 0) {
		return 0;
	}
	else {
		struct domain_info response;

		/* First check ETC_HOSTS file
		 * XXX: TODO check the order in the ETC_HOST_CONF file
		 */
		*res = get_addrinfo_from_etc_hosts (nodename, servname, hints);

		if (*res != NULL) {
			*dnssec_status = VALIDATE_SUCCESS;
			return 0;
		}

		/*
		 * Try DNS
		 */
		bzero(&response, sizeof(struct domain_info));
		if (_val_query (nodename, ns_c_in, ns_t_a, &response, dnssec_status) < 0) {
			free_domain_info_ptrs(&response);
			return EAI_SYSTEM;
		}
		else {
			/* Extract answers from response */
			*res = get_addrinfo_from_response(response.di_rrset, servname, hints);
			free_domain_info_ptrs(&response);
			return 0;
		}
	}
} /* val_getaddrinfo() */
