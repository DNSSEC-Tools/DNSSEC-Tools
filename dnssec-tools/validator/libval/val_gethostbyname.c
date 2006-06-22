/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the implementation file for a validating gethostbyname function.
 * Applications should be able to use this with minimal change.
 */
#include "validator-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include <validator.h>
#include <resolver.h>
#include "val_policy.h"
#include "val_log.h"

#define ETC_HOSTS_CONF "/etc/host.conf"
#define ETC_HOSTS      "/etc/hosts"
#define MAXLINE 4096
#define MAX_ALIAS_COUNT 2048
#define AUX_BUFLEN 16384

extern int h_errno;
static struct hostent g_hentry;
static char g_auxbuf[AUX_BUFLEN];

/*
 * Function: bufalloc
 *
 * Purpose: Allocate memory of specified size from the given buffer
 *
 * Parameters:
 *              buf -- The buffer from which to allocate memory.
 *                     This parameter must not be NULL.
 *           buflen -- Length of the buffer
 *           offset -- Pointer to an integer variable that holds
 *                     the position in the buffer from where memory
 *                     is to be allocated.  The offset is advanced
 *                     by 'alloc_size' if memory is allocated successfully.
 *                     This parameter must not be NULL.
 *       alloc_size -- Size of the memory to be allocated.
 *
 * Return value: Returns pointer to the allocated memory if successful.
 *               Returns NULL on failure.
 */
static void *bufalloc (char *buf, size_t buflen, int *offset, size_t alloc_size)
{
	if ((buf == NULL) || (offset == NULL)) {
		return NULL;
	}

	if (((*offset) + alloc_size) >= buflen) {
		return NULL;
	}
	else {
		void *retval = (void *) (buf + (*offset));
		(*offset) += alloc_size;
		return retval;
	}
}


/*
 * Function: get_hostent_from_etc_hosts
 *
 * Purpose: Read the ETC_HOSTS file and check if it contains the given name.
 *          Return the result in a hostent structure.
 *
 * Parameters:
 *              ctx -- The validation context.
 *             name -- The domain name or IP address in string form.
 *               af -- The address family: AF_INET or AF_INET6.
 *              ret -- Pointer to a hostent structure to return the result.
 *                     This parameter must not be NULL.
 *              buf -- A buffer to store auxiliary data.  This parameter must not be NULL.
 *           buflen -- Length of the buffer 'buf'.
 *           offset -- Pointer to an integer variable that contains the offset in the buffer
 *                     'buf', where data can be written.  When this function writes any data
 *                     in the auxiliary data, the offset is incremented accordingly.  This
 *                     parameter must not be NULL.
 *
 * Return value: Returns NULL on failure and 'ret' on success.
 *
 * See also: get_hostent_from_response()
 */
static struct hostent* get_hostent_from_etc_hosts (val_context_t *ctx,
						   const char *name,
						   int af,
						   struct hostent *ret,
						   char *buf,
						   int buflen,
						   int *offset)
{
	int orig_offset = 0;
	struct hosts *hs = NULL;

	if ((ret == NULL) || (buf == NULL) || (offset == NULL) || (*offset < 0)) {
		return NULL;
	}

	/* Parse the /etc/hosts file */
	hs = parse_etc_hosts (name);

	orig_offset = *offset;
	bzero(ret, sizeof(struct hostent));
	
	/* XXX: todo -- can hs have more than one element ? */
	while (hs) {
		struct hosts *h_prev = NULL;
		struct in_addr ip4_addr;
		struct in6_addr ip6_addr;
		char addr_buf[INET6_ADDRSTRLEN];
		int i, alias_count;
		int len = 0;
		
		bzero(&ip4_addr, sizeof(struct in_addr));
		bzero(&ip6_addr, sizeof(struct in6_addr));
		
		if ((af == AF_INET) && (inet_pton(AF_INET, hs->address, &ip4_addr) > 0)) {
			val_log(ctx, LOG_DEBUG, "...type of address is IPv4");
			val_log(ctx, LOG_DEBUG, "Address is: %s",
				inet_ntop(AF_INET, &ip4_addr, addr_buf, INET_ADDRSTRLEN));
		}
		else if ((af == AF_INET6) && (inet_pton(AF_INET6, hs->address, &ip6_addr) > 0)) {
			val_log(ctx, LOG_DEBUG, "...type of address is IPv6");
			val_log(ctx, LOG_DEBUG, "Address is: %s",
				inet_ntop(AF_INET, &ip6_addr, addr_buf, INET6_ADDRSTRLEN));
		}
		else {
			/* not a valid address ... skip this line */
			val_log(ctx, LOG_DEBUG, "get_hostent_from_etc_hosts() error in address format: %s", hs->address);
			h_prev = hs;
			hs = hs->next;
			FREE_HOSTS(h_prev);
			continue;
		}

		// Name
		len = (hs->canonical_hostname == NULL) ? 0 : strlen(hs->canonical_hostname);

		if (hs->canonical_hostname) {
			ret->h_name = (char *) bufalloc(buf, buflen, offset, len + 1);
			if (ret->h_name == NULL) {
				*offset = orig_offset;
				return NULL;
			}

			memcpy(ret->h_name, hs->canonical_hostname, len + 1);
		}
		else {
			ret->h_name = NULL;
		}

		// Aliases
		alias_count = 0;
		while (hs->aliases[alias_count]) {
			alias_count++;
		}
		alias_count++;
		
		ret->h_aliases = (char **) bufalloc(buf, buflen, offset, alias_count * sizeof(char *));

		if (ret->h_aliases == NULL) {
			*offset = orig_offset;
			return NULL;
		}
		
		for (i=0; i<alias_count; i++) {
			len = (hs->aliases[i] == NULL) ? 0 : strlen(hs->aliases[i]);
			if (hs->aliases[i]) {
				ret->h_aliases[i] = (char *) bufalloc(buf, buflen, offset, len + 1);
				if (ret->h_aliases[i] == NULL) {
					*offset = orig_offset;
					return NULL;
				}
				memcpy(ret->h_aliases[i], hs->aliases[i], len + 1);
			}
			else {
				ret->h_aliases[i] = NULL;
			}
		}
		
		// Addresses
		ret->h_addr_list = (char **) bufalloc(buf, buflen, offset, 2 * sizeof(char *));
		if (af == AF_INET) {
		    ret->h_addrtype = AF_INET;
		    ret->h_length = sizeof(struct in_addr);
		    ret->h_addr_list[0] = (char *) bufalloc(buf, buflen, offset, sizeof(struct in_addr));
		    if (ret->h_addr_list[0] == NULL) {
			    *offset = orig_offset;
			    return NULL;
		    }
		    memcpy(ret->h_addr_list[0], &ip4_addr, sizeof(struct in_addr));
		    ret->h_addr_list[1] = 0;
		}
		else if (af == AF_INET6) {
		    ret->h_addrtype = AF_INET6;
		    ret->h_length = sizeof(struct in6_addr);
		    ret->h_addr_list[0] = (char *) bufalloc(buf, buflen, offset, sizeof(struct in6_addr));
		    if (ret->h_addr_list[0] == NULL) {
			    *offset = orig_offset;
			    return NULL;
		    }
		    memcpy(ret->h_addr_list[0], &ip6_addr, sizeof(struct in6_addr));
		    ret->h_addr_list[1] = 0;
		}
		else {
			*offset = orig_offset;
			return NULL;
		}
		
		hs = hs->next;
		h_prev = hs;
		FREE_HOSTS(h_prev);
		return ret;
	}
	
	return NULL;
	
} /* get_hostent_from_etc_hosts() */


/*
 * Function: get_hostent_from_response
 *
 * Purpose: Converts the linked list of val_result_chain structures obtained
 *          as a result from the validator into a hostent structure.
 *
 * Parameters:
 *              ctx -- The validation context.
 *               af -- The address family: AF_INET or AF_INET6.
 *              ret -- Pointer to a hostent structure to return the result.
 *                     This parameter must not be NULL.
 *          results -- Pointer to a linked list of val_result_chain structures.
 *         h_errnop -- Pointer to an integer variable to store the h_errno value.
 *              buf -- A buffer to store auxiliary data.  This parameter must not be NULL.
 *           buflen -- Length of the buffer 'buf'.
 *           offset -- Pointer to an integer variable that contains the offset in the buffer
 *                     'buf', where data can be written.  When this function writes any data
 *                     in the auxiliary data, the offset is incremented accordingly.  This
 *                     parameter must not be NULL.
 *
 * Return value: Returns NULL on failure and 'ret' on success.
 *
 * See also: get_hostent_from_etc_hosts()
 */
static struct hostent *get_hostent_from_response (val_context_t *ctx, int af, struct hostent *ret,
						  struct val_result_chain *results, int *h_errnop,
						  char *buf, int buflen, int *offset)
{
	int alias_count = 0;
	int alias_index = 0;
	int addr_count  = 0;
	int addr_index  = 0;
	int orig_offset = 0;
	char dname [NS_MAXDNAME];

	/* Check parameter sanity */
	if (!results || !h_errnop || !buf || !offset || !ret) {
		return NULL;
	}
	
	orig_offset = *offset;
	bzero(ret, sizeof(struct hostent));

	struct val_result_chain *res;

	/* Count the number of aliases and addresses in the result */
	for (res = results; res != NULL; res = res->val_rc_next) {

		if (res->val_rc_trust == NULL)
			continue;

		struct rrset_rec *rrset = res->val_rc_trust->_as.ac_data;
		
		// Get a count of aliases and addresses
		while (rrset) {
			struct rr_rec *rr = rrset->rrs.val_rrset_data;
			
			while (rr) {
				
				if (rrset->rrs.val_rrset_type_h == ns_t_cname) {
					val_log(ctx, LOG_DEBUG, "val_gethostbyname: type of record = CNAME");
					alias_count++;
				}
				else if ((af == AF_INET) && (rrset->rrs.val_rrset_type_h == ns_t_a)) {
					val_log(ctx, LOG_DEBUG, "val_gethostbyname: type of record = A");
					addr_count++;
				}
				else if ((af == AF_INET6) && (rrset->rrs.val_rrset_type_h == ns_t_aaaa)) {
					val_log(ctx, LOG_DEBUG, "val_gethostbyname: type of record = AAAA");
					addr_count++;
				}
				
				rr = rr->rr_next;
			}
			// else ignore the rrset and move on to the next
			rrset = rrset->rrs_next;
		}
	} // end for

	ret->h_aliases = (char **) bufalloc (buf, buflen, offset, (alias_count + 1) * sizeof(char*));
	if (ret->h_aliases == NULL) {
		*offset = orig_offset;
		return NULL;
	}
	ret->h_aliases[alias_count] = 0;
	
	ret->h_addr_list = (char **) bufalloc (buf, buflen, offset, (addr_count + 1) * sizeof(char*));
	if (ret->h_addr_list == NULL) {
		*offset = orig_offset;
		return NULL;
	}
	ret->h_addr_list[addr_count] = 0;

	alias_index = alias_count -1;

	/* Process the result */
	for (res = results; res != NULL; res = res->val_rc_next) {
		if (res->val_rc_trust == NULL) 
			continue;

		struct rrset_rec *rrset = res->val_rc_trust->_as.ac_data;
		
		while (rrset) {
			struct rr_rec *rr = rrset->rrs.val_rrset_data;

			while (rr) {
				// Handle CNAME RRs
				if (rrset->rrs.val_rrset_type_h == ns_t_cname) {
					
					bzero(dname, NS_MAXDNAME);
					if (ns_name_ntop(rrset->rrs.val_rrset_name_n, dname, NS_MAXDNAME) < 0) {
						*offset = orig_offset;
						return NULL;
					}
					
					if (alias_index >= 0) {
						ret->h_aliases[alias_index] = (char *) bufalloc(buf, buflen, offset,
												(strlen(dname) + 1) * sizeof (char));
						if (ret->h_aliases[alias_index] == NULL) {
							*offset = orig_offset;
							return NULL;
						}
						memcpy(ret->h_aliases[alias_index], dname, strlen(dname) + 1);
						alias_index--;
					}
					
					if (!ret->h_name) {
						bzero(dname, NS_MAXDNAME);
						if (ns_name_ntop(rr->rr_rdata, dname, NS_MAXDNAME) < 0) {
							*offset = orig_offset;
							return NULL;
						}
						ret->h_name = (char *) bufalloc (buf, buflen, offset, (strlen(dname) + 1)* sizeof(char));
						if (ret->h_name == NULL) {
							*offset = orig_offset;
							return NULL;
						}
						memcpy(ret->h_name, dname, strlen(dname) + 1);
					}
				}
				// Handle A and AAAA RRs
				else if ( ((af == AF_INET) && (rrset->rrs.val_rrset_type_h == ns_t_a)) ||
					  ((af == AF_INET6)&& (rrset->rrs.val_rrset_type_h == ns_t_aaaa)) ) {
					
					bzero(dname, NS_MAXDNAME);
					if (ns_name_ntop(rrset->rrs.val_rrset_name_n, dname, NS_MAXDNAME) < 0) {
						*offset = orig_offset;
						return NULL;
					}
					
					if (!ret->h_name) {
						ret->h_name = (char *) bufalloc(buf, buflen, offset, (strlen(dname) + 1) * sizeof(char));
						if (ret->h_name == NULL) {
							*offset = orig_offset;
							return NULL;
						}
						memcpy(ret->h_name, dname, strlen(dname) + 1);
					}
					
					if (strcasecmp (ret->h_name, dname) == 0) {
						ret->h_length = rr->rr_rdata_length_h;
						ret->h_addrtype = af;
						
						ret->h_addr_list[addr_index] = (char *) bufalloc (buf, buflen, offset,
												  rr->rr_rdata_length_h * sizeof(char));
						if (ret->h_addr_list[addr_index] == NULL) {
							*offset = orig_offset;
							return NULL;
						}
						
						memcpy(ret->h_addr_list[addr_index], rr->rr_rdata, rr->rr_rdata_length_h);
						addr_index++;
					}
				}
				
				rr = rr->rr_next;
			}
			
			rrset = rrset->rrs_next;
		}
	}
	
	if (addr_count > 0) {
		*h_errnop = NETDB_SUCCESS;
		return ret;
	}
	else if (alias_count > 0) {
		*h_errnop = NO_DATA;
		return ret;
	}
	else {
		*offset = orig_offset;
		*h_errnop = HOST_NOT_FOUND;
		return NULL;
	}

} /* get_hostent_from_response() */


/*
 * Function: val_gethostbyname2_r
 *
 * Purpose: A validating DNSSEC-aware version of the reentrant gethostbyname2_r
 *          function.  This function supports both IPv4 and IPv6 addresses.
 *
 * Parameters:
 *              ctx -- The validation context.  Can be NULL for default value.
 *             name -- The domain name or IP address in string format.
 *               af -- Address family AF_INET or AF_INET6
 *              ret -- Pointer to a hostent variable to store the return value.
 *                     This parameter must not be NULL.
 *              buf -- Pointer to a buffer to store auxiliary data.  This
 *                     parameter must not be NULL.
 *           buflen -- Length of the buffer 'buf'.
 *           result -- Pointer to a variable of type (struct hostent *).  This
 *                     parameter must not be NULL.  *result will contain NULL on
 *                     failure and will point to the 'ret' parameter on success.
 *         h_errnop -- Pointer to an integer variable to return the h_errno error
 *                     code.  This parameter must not be NULL.
 *       val_status -- A pointer to a val_status_t variable to hold the
 *                     returned validation-status value.  This parameter
 *                     must not be NULL.
 *                     If successful, *val_status will contain a success
 *                     code. If there is a failure, *val_status will contain
 *                     the validator error code. To test whether the returned
 *                     error code represents a trustworthy status, the caller
 *                     can use the val_istrusted() function. 
 *
 * Return value: 0 on success, and a non-zero error-code on failure.
 *
 * See also: val_gethostbyname2(), val_gethostbyname_r(), val_istrusted()
 */
int val_gethostbyname2_r( const val_context_t *ctx,
			  const char *name,
			  int af,
			  struct hostent *ret,
			  char *buf,
			  size_t buflen,
			  struct hostent **result,
			  int *h_errnop,
			  val_status_t *val_status )
{
	struct in_addr ip4_addr;
	struct in6_addr ip6_addr;
	int offset = 0;
	
	if (!name || !ret || !h_errnop || !val_status || !result || !buf) {
		if (result) {
			*result = NULL;
		}
		return EINVAL;
	}
	
	bzero(&ip4_addr, sizeof(struct in_addr));
	bzero(&ip6_addr, sizeof(struct in6_addr));
	
	/* Check if the address-family is AF_INET and the address is an IPv4 address */
	if ((af == AF_INET) && (inet_pton(AF_INET, name, &ip4_addr) > 0)) {
		bzero(ret, sizeof(struct hostent));

		// Name
		ret->h_name = bufalloc(buf, buflen, &offset, strlen(name) + 1);
		if (ret->h_name == NULL) {
			return ERANGE;
		}
		memcpy(ret->h_name, name, strlen(name) + 1);

		// Alias
		ret->h_aliases = (char **) bufalloc (buf, buflen, &offset, sizeof(char *));
		if (ret->h_aliases == NULL) {
			return ERANGE;
		}
		ret->h_aliases[0] = 0;

		// Address
		ret->h_addrtype = AF_INET;
		ret->h_length = sizeof(struct in_addr);
		ret->h_addr_list = (char **) bufalloc (buf, buflen, &offset, 2 * sizeof(char *));
		if (ret->h_addr_list == NULL) {
			return ERANGE;
		}
		ret->h_addr_list[0] = (char *) bufalloc (buf, buflen, &offset, sizeof(struct in_addr));
		if (ret->h_addr_list[0] == NULL) {
			return ERANGE;
		}
		memcpy(ret->h_addr_list[0], &ip4_addr, sizeof(struct in_addr));
		ret->h_addr_list[1] = 0;

		*val_status = VAL_LOCAL_ANSWER;
		*h_errnop = NETDB_SUCCESS;
		*result = ret;

		return 0;
	}

	/* Check if the address-family is AF_INET6 and the address is an IPv6 address */
	else if ((af == AF_INET6) && (inet_pton(AF_INET6, name, &ip6_addr) > 0)) {
		bzero(ret, sizeof(struct hostent));

		// Name
		ret->h_name = bufalloc(buf, buflen, &offset, strlen(name) + 1);
		if (ret->h_name == NULL) {
			return ERANGE;
		}
		memcpy(ret->h_name, name, strlen(name) + 1);

		// Alias
		ret->h_aliases = (char **) bufalloc (buf, buflen, &offset, sizeof(char *));
		if (ret->h_aliases == NULL) {
			return ERANGE;
		}
		ret->h_aliases[0] = 0;

		// Address
		ret->h_addrtype = AF_INET6;
		ret->h_length = sizeof(struct in6_addr);
		ret->h_addr_list = (char **) bufalloc (buf, buflen, &offset, 2 * sizeof(char *));
		if (ret->h_addr_list == NULL) {
			return ERANGE;
		}
		ret->h_addr_list[0] = (char *) bufalloc(buf, buflen, &offset, sizeof(struct in6_addr));
		if (ret->h_addr_list[0] == NULL) {
			return ERANGE;
		}
		memcpy(ret->h_addr_list[0], &ip6_addr, sizeof(struct in6_addr));
		ret->h_addr_list[1] = 0;

		*val_status = VAL_LOCAL_ANSWER;
		*h_errnop = NETDB_SUCCESS;
		*result = ret;

		return 0;
	}
	else {
		int retval;
		struct val_result_chain *results = NULL;
		u_char name_n[NS_MAXCDNAME];
		val_context_t *context = NULL;
		
		if (ctx == NULL) {
			if(VAL_NO_ERROR != (retval = val_create_context(NULL, &context)))
				return retval;
		}
		else
			context = (val_context_t *) ctx;   

		*result = NULL;
		
		/* First check the ETC_HOSTS file
		 * XXX: TODO check the order in the ETC_HOST_CONF file
		 */
		*result = get_hostent_from_etc_hosts (context, name, af, ret, buf, buflen, &offset);
		
		if (*result != NULL) {
			*val_status = VAL_LOCAL_ANSWER;
			*h_errnop = NETDB_SUCCESS;
			if((ctx == NULL) && context)
				val_free_context(context);
			return 0;
		}
		
		u_int16_t type = ns_t_a;
		if (af == AF_INET6) {
			type = ns_t_aaaa;
		}

		/* Query the validator */
		if (((retval = ns_name_pton(name, name_n, NS_MAXCDNAME-1)) != -1)
		    && (VAL_NO_ERROR == (retval = val_resolve_and_check(context, name_n, ns_c_in, type, 0,
							      &results)))) {
			
			/* Convert the validator result into hostent */
		        *result = get_hostent_from_response(context, af, ret, results, h_errnop, buf, buflen, &offset);
			
			if (*result) {
			    *val_status = results->val_rc_status;
			}
		}
		
		if(*result == NULL)
			*h_errnop = HOST_NOT_FOUND;
		else
			*h_errnop = NETDB_SUCCESS;
		
		val_free_result_chain(results);
		
		if((ctx == NULL) && context)
			val_free_context(context);
		
		// XXX what if error?
		return 0;
	}	
}

/*
 * Function: val_gethostbyname2
 *
 * Purpose: A validating DNSSEC-aware version of the gethostbyname2 function.
 *          This function supports both IPv4 and IPv6 addresses.
 *
 * Parameters:
 *              ctx -- The validation context.  Can be NULL for default value.
 *             name -- The domain name or IP address in string form
 *               af -- Address family AF_INET or AF_INET6
 *       val_status -- A pointer to a val_status_t variable to hold the
 *                     returned validation-status value.  This parameter
 *                     must not be NULL.
 *                     If successful, *val_status will contain a success
 *                     code. If there is a failure, *val_status will contain
 *                     the validator error code. To test whether the returned
 *                     error code represents a trustworthy status, the caller
 *                     can use the val_istrusted() function. 
 *
 * Return value:
 *        Returns the entry from the host database or DNS for host on success.
 *        Returns NULL on failure.
 *
 * See also: val_gethostbyname2_r, val_istrusted
 */
struct hostent *val_gethostbyname2( const val_context_t *ctx,
				    const char *name,
				    int af,
				    val_status_t *val_status )
{
    struct hostent *result = NULL;
    val_gethostbyname2_r(ctx, name, af, &g_hentry, g_auxbuf,
			 AUX_BUFLEN, &result, &h_errno, val_status);
    return result;

} /* val_gethostbyname2() */

/*
 * Function: val_gethostbyname
 *
 * Purpose: A validating DNSSEC-aware version of the gethostbyname function.
 *          This function supports only IPv4 addresses.
 *
 * Parameters:
 *              ctx -- The validation context.  Can be NULL for default value.
 *             name -- The domain name or IPv4 address in dotted-decimal format.
 *       val_status -- A pointer to a val_status_t variable to hold the
 *                     returned validation-status value.  This parameter
 *                     must not be NULL.
 *                     If successful, *val_status will contain a success
 *                     code. If there is a failure, *val_status will contain
 *                     the validator error code. To test whether the returned
 *                     error code represents a trustworthy status, the caller
 *                     can use the val_istrusted() function. 
 *
 * Return value:
 *        Returns the entry from the host database or DNS for host on success.
 *        Returns NULL on failure.
 *
 * See also: val_gethostbyname_r(), val_gethostbyname2, val_istrusted()
 */
struct hostent *val_gethostbyname( const val_context_t *ctx,
				   const char *name,
				   val_status_t *val_status )
{
    return val_gethostbyname2(ctx, name, AF_INET, val_status);

} /* val_gethostbyname() */

/*
 * Function: val_gethostbyname_r
 *
 * Purpose: A validating DNSSEC-aware version of the reentrant gethostbyname_r
 *          function.  This function only supports IPv4 addresses.
 *
 * Parameters:
 *              ctx -- The validation context.  Can be NULL for default value.
 *             name -- The domain name or IPv4 address in dotted-decimal format.
 *              ret -- Pointer to a hostent variable to store the return value.
 *                     This parameter must not be NULL.
 *              buf -- Pointer to a buffer to store auxiliary data.  This
 *                     parameter must not be NULL.
 *           buflen -- Length of the buffer 'buf'.
 *           result -- Pointer to a variable of type (struct hostent *).  This
 *                     parameter must not be NULL.  *result will contain NULL on
 *                     failure and will point to the 'ret' parameter on success.
 *         h_errnop -- Pointer to an integer variable to return the h_errno error
 *                     code.  This parameter must not be NULL.
 *       val_status -- A pointer to a val_status_t variable to hold the
 *                     returned validation-status value.  This parameter
 *                     must not be NULL.
 *                     If successful, *val_status will contain a success
 *                     code. If there is a failure, *val_status will contain
 *                     the validator error code. To test whether the returned
 *                     error code represents a trustworthy status, the caller
 *                     can use the val_istrusted() function. 
 *
 * Return value: 0 on success, and a non-zero error-code on failure.
 *
 * See also: val_gethostbyname2_r(), val_gethostbyname(), val_istrusted()
 */
int val_gethostbyname_r( const val_context_t *ctx,
			 const char *name,
			 struct hostent *ret,
			 char *buf,
			 size_t buflen,
			 struct hostent **result,
			 int *h_errnop,
			 val_status_t *val_status )
{
    return val_gethostbyname2_r(ctx, name, AF_INET, ret, buf, buflen,
				result, h_errnop, val_status);
} /* val_gethostbyname_r() */
