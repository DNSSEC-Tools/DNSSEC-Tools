/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 */

/* 
 * DESCRIPTION
 * This file contains the implementation for a validating gethostbyname function.
 * Applications should be able to use this with minimal change.
 */
#include "validator-internal.h"

#include "val_policy.h"
#include "val_parse.h"
#include "val_context.h"

#define MAXLINE 4096
#define MAX_ALIAS_COUNT 2048
#define AUX_BUFLEN 16384

static struct hostent g_hentry;
static char     g_auxbuf[AUX_BUFLEN];

extern int address_to_reverse_domain(const char *saddr, int family,
                                  char *dadd, int dlen);

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
static void    *
bufalloc(char *buf, size_t buflen, int *offset, size_t alloc_size)
{
    if ((buf == NULL) || (offset == NULL)) {
        return NULL;
    }

    if (((*offset) + alloc_size) >= buflen) {
        return NULL;
    } else {
        void           *retval = (void *) (buf + (*offset));
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
static struct hostent *
get_hostent_from_etc_hosts(val_context_t * ctx,
                           const char *name,
                           int af,
                           struct hostent *ret,
                           char *buf, int buflen, int *offset)
{
    int             orig_offset = 0;
    struct hosts   *hs = NULL;
    struct hosts   *h_prev = NULL;

    if ((ret == NULL) || (buf == NULL) || (offset == NULL)
        || (*offset < 0)) {
        return NULL;
    }

    /*
     * Parse the /etc/hosts file 
     */
    hs = parse_etc_hosts(name);

    orig_offset = *offset;
    memset(ret, 0, sizeof(struct hostent));

    /*
     * XXX: todo -- can hs have more than one element ? 
     */
    while (hs) {
        struct sockaddr_in sa;
#if defined( WIN32 )
        size_t addrlen4 = sizeof(struct sockaddr_in);
#endif
#ifdef VAL_IPV6
        struct sockaddr_in6 sa6;
#if defined( WIN32 )
        size_t addrlen6 = sizeof(struct sockaddr_in6);
#endif
#endif
        char            addr_buf[INET6_ADDRSTRLEN];
        int             i, alias_count;
        int             len = 0;
        const char *addr = NULL;
        size_t buflen = INET6_ADDRSTRLEN;

        memset(&sa, 0, sizeof(sa));
#ifdef VAL_IPV6
        memset(&sa6, 0, sizeof(sa6));
#endif

        if ((af == AF_INET)
            && (INET_PTON(AF_INET, hs->address, ((struct sockaddr *)&sa), &addrlen4) > 0)) {
            INET_NTOP(AF_INET, (&sa), sizeof(sa), addr_buf, buflen, addr);
            val_log(ctx, LOG_DEBUG, "get_hostent_from_etc_hosts(): type of address is IPv4");
            val_log(ctx, LOG_DEBUG, "get_hostent_from_etc_hosts(): Address is: %s",
                    addr
		);
        } 
#ifdef VAL_IPV6
	else if ((af == AF_INET6)
                   && (INET_PTON(AF_INET6, hs->address, ((struct sockaddr *)&sa6), &addrlen6) > 0)) {
	    
            INET_NTOP(AF_INET6, (&sa6), sizeof(sa6), addr_buf, buflen, addr);
            val_log(ctx, LOG_DEBUG, "get_hostent_from_etc_hosts(): type of address is IPv6");
            val_log(ctx, LOG_DEBUG, "get_hostent_from_etc_hosts(): Address is: %s",
                    addr
                  );
        } 
#endif
	else {
            /*
             * not a valid address ... skip this line 
             */
            val_log(ctx, LOG_WARNING,
                    "get_hostent_from_etc_hosts(): error in address format: %s",
                    hs->address);
            h_prev = hs;
            hs = hs->next;
            FREE_HOSTS(h_prev);
            continue;
        }

        // Name
        len =
            (hs->canonical_hostname ==
             NULL) ? 0 : strlen(hs->canonical_hostname);

        if (hs->canonical_hostname) {
            ret->h_name = (char *) bufalloc(buf, buflen, offset, len + 1);
            if (ret->h_name == NULL) {
                goto err;
            }

            memcpy(ret->h_name, hs->canonical_hostname, len + 1);
        } else {
            ret->h_name = NULL;
        }

        // Aliases
        alias_count = 0;
        while (hs->aliases[alias_count]) {
            alias_count++;
        }
        alias_count++;

        ret->h_aliases =
            (char **) bufalloc(buf, buflen, offset,
                               alias_count * sizeof(char *));

        if (ret->h_aliases == NULL) {
            goto err;
        }

        for (i = 0; i < alias_count; i++) {
            len = (hs->aliases[i] == NULL) ? 0 : strlen(hs->aliases[i]);
            if (hs->aliases[i]) {
                ret->h_aliases[i] =
                    (char *) bufalloc(buf, buflen, offset, len + 1);
                if (ret->h_aliases[i] == NULL) {
                    goto err;
                }
                memcpy(ret->h_aliases[i], hs->aliases[i], len + 1);
            } else {
                ret->h_aliases[i] = NULL;
            }
        }

        // Addresses
        ret->h_addr_list =
            (char **) bufalloc(buf, buflen, offset, 2 * sizeof(char *));
        if ((ret->h_addr_list == NULL)
            || ((af != AF_INET) && (af != AF_INET6))) {
            goto err;
        }
        if (af == AF_INET) {
            ret->h_addrtype = AF_INET;
            ret->h_length = sizeof(struct in_addr);
            ret->h_addr_list[0] =
                (char *) bufalloc(buf, buflen, offset,
                                  sizeof(struct in_addr));
            if (ret->h_addr_list[0] == NULL) {
                goto err;
            }
            memcpy(ret->h_addr_list[0], &sa.sin_addr, sizeof(struct in_addr));
            ret->h_addr_list[1] = 0;
        } 
#ifdef VAL_IPV6
        else if (af == AF_INET6) {
            ret->h_addrtype = AF_INET6;
            ret->h_length = sizeof(struct in6_addr);
            ret->h_addr_list[0] =
                (char *) bufalloc(buf, buflen, offset,
                                  sizeof(struct in6_addr));
            if (ret->h_addr_list[0] == NULL) {
                goto err;
            }
            memcpy(ret->h_addr_list[0], &sa6.sin6_addr,
                   sizeof(struct in6_addr));
            ret->h_addr_list[1] = 0;
        }
#endif

        /*
         * clean up host list 
         */
        while (hs) {
            h_prev = hs;
            hs = hs->next;
            FREE_HOSTS(h_prev);
        }
        return ret;
    }

    return NULL;

  err:
    /*
     * clean up host list 
     */
    while (hs) {
        h_prev = hs;
        hs = hs->next;
        FREE_HOSTS(h_prev);
    }

    *offset = orig_offset;
    return NULL;

}                               /* get_hostent_from_etc_hosts() */


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
static struct hostent *
get_hostent_from_response(val_context_t * ctx, int af, struct hostent *ret,
                          struct val_result_chain *results, int *h_errnop,
                          char *buf, int buflen, int *offset, 
                          val_status_t * val_status)
{
    int             alias_count = 0;
    int             alias_index = 0;
    int             addr_count = 0;
    int             addr_index = 0;
    int             orig_offset = 0;
    struct val_result_chain *res;
    int validated = 1;
    int trusted = 1;
    struct val_rrset_rec *rrset;
    char *alias_target = NULL;

    /*
     * Check parameter sanity 
     */
    if (!results || !h_errnop || !buf || !offset || !ret || !val_status) {
        return NULL;
    }

    *val_status = VAL_DONT_KNOW;
    *h_errnop = 0;
    
    orig_offset = *offset;
    memset(ret, 0, sizeof(struct hostent));

    /*
     * Count the number of aliases and addresses in the result 
     */
    for (res = results; res != NULL; res = res->val_rc_next) {
        rrset = res->val_rc_rrset;

        if (res->val_rc_alias && rrset) {
            val_log(ctx, LOG_DEBUG,
                    "get_hostent_from_response(): type of record = CNAME");
            alias_count++;
            continue;
        }

        // Get a count of aliases and addresses
        if (rrset) {
            struct val_rr_rec  *rr = rrset->val_rrset_data;

            while (rr) {

                if ((af == AF_INET)
                           && (rrset->val_rrset_type == ns_t_a)) {
                    val_log(ctx, LOG_DEBUG,
                            "get_hostent_from_response(): type of record = A");
                    addr_count++;
                } else if ((af == AF_INET6)
                           && (rrset->val_rrset_type == ns_t_aaaa)) {
                    val_log(ctx, LOG_DEBUG,
                            "get_hostent_from_response(): type of record = AAAA");
                    addr_count++;
                }

                rr = rr->rr_next;
            }
        }
    }

    ret->h_aliases =
        (char **) bufalloc(buf, buflen, offset,
                           (alias_count + 1) * sizeof(char *));
    if (ret->h_aliases == NULL) {
        goto err;
    }
    ret->h_aliases[alias_count] = NULL;

    ret->h_addr_list =
        (char **) bufalloc(buf, buflen, offset,
                           (addr_count + 1) * sizeof(char *));
    if (ret->h_addr_list == NULL) {
        goto err;
    }
    ret->h_addr_list[addr_count] = NULL;

    alias_index = alias_count - 1;

    if (results == NULL) {
        *val_status = VAL_UNTRUSTED_ANSWER;
        *h_errnop = HOST_NOT_FOUND; 
        goto err;
    } 
   
    /*
     * Process the result 
     */
    for (res = results; res != NULL; res = res->val_rc_next) {

        rrset = res->val_rc_rrset;

        if (!(validated && val_isvalidated(res->val_rc_status))) 
            validated = 0;
        if (!(trusted && val_istrusted(res->val_rc_status)))
            trusted = 0;

        /* save the non-existence state */
        if (val_does_not_exist(res->val_rc_status)) {
            *val_status = res->val_rc_status;
            if (res->val_rc_status == VAL_NONEXISTENT_NAME ||
                res->val_rc_status == VAL_NONEXISTENT_NAME_NOCHAIN) {

                *h_errnop = HOST_NOT_FOUND;
            } else { 
                *h_errnop = NO_DATA;
            }
            break;
        }

        if (res->val_rc_alias && rrset) {
            // Handle CNAME RRs
            if (alias_index >= 0) {
                ret->h_aliases[alias_index] =
                    (char *) bufalloc(buf, buflen, offset,
                                      (strlen(rrset->val_rrset_name) + 1) * sizeof(char));
                if (ret->h_aliases[alias_index] == NULL) {
                    goto err;
                }
                memcpy(ret->h_aliases[alias_index], rrset->val_rrset_name,
                       strlen(rrset->val_rrset_name) + 1);
                alias_index--;
            }

            /* save the alias target for later use */
            alias_target = res->val_rc_alias; 
        } else if (rrset) {

            if (((af == AF_INET)
                      && (rrset->val_rrset_type == ns_t_a))
                || ((af == AF_INET6)
                      && (rrset->val_rrset_type == ns_t_aaaa))) {

                struct val_rr_rec  *rr = rrset->val_rrset_data;

                if (!ret->h_name) {
                    ret->h_name =
                            (char *) bufalloc(buf, buflen, offset,
                                              (strlen(rrset->val_rrset_name) +
                                               1) * sizeof(char));
                    if (ret->h_name == NULL) {
                        goto err;
                    }
                    memcpy(ret->h_name, rrset->val_rrset_name, strlen(rrset->val_rrset_name) + 1);
                }

                while (rr) {
                    // Handle A and AAAA RRs
                    ret->h_length = rr->rr_rdata_length;
                    ret->h_addrtype = af;
                    ret->h_addr_list[addr_index] =
                            (char *) bufalloc(buf, buflen, offset,
                                              rr->rr_rdata_length *
                                              sizeof(char));
                    if (ret->h_addr_list[addr_index] == NULL) {
                        goto err;
                    }

                    memcpy(ret->h_addr_list[addr_index], rr->rr_rdata,
                               rr->rr_rdata_length);
                    addr_index++;

                    rr = rr->rr_next;
                }
            }
        }
    }
    /* pick up official name from the alias target */
    if (!ret->h_name && alias_target) {
        ret->h_name = (char *) bufalloc(buf, buflen, offset,
                          (strlen(alias_target) + 1) * sizeof(char));
        if (ret->h_name == NULL) {
            goto err;
        }
        memcpy(ret->h_name, alias_target, strlen(alias_target) + 1);
    }

    if (addr_count > 0) {
        *h_errnop = NETDB_SUCCESS;
        if (validated)
            *val_status = VAL_VALIDATED_ANSWER;
        else if (trusted)
            *val_status = VAL_TRUSTED_ANSWER;
        else 
            *val_status = VAL_UNTRUSTED_ANSWER; 
    } else if (alias_count == 0) {
        goto err;
    } else if (*h_errnop == 0)   {
        /* missing a proof of non-existence for alias */
        *val_status = VAL_UNTRUSTED_ANSWER;
        *h_errnop = NO_DATA;
    } 
    return ret;

err:
    *offset = orig_offset;
    return NULL;
    
}                               /* get_hostent_from_response() */


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
int
val_gethostbyname2_r(val_context_t * context,
                     const char *name,
                     int af,
                     struct hostent *ret,
                     char *buf,
                     size_t buflen,
                     struct hostent **result,
                     int *h_errnop, val_status_t * val_status)
{
    struct sockaddr_in  sa;
#if defined( WIN32 )
    size_t addrlen4 = sizeof(struct sockaddr_in);
#endif
#ifdef VAL_IPV6
    struct sockaddr_in6 sa6;
#if defined( WIN32 )
    size_t addrlen6 = sizeof(struct sockaddr_in6);
#endif
#endif
    int             offset = 0;
    val_status_t local_ans_status = VAL_OOB_ANSWER;
    int trusted = 0;
    int             retval;
    struct val_result_chain *results = NULL;
    u_int16_t       type;
    val_context_t *ctx = NULL;

    *val_status = VAL_DONT_KNOW;

    memset(&sa, 0, sizeof(sa));
#ifdef VAL_IPV6
    memset(&sa6, 0, sizeof(sa6));
#endif
    
    if (!name || !ret || !h_errnop || !val_status || !result || !buf) {
        goto err;
    }

    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL)
        goto err; 

    if (VAL_NO_ERROR == val_is_local_trusted(ctx, &trusted)) {
        if (trusted) {
            local_ans_status = VAL_TRUSTED_ANSWER;
        }
    }

    /*
     * Check if the address-family is AF_INET and the address is an IPv4 address 
     */
    if ((af == AF_INET) && (INET_PTON(AF_INET, name, ((struct sockaddr *)&sa), &addrlen4) > 0)) {
        memset(ret, 0, sizeof(struct hostent));

        // Name
        ret->h_name = bufalloc(buf, buflen, &offset, strlen(name) + 1);
        if (ret->h_name == NULL) {
            goto err; 
        }
        memcpy(ret->h_name, name, strlen(name) + 1);

        // Alias
        ret->h_aliases =
            (char **) bufalloc(buf, buflen, &offset, sizeof(char *));
        if (ret->h_aliases == NULL) {
            goto err;  
        }
        ret->h_aliases[0] = 0;

        // Address
        ret->h_addrtype = AF_INET;
        ret->h_length = sizeof(struct in_addr);
        ret->h_addr_list =
            (char **) bufalloc(buf, buflen, &offset, 2 * sizeof(char *));
        if (ret->h_addr_list == NULL) {
            goto err;      
        }
        ret->h_addr_list[0] =
            (char *) bufalloc(buf, buflen, &offset,
                              sizeof(struct in_addr));
        if (ret->h_addr_list[0] == NULL) {
            goto err;      
        }
        memcpy(ret->h_addr_list[0], &sa.sin_addr, sizeof(struct in_addr));
        ret->h_addr_list[1] = 0;

        *val_status = VAL_TRUSTED_ANSWER;
        *h_errnop = NETDB_SUCCESS;
        *result = ret;
    }

#ifdef VAL_IPV6
    /*
     * Check if the address-family is AF_INET6 and the address is an IPv6 address 
     */
    else if ((af == AF_INET6)
             && (INET_PTON(AF_INET6, name, ((struct sockaddr *)&sa6), &addrlen6) > 0)) {
        memset(ret, 0, sizeof(struct hostent));

        // Name
        ret->h_name = bufalloc(buf, buflen, &offset, strlen(name) + 1);
        if (ret->h_name == NULL) {
            goto err;
        }
        memcpy(ret->h_name, name, strlen(name) + 1);

        // Alias
        ret->h_aliases =
            (char **) bufalloc(buf, buflen, &offset, sizeof(char *));
        if (ret->h_aliases == NULL) {
            goto err;     
        }
        ret->h_aliases[0] = 0;

        // Address
        ret->h_addrtype = AF_INET6;
        ret->h_length = sizeof(struct in6_addr);
        ret->h_addr_list =
            (char **) bufalloc(buf, buflen, &offset, 2 * sizeof(char *));
        if (ret->h_addr_list == NULL) {
            goto err;    
        }
        ret->h_addr_list[0] =
            (char *) bufalloc(buf, buflen, &offset,
                              sizeof(struct in6_addr));
        if (ret->h_addr_list[0] == NULL) {
            goto err;   
        }
        memcpy(ret->h_addr_list[0], &sa6.sin6_addr, sizeof(struct in6_addr));
        ret->h_addr_list[1] = 0;

        *val_status = VAL_TRUSTED_ANSWER;
        *h_errnop = NETDB_SUCCESS;
        *result = ret;

    } 
#endif
    else if (NULL != 
                (*result = get_hostent_from_etc_hosts(ctx, name, af, 
                                                      ret, buf, buflen, &offset))) {
        /*
         * First check the ETC_HOSTS file
         * XXX: TODO check the order in the ETC_HOST_CONF file
         */
        *val_status = local_ans_status;
        *h_errnop = NETDB_SUCCESS;

    } else {

#ifdef VAL_IPV6
        if (af == AF_INET6) 
            type = ns_t_aaaa;
        else 
#endif
            type = ns_t_a;

        /*
         * Query the validator 
         */
        if (VAL_NO_ERROR ==
                (retval =
                 val_resolve_and_check(ctx, name, ns_c_in, type,
                                       0,
                                       &results))) {

            /*
             * Convert the validator result into hostent 
             */
            *result =
                get_hostent_from_response(ctx, af, ret, results,
                                          h_errnop, buf, buflen, &offset, val_status);

        } else {
            val_log(ctx, LOG_ERR, 
                    "val_gethostbyname2_r(): val_resolve_and_check failed - %s", p_val_err(retval));
        }

        if (*result == NULL) {
            goto err;
        } else {
            val_free_result_chain(results);
            results = NULL;
            *h_errnop = NETDB_SUCCESS;
        }

    }
    val_log(ctx, LOG_DEBUG, "val_gethostbyname2_r returned success, herrno = %d, val_status = %s", 
                *h_errnop, val_status? p_val_status(*val_status) : NULL); 
    CTX_UNLOCK_POL(ctx);
    return 0;

err:
    if (result) {
        *result = NULL;
    }
    if (h_errnop) 
        *h_errnop = NO_RECOVERY;

    if (ctx) {
        val_log(ctx, LOG_DEBUG, "val_gethostbyname2_r returned failure, herrno = %d, val_status = %s", 
                *h_errnop, val_status? p_val_status(*val_status) : NULL); 
        CTX_UNLOCK_POL(ctx);
    }
    return (NO_RECOVERY);
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
struct hostent *
val_gethostbyname2(val_context_t * ctx,
                   const char *name, int af, val_status_t * val_status)
{
    struct hostent *result = NULL;
    int last_err = 0;
    val_gethostbyname2_r(ctx, name, af, &g_hentry, g_auxbuf,
                         AUX_BUFLEN, &result, &last_err, val_status);
    SET_LAST_ERR(last_err);
    return result;

}                               /* val_gethostbyname2() */

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
struct hostent *
val_gethostbyname(val_context_t * ctx,
                  const char *name, val_status_t * val_status)
{
    return val_gethostbyname2(ctx, name, AF_INET, val_status);
}                               /* val_gethostbyname() */

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
int
val_gethostbyname_r(val_context_t * ctx,
                    const char *name,
                    struct hostent *ret,
                    char *buf,
                    size_t buflen,
                    struct hostent **result,
                    int *h_errnop, val_status_t * val_status)
{
    return val_gethostbyname2_r(ctx, name, AF_INET, ret, buf, buflen,
                                result, h_errnop, val_status);
}                               /* val_gethostbyname_r() */

/*
 * A thread-safe, re-entrant version of val_gethostbyaddr 
 */
int
val_gethostbyaddr_r(val_context_t * context,
                    const char *addr,
                    int len,
                    int type,
                    struct hostent *ret,
                    char *buf,
                    int buflen,
                    struct hostent **result,
                    int *h_errnop, val_status_t * val_status)
{

    char            domain_string[NS_MAXDNAME];
    int             ret_status = 0, bufused = 0;
    struct val_answer_chain *val_res = NULL;
    struct val_answer_chain *res;
    int retval;
    val_context_t *ctx = NULL;
    
    /*
     * check misc parameters exist 
     */
    if (!addr || !ret || !buf || (buflen <= 0) ||
        !result || !h_errnop || !val_status) {
        if (h_errnop)
            *h_errnop = NO_RECOVERY;
        return (NO_RECOVERY);
    }

    /*
     * default the input parameters 
     */
    *result = NULL;
    ret->h_name = NULL;
    ret->h_aliases = NULL;
    ret->h_addr_list = NULL;
    *h_errnop = 0;
    *val_status = VAL_UNTRUSTED_ANSWER;

    /*
     * get the address values, only support IPv4 and IPv6 
     */
    if (AF_INET == type && len >= sizeof(struct in_addr)) {
        ret->h_addrtype = type;
        ret->h_length = sizeof(struct in_addr);
    } 
#ifdef VAL_IPV6
    else if (AF_INET6 == type && len >= sizeof(struct in6_addr)) {
        ret->h_addrtype = type;
        ret->h_length = sizeof(struct in6_addr);
    } 
#endif
    else {
        *h_errnop = NO_RECOVERY;
        return (NO_RECOVERY);
    }

    memset(domain_string, 0, sizeof(domain_string));

    if (0 !=
        (ret_status = address_to_reverse_domain(addr, type,
                                                domain_string, sizeof(domain_string)))
        ) {
        *h_errnop = ret_status;
        return ret_status;
    }

    /*
     * if there is memory, add the address to hostent's address list 
     */
    if ((buflen > bufused) && 
        ((buflen - bufused) >= (ret->h_length + (sizeof(char *) * 2)))) {
        ret->h_addr_list = (char **) (buf + bufused);
        bufused = bufused + (sizeof(char *) * 2);
        ret->h_addr_list[0] = buf + bufused;
        ret->h_addr_list[1] = NULL;
        bufused = bufused + ret->h_length;
        memcpy(ret->h_addr_list[0], addr, ret->h_length);
    } else {                    /* no memory, fail */
        *h_errnop = NO_RECOVERY;
        return (NO_RECOVERY);
    }

    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL) {
        *h_errnop = NO_RECOVERY;
        return (NO_RECOVERY);
    }

    if (VAL_NO_ERROR != (retval = val_get_rrset(ctx,   /* val_context_t *  */
                                                domain_string, /* domain name */ 
                                                ns_c_in,   /* const u_int16_t q_class */
                                                ns_t_ptr,  /* const u_int16_t type */
                                                0,
                                                &val_res))) { /* struct val_answer_chain **results */
        val_log(ctx, LOG_ERR, 
                "val_gethostbyaddr_r(): val_get_rrset failed - %s", p_val_err(retval));
        CTX_UNLOCK_POL(ctx);
        *h_errnop = NO_RECOVERY;
        return NO_RECOVERY;
    }

    CTX_UNLOCK_POL(ctx);

    if (!val_res) {
        *h_errnop = NO_RECOVERY;
        return NO_RECOVERY;
    }

    for (res = val_res; res; res=res->val_ans_next) {

        struct rr_rec  *rr = res->val_ans;
        if (rr) {
            struct rr_rec  *rr_it = NULL;
            int             count = 0;
            int aliases_sz = 0;
            /*
             * if the buffer has enough room add the first host address 
             */
            if (rr->rr_length < (buflen - bufused - 1)) {
                /*
                 * setup hostent 
                 */
                ret->h_name = buf + bufused;
                ns_name_ntop(rr->rr_data, ret->h_name,
                             (buflen - bufused));
                bufused = bufused + strlen(ret->h_name) + 1;

                rr_it = rr->rr_next;
                /*
                 * are there other hostnames? 
                 */
                if (rr_it) {
                    /*
                     * calculate the amount of memory we need for aliases. 
                     */
                    do {
                        count++;
                        aliases_sz = aliases_sz + rr_it->rr_length + 1;
                    } while (NULL != (rr_it = rr_it->rr_next));

                    /*
                     * check that we have the space in the buffer 
                     */
                    if (buflen >=
                        (bufused + (sizeof(char *) * (count + 1)) +
                        aliases_sz)) {
                        /*
                         * assign the string pointer array 
                         */
                        ret->h_aliases = (char **) (buf + bufused);
                        bufused = bufused + (sizeof(char *) * (count + 1));

                        /*
                         * assign the strings 
                         */
                        rr_it = rr->rr_next;
                        count = 0;
                        do {
                            ret->h_aliases[count] = buf + bufused;
                            ns_name_ntop(rr_it->rr_data,
                                         ret->h_aliases[count],
                                        (buflen - bufused));
                            bufused =
                                bufused + strlen(ret->h_aliases[count]) + 1;
                            count++;
                        } while (NULL != (rr_it = rr_it->rr_next));
                        /*
                         * mark end of array 
                         */
                        ret->h_aliases[count] = NULL;
                    }
                    /*
                     * else we didn't have enough memory for the aliases.  They
                     * will be ignored with only one hostname returned 
                     */
                }                   /* else there are no other hostnames/aliases */

            } else {                /* else there is not enough room for even one host name, fail */
                ret->h_name = NULL;
                *h_errnop = NO_RECOVERY;
                return NO_RECOVERY;
            }
            break;

        } else if  (val_does_not_exist(res->val_ans_status)) {
                    
            if ((res->val_ans_status == VAL_NONEXISTENT_TYPE) ||
                (res->val_ans_status == VAL_NONEXISTENT_TYPE_NOCHAIN)) {
                    *h_errnop = NO_DATA;
            } else if ((res->val_ans_status == VAL_NONEXISTENT_NAME) ||
                       (res->val_ans_status == VAL_NONEXISTENT_NAME_NOCHAIN)) {
                    *h_errnop = HOST_NOT_FOUND;
            }

            *result = ret;
            return *h_errnop;
        }
    }

    if (!res) { /* no rrset, but a succesful return from the query?, fail */
        ret->h_name = NULL;
        *h_errnop = NO_RECOVERY;
        return NO_RECOVERY;
    }

    /* set the value of merged trusted and validated status values */
    if (val_isvalidated(res->val_ans_status))
        *val_status = VAL_VALIDATED_ANSWER; 
    else if (val_istrusted(res->val_ans_status))
        *val_status = VAL_TRUSTED_ANSWER; 

    /*
     * no error, set result 
     */
    *result = ret;
    return *h_errnop;

}                               /* val_getthostbyaddr_r */


/*
 * A old version of gethostbyaddr for use with validator
 */
struct hostent *
val_gethostbyaddr(val_context_t * context,
                  const char *addr,
                  int len, int type, val_status_t * val_status)
{
    /*
     * static buffer size for hostent is set to 512 
     */
    const int       buflen = 512;
    static char     buffer[512];        /* compiler doesn't consider a const, constant */
    static struct hostent ret_hostent;

    struct hostent *result_hostent = NULL;
    int             errnum = 0;
    int             response;
    
    /*
     * set defaults for static values 
     */
    memset(buffer, 0, sizeof(char) * buflen);
    ret_hostent.h_name = NULL;
    ret_hostent.h_aliases = NULL;
    ret_hostent.h_addrtype = 0;
    ret_hostent.h_length = 0;
    ret_hostent.h_addr_list = NULL;

    response = val_gethostbyaddr_r(context,
                                   addr, len, type,
                                   &ret_hostent,
                                   buffer, buflen,
                                   &result_hostent,
                                   &errnum,
                                   val_status);

    if (response != 0) {
        SET_LAST_ERR(response);
        return NULL;
    }
    /*
     * should have succeeded, if memory doesn't match, fail. 
     */
    else if (&ret_hostent != result_hostent) {
        SET_LAST_ERR(NO_RECOVERY);
        return NULL;
    }

    /*
     * success 
     */
    SET_LAST_ERR(NETDB_SUCCESS);
    return &ret_hostent;
}                               /* val_gethostbyaddr */
