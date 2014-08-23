/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the implementation file for a validating getaddrinfo function.
 * Applications should be able to use this in place of getaddrinfo with
 * minimal change.
 */
/*
 * DESCRIPTION
 * Contains implementation of val_getaddrinfo() and friends
 */
#include "validator-internal.h"

#include "val_policy.h"
#include "val_parse.h"
#include "val_context.h"

#ifndef  INADDR_LOOPBACK
# define INADDR_LOOPBACK    0x7f000001
#endif

/* 
 * Free the addrinfo structure that we have allocated 
 */
void
val_freeaddrinfo(struct addrinfo *ainfo)
{
    struct addrinfo *acurr = ainfo;

    while (acurr != NULL) {
        struct addrinfo *anext = acurr->ai_next;
        if (acurr->ai_addr) {
            free(acurr->ai_addr);
        }
        if (acurr->ai_canonname) {
            free(acurr->ai_canonname);
        }
        free(acurr);
        acurr = anext;
    }
}

/*
 * Function: append_addrinfo
 *
 * Purpose: A utility function to link one addrinfo linked list to another.
 *          The scope of this function is limited to this file.
 *
 * Parameters:
 *             a1 -- A pointer to the first addrinfo linked list
 *             a2 -- A pointer to the second addrinfo linked list
 *
 * Returns:
 *             a2 appended to a1.
 */
static struct addrinfo *
append_addrinfo(struct addrinfo *a1, struct addrinfo *a2)
{
    struct addrinfo *a;
    if (a1 == NULL)
        return a2;
    if (a2 == NULL)
        return a1;

    a = a1;
    while (a->ai_next != NULL) {
        a = a->ai_next;
    }

    a->ai_next = a2;
    return a1;
}

/*
 * Function: dup_addrinfo
 *
 * Purpose: Duplicates just the current addrinfo struct and its contents;
 *          does not duplicate the entire addrinfo linked list.
 *          Sets the ai_next pointer of the new addrinfo structure to NULL.
 *          The scope of this function is limited to this file.
 *
 * Parameters:
 *             a -- A pointer to a struct addrinfo variable which is to be
 *                  duplicated.
 *
 * Returns: A pointer to the duplicated struct addrinfo value.
 */
static struct addrinfo *
dup_addrinfo(const struct addrinfo *a)
{
    struct addrinfo *new_a = NULL;

    if (a == NULL)
        return NULL;

    new_a = (struct addrinfo *) malloc(sizeof(struct addrinfo));
    if (new_a == NULL)
        return NULL;

    memset(new_a, 0, sizeof(struct addrinfo));

    new_a->ai_flags = a->ai_flags;
    new_a->ai_family = a->ai_family;
    new_a->ai_socktype = a->ai_socktype;
    new_a->ai_protocol = a->ai_protocol;
    new_a->ai_addrlen = a->ai_addrlen;
    new_a->ai_addr = (struct sockaddr *) malloc(a->ai_addrlen);
    if (new_a->ai_addr == NULL) {
        free(new_a);
        return NULL;
    }

    memcpy(new_a->ai_addr, a->ai_addr, a->ai_addrlen);

    if (a->ai_canonname != NULL) {
        new_a->ai_canonname = strdup(a->ai_canonname);
        if (new_a->ai_canonname == NULL) {
            free(new_a->ai_addr);
            free(new_a);
            return NULL;
        }
    } else {
        new_a->ai_canonname = NULL;
    }
    new_a->ai_next = NULL;
    return new_a;
}


/*
 * Function: val_setport
 *
 * Purpose: Set the port number in an sockaddr... structure (IPv4 or
 *          IPv6 address) given a string value of a port number or
 *          service name.
 *
 * Parameters:
 *          saddr -- A pointer to the address
 *          serv  -- a char point to a port number or service name.
 *          proto -- the protocol to look up the port information 
 *                   with. (usually "udp" or "tcp")
 *
 * Returns:
 *          This function has no return value.
 *
 * See also: process_service_and_hints
 */
void
val_setport(struct sockaddr *saddr, const char *serv, const char *proto)
{
    struct servent *sent = NULL;
    int             portnum = 0;

    /*
     * figure out the port number 
     */
    if (NULL == serv) {
        portnum = 0;
    } else if (strtol(serv, (char **)NULL, 10)) {
        u_int16_t tmp = htons(strtol(serv, (char **)NULL, 10));
        sent = getservbyport(tmp, proto);
        if (sent)
            portnum = sent->s_port;
        else
            portnum = tmp;
    } else if (NULL != (sent = getservbyname(serv, proto))) {
        portnum = sent->s_port;
    }

    /*
     * set port number depending on address family
     */
    /*
     * note: s_port above is already in network byte order 
     */
    if (PF_INET == saddr->sa_family) {
        ((struct sockaddr_in *) saddr)->sin_port = portnum;
    } 
#ifdef VAL_IPV6
    else if (PF_INET6 == saddr->sa_family) {
        ((struct sockaddr_in6 *) saddr)->sin6_port = portnum;
    }
#endif
}                               /* val_setport */


/*
 * Function: process_service_and_hints
 *
 * Purpose: Add additional addrinfo structures to the list depending on
 *          the service name and hints.
 *          The scope of this function is limited to this file.
 *
 * Parameters:
 *            servname -- Name of the service.  Can be NULL.
 *               hints -- Hints to influence the result.  Can be NULL.
 *                 res -- Points to a linked list of addrinfo structures.
 *                        On return, this linked list may be augmented by
 *                        additional _addrinfo structures depending on
 *                        the service name and hints.
 *
 * Returns: 0 if successful, a non-zero value if failure.
 */
static int
process_service_and_hints(const char *servname,
                          const struct addrinfo *hints,
                          struct addrinfo **res)
{
    struct addrinfo *a1 = NULL;
    struct addrinfo *a2 = NULL;
    int             proto_found = 0;
    int             created_locally = 0;

    if (res == NULL)
        return EAI_SERVICE;

    if (*res == NULL) {
        created_locally = 1;
        a1 = (struct addrinfo *) malloc(sizeof(struct addrinfo));
        if (a1 == NULL)
            return EAI_MEMORY;
        memset(a1, 0, sizeof(struct addrinfo));

        *res = a1;
    } else {
        a1 = *res;
    }

    if (!a1)
        return 0;

    /*
     * check for sockaddr... memory allocation 
     */
    if (NULL == a1->ai_addr) {
        a1->ai_addr = (struct sockaddr *)
            malloc(sizeof(struct sockaddr_storage));
        memset(a1->ai_addr, 0, sizeof(struct sockaddr_storage));
    }
    if (NULL == a1->ai_addr) {
        free(a1);
        return EAI_MEMORY;
    }

    /*
     * Flags 
     */
    if ((hints != NULL) && (hints->ai_flags != 0)) {
        a1->ai_flags = hints->ai_flags;
    } else {
#if defined(AI_V4MAPPED) && defined(AI_ADDRCONFIG)
        a1->ai_flags = (AI_V4MAPPED | AI_ADDRCONFIG);
#else
        a1->ai_flags = 0;       /* ?? something else? */
#endif
    }

    /*
     * Check if we have to return addrinfo structures for the
     SOCK_STREAM socktype
     */
    if (hints == NULL || hints->ai_socktype == 0
        || hints->ai_socktype == SOCK_STREAM) {

        a1->ai_socktype = SOCK_STREAM;
        a1->ai_protocol = IPPROTO_TCP;
        val_setport(a1->ai_addr, servname, "tcp");
        a1->ai_next = NULL;
        proto_found = 1;
    }

    /*
     * Check if we have to return addrinfo structures for the
     SOCK_DGRAM socktype
     */
    if ((hints == NULL || hints->ai_socktype == 0
         || hints->ai_socktype == SOCK_DGRAM)) {

        if (proto_found) {
            a2 = dup_addrinfo(a1);
            if (a2 == NULL)
                return EAI_MEMORY;
            a1->ai_next = a2;
            a1 = a2;
        }
        a1->ai_socktype = SOCK_DGRAM;
        a1->ai_protocol = IPPROTO_UDP;
        val_setport(a1->ai_addr, servname, "udp");
        proto_found = 1;
    }

    /*
     * Check if we have to return addrinfo structures for the
     SOCK_RAW socktype
     */
    if ((hints == NULL || hints->ai_socktype == 0
         || hints->ai_socktype == SOCK_RAW)) {

        if (proto_found) {
            a2 = dup_addrinfo(a1);
            // xxx-note: uggh. may have augmented caller's res ptr
            //     above, so I hate returning an error. But then
            //     returning 0 in the face of an error doesn't
            //     seem right either.
            if (a2 == NULL)
                return EAI_MEMORY;
            a1->ai_next = a2;
            a1 = a2;
        }
        a1->ai_socktype = SOCK_RAW;
        a1->ai_protocol = IPPROTO_IP;
        val_setport(a1->ai_addr, servname, "ip");
        proto_found = 1;
    }

    if (proto_found) {
        return 0;
    } else {
        /*
         * no valid protocol found 
         */
        // xxx-audit: function documentation doesn't mention anything
        //     about possibly nuking the caller's ptr and freeing their
        //     memory. Maybe there needs to be a better separation
        //     between memory allocated here and caller's memory.
        /*
         * if top memory allocated locally, delete 
         */
        if (created_locally) {
            *res = NULL;
            val_freeaddrinfo(a1);
        }
        return EAI_SERVICE;
    }
}                               /* end process_service_and_hints */


/*
 * Function: get_addrinfo_from_etc_hosts
 *
 * Purpose: Read the ETC_HOSTS file and check if it contains the given name.
 *          The scope of this function is limited to this file.
 *
 * Parameters:
 *              ctx -- The validation context.  Must not be NULL.
 *         nodename -- Name of the node.  Must not be NULL.
 *         servname -- Name of the service.  Can be NULL.
 *            hints -- Hints that influence the results.  Can be NULL.
 *              res -- Pointer to a variable of type addrinfo *.  On
 *                     successful return, this will contain a linked list
 *                     of addrinfo structures.
 *
 * Returns: 0 if successful, and a non-zero value on error.
 *
 * See also: get_addrinfo_from_dns(), val_getaddrinfo()
 */
static int
get_addrinfo_from_etc_hosts(val_context_t * ctx,
                            const char *nodename,
                            const char *servname,
                            const struct addrinfo *hints,
                            struct addrinfo **res)
{
    struct hosts   *hs = NULL;
    struct addrinfo *retval = NULL;
    int ret = EAI_NONAME;
    struct hosts   *h_prev = NULL;
    struct addrinfo *ainfo = NULL;

    if (res == NULL) 
        return 0;

    val_log(ctx, LOG_DEBUG, "get_addrinfo_from_etc_hosts(): Parsing "
            ETC_HOSTS);

    /*
     * Parse the /etc/hosts/ file 
     */
    hs = parse_etc_hosts(nodename);

    while (hs) {
        int             alias_index = 0;
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
        h_prev = hs;

        ainfo =
            (struct addrinfo *) malloc(sizeof(struct addrinfo));
        if (!ainfo) {
            ret = EAI_MEMORY;
            goto err;
        }

        //val_log(ctx, LOG_DEBUG, "{");
        //val_log(ctx, LOG_DEBUG, "  Address: %s", hs->address);
        //val_log(ctx, LOG_DEBUG, "  Canonical Hostname: %s",
        //        hs->canonical_hostname);
        //val_log(ctx, LOG_DEBUG, "  Aliases:");

        while (hs->aliases[alias_index] != NULL) {
            //val_log(ctx, LOG_DEBUG, "   %s", hs->aliases[alias_index]);
            alias_index++;
        }

        //val_log(ctx, LOG_DEBUG, "}");

        memset(ainfo, 0, sizeof(struct addrinfo));
        memset(&sa, 0, sizeof(sa));
#ifdef VAL_IPV6
        memset(&sa6, 0, sizeof(sa6));
#endif

        /*
         * Check if the address is an IPv4 address 
         */
        if (INET_PTON(AF_INET, hs->address, ((struct sockaddr *)&sa), &addrlen4) > 0) {
            struct sockaddr_in *saddr4 =
                (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
            if (saddr4 == NULL) {
                ret = EAI_MEMORY;
                goto err;
            }
            memset(saddr4, 0, sizeof(struct sockaddr_in));
            ainfo->ai_family = AF_INET;
            saddr4->sin_family = AF_INET;
            ainfo->ai_addrlen = sizeof(struct sockaddr_in);
            memcpy(&(saddr4->sin_addr), &sa.sin_addr, sizeof(struct in_addr));
            ainfo->ai_addr = (struct sockaddr *) saddr4;
            ainfo->ai_canonname = NULL;
        }
#ifdef VAL_IPV6
        /*
         * Check if the address is an IPv6 address 
         */
        else if (INET_PTON(AF_INET6, hs->address, ((struct sockaddr *)&sa6), &addrlen6) > 0) {
            struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)
                malloc(sizeof(struct sockaddr_in6));
            if (saddr6 == NULL) {
                ret = EAI_MEMORY;
                goto err;
            }
            memset(saddr6, 0, sizeof(struct sockaddr_in6));
            ainfo->ai_family = AF_INET6;
            saddr6->sin6_family = AF_INET6;
            ainfo->ai_addrlen = sizeof(struct sockaddr_in6);
            memcpy(&(saddr6->sin6_addr), &sa6.sin6_addr,
                   sizeof(struct in6_addr));
            ainfo->ai_addr = (struct sockaddr *) saddr6;
            ainfo->ai_canonname = NULL;
        } 
#endif
        else {
            val_log(ctx, LOG_WARNING, 
                    "get_addrinfo_from_etc_hosts(): Unkown address type");
            val_freeaddrinfo(ainfo);
            continue;
        }

        /*
         * Expand the results based on servname and hints 
         */
        if ((ret = process_service_and_hints(servname, hints, &ainfo)) != 0) {
            val_log(ctx, LOG_INFO, 
                    "get_addrinfo_from_etc_hosts(): Failed in process_service_and_hints()");
            goto err;
        }

        if (retval) {
            retval = append_addrinfo(retval, ainfo);
        } else {
            retval = ainfo;
        }

        hs = hs->next;
        FREE_HOSTS(h_prev);
    }

    val_log(ctx, LOG_DEBUG, "get_addrinfo_from_etc_hosts(): Parsing "
            ETC_HOSTS " OK");

    *res = retval;
    if (retval) {
        return 0;
    } else {
        return EAI_NONAME;
    }

err:
    if (ainfo) {
        val_freeaddrinfo(ainfo);
    }
    if (retval) {
        val_freeaddrinfo(retval);
    }

    while (hs) {
        h_prev = hs;
        hs = hs->next;
        FREE_HOSTS(h_prev);
    }
    return ret;
}                               /* get_addrinfo_from_etc_hosts() */


/*
 * Function: get_addrinfo_from_result
 *
 * Purpose: Converts the result value from the validator (which is
 *          in the form of a linked list of val_answer_chain structures)
 *          into a liked list of addrinfo structures.
 *          The scope of this function is limited to this file.
 *
 * Parameters:
 *              ctx -- The validation context.
 *          results -- The results obtained from the get_rr_set 
 *                     method in the validator API.
 *         servname -- The service name.  Can be NULL.
 *            hints -- Hints that influence the returned results.  Can be NULL.
 *              res -- A pointer to a variable of type struct addrinfo *.
 *                     On successful return, this will contain a linked list
 *                     of addrinfo structures.
 *
 * Returns: 0 on success, and a non-zero error-code on error.
 *
 * See also: get_addrinfo_from_etc_hosts(), val_getaddrinfo()
 */
static int
get_addrinfo_from_result(const val_context_t * ctx,
                         struct val_answer_chain *results,
                         const char *servname,
                         const struct addrinfo *hints,
                         struct addrinfo **res,
                         val_status_t *val_status)
{
    struct addrinfo *ainfo_head = NULL;
    struct addrinfo *ainfo_tail = NULL;
    struct val_answer_chain *result = NULL;
    char           *canonname = NULL;
    int validated;
    int trusted;
    int retval = EAI_FAIL;

    if (res == NULL)
        return EAI_FAIL;

    /* 
     * we may be calling get_addrinfo_from_result() repeatedly
     * set the starting values for validated, trusted and the answer list
     */
    validated = val_isvalidated(*val_status)? 1 : 0;
    trusted = val_istrusted(*val_status)? 1 : 0;

    ainfo_head = *res;
    ainfo_tail = ainfo_head;
    if (ainfo_tail) {
        while (ainfo_tail->ai_next)
            ainfo_tail = ainfo_tail->ai_next;
    }

    /*
     * Loop for each result in the linked list of val_answer_chain structures 
     */
    for (result = results; result != NULL; result = result->val_ans_next) {

        /* set the value of merged trusted and validated status values */
        if (!(validated && val_isvalidated(result->val_ans_status)))
            validated = 0;
        if (!(trusted && val_istrusted(result->val_ans_status)))
            trusted = 0;

        if (result->val_ans != NULL) {
            struct rr_rec *rr = result->val_ans;

            canonname = result->val_ans_name;

            /*
             * Loop for each rr in the linked list 
             */
            while (rr != NULL) {
                struct addrinfo *ainfo = NULL;

                ainfo = (struct addrinfo *)
                    malloc(sizeof(struct addrinfo));
                if (ainfo == NULL) {
                    return EAI_MEMORY;
                }
                memset(ainfo, 0, sizeof(struct addrinfo));

                /*
                 * Check if the record-type is A 
                 */
                if (result->val_ans_type == ns_t_a) {
                    struct sockaddr_in *saddr4 = (struct sockaddr_in *)
                        malloc(sizeof(struct sockaddr_in));
                    if (saddr4 == NULL) {
                        val_freeaddrinfo(ainfo);
                        return EAI_MEMORY;
                    }
                    val_log(ctx, LOG_DEBUG, "get_addrinfo_from_result(): rrset of type A found");
                    memset(saddr4, 0, sizeof(struct sockaddr_in));
                    saddr4->sin_family = AF_INET;
                    ainfo->ai_family = AF_INET;
                    ainfo->ai_addrlen = sizeof(struct sockaddr_in);
                    memcpy(&(saddr4->sin_addr.s_addr), rr->rr_data,
                           rr->rr_length);
                    ainfo->ai_addr = (struct sockaddr *) saddr4;
                }
                /*
                 * Check if the record-type is AAAA 
                 */
#ifdef VAL_IPV6
                else if (result->val_ans_type == ns_t_aaaa) {
                    struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)
                        malloc(sizeof(struct sockaddr_in6));
                    if (saddr6 == NULL) {
                        val_freeaddrinfo(ainfo);
                        return EAI_MEMORY;
                    }
                    val_log(ctx, LOG_DEBUG, "get_addrinfo_from_result(): rrset of type AAAA found");
                    memset(saddr6, 0, sizeof(struct sockaddr_in6));
                    saddr6->sin6_family = AF_INET6;
                    ainfo->ai_family = AF_INET6;
                    ainfo->ai_addrlen = sizeof(struct sockaddr_in6);
                    memcpy(&(saddr6->sin6_addr.s6_addr), rr->rr_data,
                           rr->rr_length);
                    ainfo->ai_addr = (struct sockaddr *) saddr6;
                } 
#endif
                else {
                    val_freeaddrinfo(ainfo);
                    rr = rr->rr_next;
                    continue;
                }

                /*
                 * Check if the AI_CANONNAME flag is specified 
                 */
                if (hints && (hints->ai_flags & AI_CANONNAME) && canonname) {
                    ainfo->ai_canonname = strdup(canonname);
                }

                /*
                 * Expand the results based on servname and hints 
                 */
                if ((retval = process_service_and_hints(servname, hints, &ainfo))
                    != 0) {
                    val_freeaddrinfo(ainfo);
                    val_log(ctx, LOG_INFO, 
                        "get_addrinfo_from_result(): Failed in process_service_and_hints()");
                    return retval;
                }

                if (ainfo_head == NULL) {
                    ainfo_head = ainfo;
                    *res = ainfo_head;
                } else {
                    ainfo_tail->ai_next = ainfo;
                }

                if (ainfo)
                    ainfo_tail = ainfo;

                rr = rr->rr_next;
            }
        } else if (val_does_not_exist(result->val_ans_status)) {
            retval = EAI_NONAME;
            break;
        } else {
            retval = EAI_FAIL;
        }
    }

    if (!ainfo_head) {
        if (result) {
            /* if result is not NULL, this corresponds to a p.n.e */
            *val_status = result->val_ans_status;
        } else {
            *val_status = VAL_UNTRUSTED_ANSWER;
        }
    } else {
        if (validated)
            *val_status = VAL_VALIDATED_ANSWER;
        else if (trusted)
            *val_status = VAL_TRUSTED_ANSWER;
        else
            *val_status = VAL_UNTRUSTED_ANSWER;
        // return success if we have at least one answer
        retval = 0;
    }

    return retval;
}                               /* get_addrinfo_from_result() */

/*
 * Function: get_addrinfo_from_dns
 *
 * Purpose: Resolve the nodename from DNS and fill in the addrinfo
 *          return value.  The scope of this function is limited to this
 *          file, and is called from val_getaddrinfo().
 *
 * Parameters:
 *              ctx -- The validation context.
 *         nodename -- The name of the node.  This value must not be NULL.
 *         servname -- The service name.  Can be NULL.
 *            hints -- Hints to influence the return value.  Can be NULL.
 *              res -- A pointer to a variable of type (struct addrinfo *) to
 *                     hold the result.  The caller must free this return value
 *                     using val_freeaddrinfo().
 *
 * Returns: 0 on success and a non-zero value on error.
 *
 * See also: val_getaddrinfo()
 */

static int
get_addrinfo_from_dns(val_context_t * ctx,
                      const char *nodename,
                      const char *servname,
                      const struct addrinfo *hints_param,
                      struct addrinfo **res,
                      val_status_t *val_status)
{
    struct val_answer_chain *results = NULL;
    struct addrinfo *ainfo = NULL;
    const struct addrinfo *hints;
    struct addrinfo default_hints;
    int    ret = EAI_FAIL, have4 = 1, have6 = 1;

    val_log(ctx, LOG_DEBUG, "get_addrinfo_from_dns() called");

    *val_status = VAL_VALIDATED_ANSWER;

    if (NULL == nodename && NULL == servname) {
        return EAI_NONAME;
    }

    /*
     * use a default hints structure if one is not available.
     */
    if (hints_param == NULL) {
        memset(&default_hints, 0, sizeof(default_hints));
        hints = &default_hints;
    } else {
        hints = hints_param;
    }

    if (res == NULL ||
        (hints->ai_family != AF_UNSPEC &&
         hints->ai_family != AF_INET &&
         hints->ai_family != AF_INET6)) {

        *val_status = VAL_UNTRUSTED_ANSWER;
        return EAI_NONAME; 
    }

#ifdef AI_ADDRCONFIG
    if (hints->ai_flags & AI_ADDRCONFIG) {
        have4 = val_context_ip4(ctx);
        have6 = val_context_ip6(ctx);
    }
#endif
    
    /*
     * Check if we need to return IPv4 addresses based on the hints 
     */
    if ((hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET) 
#ifdef AI_ADDRCONFIG
        && (have4 != 0)
#endif
        ) {
        val_log(ctx, LOG_DEBUG,
                "get_addrinfo_from_dns(): checking for A records");

        if ((VAL_NO_ERROR == 
                    val_get_rrset(ctx, nodename, ns_c_in, ns_t_a, 0, &results)) 
                && results) {
            
            ret = get_addrinfo_from_result(ctx, results, servname,
                                         hints, &ainfo, val_status);

            val_log(ctx, LOG_DEBUG, "get_addrinfo_from_dns(): "
                    "get_addrinfo_from_result() returned=%d with val_status=%d",
                    ret, *val_status);

            val_free_answer_chain(results);
            results = NULL;
        } 
    } 

#ifdef VAL_IPV6
    /*
     * Check if we need to return IPv6 addresses based on the hints 
     */
    if ((hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET6)
#ifdef AI_ADDRCONFIG
        && (have6 != 0)
#endif
        ) {

        val_log(ctx, LOG_DEBUG,
                "get_addrinfo_from_dns(): checking for AAAA records");
        
        if ((VAL_NO_ERROR == 
             val_get_rrset(ctx, nodename, ns_c_in, ns_t_aaaa, 0, &results)) 
            && results) {
            ret = get_addrinfo_from_result(ctx, results, servname,
                                         hints, &ainfo, val_status);

            val_log(ctx, LOG_DEBUG, "get_addrinfo_from_dns(): "
                    "get_addrinfo_from_result() returned=%d with val_status=%d",
                    ret, *val_status);

            val_free_answer_chain(results);
            results = NULL;
        } 
    } 
#endif

    *res = ainfo;
    
    return ret; 

}                               /* get_addrinfo_from_dns() */

/**
 * _getaddrinfo_local: helper function for val_getaddrinfo and
 *    val_getaddrinfo async. Checks local resources.
 *
 * Return value: This function returns 0 if it succeeds, or one of the
 *               non-zero error codes if it fails.  The error code
 *               EAI_AGAIN indicates that the caller should try DNS next.
 */
static int
_getaddrinfo_local(val_context_t * ctx, const char *nodename,
                   const char *servname, const struct addrinfo *hints,
                   struct addrinfo **res, val_status_t *val_status)
{
    struct sockaddr_in  sa;
    struct addrinfo *ainfo4 = NULL;
#if defined( WIN32 )
    size_t addrlen4 = sizeof(struct sockaddr_in);
#endif
#ifdef VAL_IPV6
    struct sockaddr_in6 sa6;
    struct addrinfo *ainfo6 = NULL;
#if defined( WIN32 )
    size_t addrlen6 = sizeof(struct sockaddr_in6);
#endif
#endif
    int             retval = 0;
    const char     *localhost4 = "127.0.0.1";
    const char     *localhost6 = "::1";
    const char     *nname = nodename;
    const struct addrinfo *cur_hints;
    struct addrinfo default_hints;
    val_status_t local_ans_status = VAL_OOB_ANSWER;
    int trusted = 0;
    
    val_log(ctx, LOG_DEBUG,
            "val_getaddrinfo called with nodename = %s, servname = %s",
            nodename == NULL ? "(null)" : nodename,
            servname == NULL ? "(null)" : servname);


    if (VAL_NO_ERROR == val_is_local_trusted(ctx, &trusted)) {
        if (trusted) {
            local_ans_status = VAL_TRUSTED_ANSWER;
        }
    }
    if (res == NULL || val_status == NULL) {
        retval = 0;
        goto done;
    }

    *res = NULL;
    *val_status = VAL_UNTRUSTED_ANSWER;

    /*
     * use a default hints structure if one is not available.
     */
    if (hints == NULL) {
        memset(&default_hints, 0, sizeof(default_hints));
        cur_hints = &default_hints;
    } else {
        cur_hints = hints;
    }

    /*
     * Check that at least one of nodename or servname is non-NULL
     */
    if (NULL == nodename && NULL == servname) {
        retval = EAI_NONAME;
        goto done;
    }

    /*
     * if nodename is blank and hints includes ipv4 or unspecified,
     * use IPv4 localhost 
     */
    if (NULL == nodename &&
        (AF_INET == cur_hints->ai_family ||
         AF_UNSPEC == cur_hints->ai_family)
        ) {
        nname = localhost4;
    }

    memset(&sa, 0, sizeof(sa));
#ifdef VAL_IPV6
    memset(&sa6, 0, sizeof(sa6));
#endif

    /*
     * check for IPv4 addresses 
     */
    if (NULL != nname && INET_PTON(AF_INET, nname, ((struct sockaddr *)&sa), &addrlen4) > 0) {

        struct sockaddr_in *saddr4 =
            (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
        if (saddr4 == NULL) {
            retval = EAI_MEMORY;
            goto done;
        }
        ainfo4 =
            (struct addrinfo *) malloc(sizeof(struct addrinfo));
        if (ainfo4 == NULL) {
            free(saddr4);
            retval = EAI_MEMORY;
            goto done;
        }

        memset(ainfo4, 0, sizeof(struct addrinfo));
        memset(saddr4, 0, sizeof(struct sockaddr_in));

        saddr4->sin_family = AF_INET;
        ainfo4->ai_family = AF_INET;
        memcpy(&(saddr4->sin_addr), &sa.sin_addr, sizeof(struct in_addr));
        ainfo4->ai_addr = (struct sockaddr *) saddr4;
        saddr4 = NULL;
        ainfo4->ai_addrlen = sizeof(struct sockaddr_in);
        ainfo4->ai_canonname = NULL;

        if ((retval = process_service_and_hints(servname, cur_hints, &ainfo4))
            != 0) {
            val_freeaddrinfo(ainfo4);
            val_log(ctx, LOG_INFO, 
                    "val_getaddrinfo(): Failed in process_service_and_hints()");
            goto done;
        }

        *res = ainfo4;
        retval = 0;
    }

    /*
     * if nodename is blank and hints includes ipv6 or unspecified,
     * use IPv6 localhost 
     */
    if (NULL == nodename &&
        (AF_INET6 == cur_hints->ai_family ||
         AF_UNSPEC == cur_hints->ai_family)
        ) {
        nname = localhost6;
    }

#ifdef VAL_IPV6
    /*
     * Check for IPv6 address 
     */
    if (nname != NULL && INET_PTON(AF_INET6, nname, ((struct sockaddr *)&sa6), &addrlen6) > 0) {

        struct sockaddr_in6 *saddr6 =
            (struct sockaddr_in6 *) malloc(sizeof(struct sockaddr_in6));
        if (saddr6 == NULL) {
            retval = EAI_MEMORY;
            goto done;
        }
        ainfo6 =
            (struct addrinfo *) malloc(sizeof(struct addrinfo));
        if (ainfo6 == NULL) {
            free(saddr6);
            retval = EAI_MEMORY;
            goto done;
        }

        memset(ainfo6, 0, sizeof(struct addrinfo));
        memset(saddr6, 0, sizeof(struct sockaddr_in6));

        saddr6->sin6_family = AF_INET6;
        ainfo6->ai_family = AF_INET6;
        memcpy(&(saddr6->sin6_addr), &sa6.sin6_addr, sizeof(struct in6_addr));
        ainfo6->ai_addr = (struct sockaddr *) saddr6;
        saddr6 = NULL;
        ainfo6->ai_addrlen = sizeof(struct sockaddr_in6);
        ainfo6->ai_canonname = NULL;

        if ((retval = process_service_and_hints(servname, cur_hints, &ainfo6))
            != 0) {
            val_freeaddrinfo(ainfo6);
            val_log(ctx, LOG_INFO, 
                    "val_getaddrinfo(): Failed in process_service_and_hints()");
            goto done;
        }

        if (NULL != *res) {
            *res = append_addrinfo(*res, ainfo6);
        } else {
            *res = ainfo6;
        }
        retval = 0;
    }
#endif

    if (*res) {
        *val_status = VAL_TRUSTED_ANSWER;
        goto done;
    } 
    if (nodename) {

        /*
         * If nodename was specified and was not an IPv4 or IPv6
         * address, get its information from local store or from dns
         * or return error if AI_NUMERICHOST specified
         */
        if (cur_hints->ai_flags & AI_NUMERICHOST) {
            retval = EAI_NONAME;
            goto done;
        }
        /*
         * First check ETC_HOSTS file
         * * XXX: TODO check the order in the ETC_HOST_CONF file
         */
        if (get_addrinfo_from_etc_hosts(ctx, nodename, servname,
                                        cur_hints, res) == EAI_SERVICE) {
            retval = EAI_SERVICE;
        } else if (*res != NULL) {
            retval = 0;
            *val_status = local_ans_status;
        }

        /*
         * Try DNS
         */
        else {
            /*
             * should never get EAI_AGAIN for local resources, so use it
             * to singal the user to try DNS.
             */
            retval = EAI_AGAIN;
        }
    }

done:
    return retval;
}                               /* _getaddrinfo_local */

/**
 * val_getaddrinfo: A validating getaddrinfo function.
 *                  Based on getaddrinfo() as defined in RFC3493.
 *
 * Parameters:
 *     Note: All the parameters, except the val_status parameter,
 *     ----  are similar to the getaddrinfo function.
 *
 *     [IN]  ctx: The validation context. Can be NULL for default value.
 *     [IN]  nodename: Specifies either a numerical network address (dotted-
 *                decimal format for IPv4, hexadecimal format for IPv6)
 *                or a network hostname, whose network addresses are
 *                looked up and resolved.
 *                node or service parameter, but not both, may be NULL.
 *     [IN]  servname: Used to set the port number in the network address
 *                of each socket structure returned.  If service is NULL
 *                the  port  number will be left uninitialized.
 *     [IN]  hints: Specifies  the  preferred socket type, or protocol.
 *                A NULL hints specifies that any network address or
 *                protocol is acceptable.
 *     [OUT] res: Points to a dynamically-allocated link list of addrinfo
 *                structures. The caller must free this return value
 *                using val_freeaddrinfo().
 *
 *     Note that at least one of nodename or servname must be a non-NULL value.
 *
 * Return value: This function returns 0 if it succeeds, or one of the
 *               non-zero error codes if it fails.  See man getaddrinfo(3)
 *               for more details.
 */
int
val_getaddrinfo(val_context_t * context,
                const char *nodename, const char *servname,
                const struct addrinfo *hints, struct addrinfo **res,
                val_status_t *val_status)
{
    val_context_t *ctx = NULL;
    int            retval;

    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL) 
        return EAI_FAIL;

    /** try local sources first */
    retval = _getaddrinfo_local(context, nodename, servname, hints, res,
                                val_status);

    if (EAI_AGAIN == retval) { /* EAI_AGAIN from local means try DNS */

        retval = get_addrinfo_from_dns(ctx, nodename, servname,
                                       hints, res, val_status);
    }

    CTX_UNLOCK_POL(ctx);
    return retval;
}                               /* val_getaddrinfo() */


/*
 * address_to_reverse_domain converts a sockaddr address for IPv4 or
 * IPv6 to a reverse domain adress string 'dadd'.
 * 
 * For reverse IPv6, the domain address string is a minimum of 74
 * octets in length.
 * 
 * For reverse IPv4, the domain address string is a minimum of 30
 * octets in length.
 * 
 * returns 0 on success, 1 on failure. 
 */
int
address_to_reverse_domain(const u_char *saddr, int family,
                          char *dadd, int dlen)
{

    if (AF_INET == family) {
        if (dlen < 30)
            return (EAI_FAIL);
        snprintf(dadd, dlen, "%d.%d.%d.%d.in-addr.arpa.",
                 *(saddr + 3), *(saddr + 2), *(saddr + 1), *(saddr));
    } else if (AF_INET6 == family) {
        if (dlen < 74)
            return (EAI_FAIL);
        snprintf(dadd, dlen,
                 "%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.ip6.arpa.",
                 (*(saddr + 15) & 0x0F), (*(saddr + 15) >> 4),
                 (*(saddr + 14) & 0x0F), (*(saddr + 14) >> 4),
                 (*(saddr + 13) & 0x0F), (*(saddr + 13) >> 4),
                 (*(saddr + 12) & 0x0F), (*(saddr + 12) >> 4),
                 (*(saddr + 11) & 0x0F), (*(saddr + 11) >> 4),
                 (*(saddr + 10) & 0x0F), (*(saddr + 10) >> 4),
                 (*(saddr + 9) & 0x0F), (*(saddr + 9) >> 4),
                 (*(saddr + 8) & 0x0F), (*(saddr + 8) >> 4),
                 (*(saddr + 7) & 0x0F), (*(saddr + 7) >> 4),
                 (*(saddr + 6) & 0x0F), (*(saddr + 6) >> 4),
                 (*(saddr + 5) & 0x0F), (*(saddr + 5) >> 4),
                 (*(saddr + 4) & 0x0F), (*(saddr + 4) >> 4),
                 (*(saddr + 3) & 0x0F), (*(saddr + 3) >> 4),
                 (*(saddr + 2) & 0x0F), (*(saddr + 2) >> 4),
                 (*(saddr + 1) & 0x0F), (*(saddr + 1) >> 4),
                 (*(saddr) & 0x0F), (*(saddr) >> 4));
    } else {
        val_log((val_context_t *) NULL, LOG_INFO,
                "address_to_reverse_domain(): Error - unsupported family : \'%d\'",
                family);
        return (EAI_FAMILY);
    }

    /*
     * ns_name_pton(dadd, wadd, wlen); 
     */

    val_log((val_context_t *) NULL, LOG_DEBUG,
            "address_to_reverse_domain(): reverse domain address \'%s\'",
            dadd);

    return (0);
}                               /* address_to_reverse_domain */


/*
 * address_to_string converts a sockaddr address for IPv4 or IPv6
 * to a string address 'nadd'
 * 
 * For IPv6, the string address should be at least 74 characters in
 * length.
 * 
 * For IPv4, the string address should be at least 30 characeters in
 * length.
 * 
 * returns 0 on success, 1 on failure. 
 */
int
address_to_string(const u_char *saddr, int family, char *nadd, int nlen)
{

    if (AF_INET == family) {
        if (nlen < 30)
            return (EAI_FAIL);
        snprintf(nadd, nlen, "%d.%d.%d.%d",
                 *(saddr), *(saddr + 1), *(saddr + 2), *(saddr + 3));
    } else if (AF_INET6 == family) {
        int shorten = 0;
        if (nlen < 74)
            return (EAI_FAIL);
        snprintf(nadd, nlen,
                 "%X%X%X%X:%X%X%X%X:%X%X%X%X:%X%X%X%X:%X%X%X%X:%X%X%X%X:%X%X%X%X:%X%X%X%X",
                 (*(saddr) >> 4), (*(saddr) & 0x0F), (*(saddr + 1) >> 4),
                 (*(saddr + 1) & 0x0F), (*(saddr + 2) >> 4),
                 (*(saddr + 2) & 0x0F), (*(saddr + 3) >> 4),
                 (*(saddr + 3) & 0x0F), (*(saddr + 4) >> 4),
                 (*(saddr + 4) & 0x0F), (*(saddr + 5) >> 4),
                 (*(saddr + 5) & 0x0F), (*(saddr + 6) >> 4),
                 (*(saddr + 6) & 0x0F), (*(saddr + 7) >> 4),
                 (*(saddr + 7) & 0x0F), (*(saddr + 8) >> 4),
                 (*(saddr + 8) & 0x0F), (*(saddr + 9) >> 4),
                 (*(saddr + 9) & 0x0F), (*(saddr + 10) >> 4),
                 (*(saddr + 10) & 0x0F), (*(saddr + 11) >> 4),
                 (*(saddr + 11) & 0x0F), (*(saddr + 12) >> 4),
                 (*(saddr + 12) & 0x0F), (*(saddr + 13) >> 4),
                 (*(saddr + 13) & 0x0F), (*(saddr + 14) >> 4),
                 (*(saddr + 14) & 0x0F), (*(saddr + 15) >> 4),
                 (*(saddr + 15) & 0x0F));
        /** replace leading 0000 with :: */
        while (0 == strncmp("0000:", &nadd[shorten], 5))
            shorten += 5;
        if (shorten) {
            nadd[0] = ':';
            memmove(&nadd[1],&nadd[shorten-1], strlen(nadd)-shorten+2);
        }
    } else {
        val_log((val_context_t *) NULL, LOG_INFO,
                "address_to_string(): Error - unsupported family : \'%d\'",
                family);
        return (EAI_FAMILY);
    }

    val_log((val_context_t *) NULL, LOG_DEBUG,
            "address_to_string(): numeric address \'%s\'", nadd);

    return (0);
}                               /* address_to_string */


int
val_getnameinfo(val_context_t * context,
                const struct sockaddr *sa,
                size_t salen,
                char *host,
                size_t hostlen,
                char *serv,
                size_t servlen, int flags, val_status_t * val_status)
{

    char            domain_string[NS_MAXDNAME], number_string[NS_MAXDNAME];
    const u_char   *theAddress = NULL;
    int             theAddressFamily;
    int             retval = 0, ret_status = 0;

    struct val_answer_chain *res;
    struct val_answer_chain *val_res = NULL;
    val_context_t *ctx = NULL;
    
    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL)
        return EAI_FAIL;;

    val_log(ctx, LOG_DEBUG, "val_getnameinfo(): called");

    /*
     * check misc parameters, there should be at least one of host or
     * server, check if flags indicate host is required 
     */
    if (!val_status || !sa) {
      retval = EAI_FAIL;
      goto done;
    }

    *val_status = VAL_UNTRUSTED_ANSWER;

    if (!host && !serv) {
      retval = EAI_NONAME;
      goto done;
    }
    
    /*
     * should the services be looked up 
     */
    if (serv && servlen > 0) {
        struct servent *sent;
        u_int16_t port;
        if (sa->sa_family == AF_INET) {
            port = ((const struct sockaddr_in*)sa)->sin_port;
        } 
#ifdef VAL_IPV6
        else if (sa->sa_family == AF_INET6) {
            port = ((const struct sockaddr_in6*)sa)->sin6_port;
        } 
#endif
        else {
            val_log(ctx, LOG_DEBUG, "val_getnameinfo(): Address family %d not known.", sa->sa_family);
            retval = EAI_FAMILY;
            goto done;
        }

        val_log(ctx, LOG_DEBUG, 
            "val_getnameinfo(): get service for port(%d)",ntohs(port));
        if (flags & NI_DGRAM)
            sent = getservbyport(port, "udp");
        else
            sent = getservbyport(port, NULL);

        if (sent) {
            if (flags & NI_NUMERICSERV) {
                val_log(ctx, LOG_DEBUG, "val_getnameinfo(): NI_NUMERICSERV");
                snprintf(serv, servlen, "%d", ntohs(sent->s_port));
            } else {
                strncpy(serv, sent->s_name, servlen);
            }
            val_log(ctx, LOG_DEBUG, "val_getnameinfo(): service is %s : %s ",
                serv, sent->s_proto);
        } else {
            strncpy(serv, "", servlen);
        }
    }

    /*
     * should the host be looked up 
     */
    if (!host || hostlen == 0) {
        *val_status = VAL_TRUSTED_ANSWER;
        retval = 0;
        goto done;
    }

    /*
     * get the address values, only support IPv4 and IPv6 
     */
    if (AF_INET == sa->sa_family && salen >= sizeof(struct sockaddr_in)) {
        theAddress =
            (const u_char *) &((const struct sockaddr_in *) sa)->sin_addr;
        theAddressFamily = AF_INET;
    } 
#ifdef VAL_IPV6
    else if (AF_INET6 == sa->sa_family
               && salen >= sizeof(struct sockaddr_in6)) {
        static const u_char _ipv6_wrapped_ipv4[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff };
        theAddress =
            (const u_char *) &((const struct sockaddr_in6 *) sa)->sin6_addr;
        if (!(flags & NI_NUMERICHOST) &&
            (0 == memcmp(&((const struct sockaddr_in6 *) sa)->sin6_addr,
                         _ipv6_wrapped_ipv4, sizeof(_ipv6_wrapped_ipv4)))) {
            val_log(ctx, LOG_DEBUG, "val_getnameinfo(): ipv4 wrapped addr");
            theAddress += sizeof(_ipv6_wrapped_ipv4);
            theAddressFamily = AF_INET;
        }
        else
            theAddressFamily = AF_INET6;
            
    } 
#endif
    else {
        val_log(ctx, LOG_DEBUG, "val_getnameinfo(): Address family %d not known or length %d too small.", sa->sa_family, salen);
        retval = EAI_FAMILY;
        goto done;
    }

    /*
     * get string values: address string, reverse domain string, on
     * the wire reverse domain string 
     */
    memset(number_string, 0, sizeof(number_string));
    memset(domain_string, 0, sizeof(domain_string));

    if ((0 != (ret_status =
             address_to_string(theAddress, theAddressFamily,
                     number_string, sizeof(number_string))))
         ||
        (0 != (ret_status =
             address_to_reverse_domain(theAddress, theAddressFamily,
                      domain_string, sizeof(domain_string))))) {
            retval = ret_status;
            goto done;
    }

    /*
     * set numeric value initially for either NI_NUMERICHOST or failed lookup
     */
    strncpy(host, number_string, hostlen);

    val_log(ctx, LOG_DEBUG, "val_getnameinfo(): pre-val flags(%d)", flags);

    if ((flags & NI_NUMERICHOST) && !(flags & NI_NAMEREQD)) {
        *val_status = VAL_TRUSTED_ANSWER;
        val_log(ctx, LOG_DEBUG, "val_getnameinfo(): returning host (%s)", host);
        retval = 0;
        goto done;
    }

    val_log(ctx, LOG_DEBUG, "val_getnameinfo(): val_get_rrset host flags(%d)", flags);
    if (VAL_NO_ERROR != 
              (retval = val_get_rrset(ctx,       /*val_context_t*  */
                                      domain_string, /*u_char *wire_domain_name */
                                      ns_c_in,   /*const u_int16_t q_class */
                                      ns_t_ptr,  /*const u_int16_t type */
                                      0, /*const u_int32_t flags */
                                      &val_res))) { /* struct val_answer_chain **results */
        val_log(ctx, LOG_ERR, 
                "val_getnameinfo(): val_get_rrset failed - %s", 
                p_val_err(retval));
        *val_status = VAL_UNTRUSTED_ANSWER;
        retval = EAI_FAIL;
        goto done;
    }

    if (!val_res) {
        val_log(ctx, LOG_ERR, "val_getnameinfo(): EAI_MEMORY");
        *val_status = VAL_UNTRUSTED_ANSWER;
        retval = EAI_MEMORY;
        goto done;
    }

    retval = 0;

    for (res = val_res; res; res=res->val_ans_next) {
        /* set the value of merged trusted and validated status values */
        if (res->val_ans) {
            if (host && (hostlen > 0) 
                && (hostlen >= res->val_ans->rr_length) 
                && !(flags & NI_NUMERICHOST))  {
                    ns_name_ntop(res->val_ans->rr_data,
                               host, hostlen);
            }
            if (val_isvalidated(res->val_ans_status))
                *val_status = VAL_VALIDATED_ANSWER;
            else if (val_istrusted(res->val_ans_status))
                *val_status = VAL_TRUSTED_ANSWER;
            else
                *val_status = VAL_UNTRUSTED_ANSWER;
            break;
        } else if (val_does_not_exist(res->val_ans_status)) {
            if ((res->val_ans_status == VAL_NONEXISTENT_TYPE) ||
                    (res->val_ans_status == VAL_NONEXISTENT_TYPE_NOCHAIN)) {
                retval = EAI_NODATA;
            } else { 
                retval = EAI_NONAME;
            }
            break;
        } 
    }
    val_free_answer_chain(val_res);

    val_log(ctx, LOG_DEBUG,
          "val_getnameinfo(): val_get_rrset for host %s, returned %s with lookup status %d and validator status %d : %s",
          domain_string, host,
          retval, 
          *val_status, p_val_status(*val_status));

done:
    CTX_UNLOCK_POL(ctx);
    return retval;

}                               // val_getnameinfo

/*
 * define error codes for val_getaddrinfo and val_getnameinfo which
 * have a DNSSEC validation status.
 */
int val_getaddrinfo_has_status(int rc) {
#if defined(EAI_NODATA) && defined(EAI_NONAME)
    return ((rc == 0) || (rc == EAI_NONAME) || (rc == EAI_NODATA));
#elif defined(EAI_NONAME)
    return ((rc == 0) || (rc == EAI_NONAME));
#elif defined(WSAHOST_NOT_FOUND) && defined(WSANO_DATA) 
	return ((rc == 0) || (rc == WSAHOST_NOT_FOUND) || (rc == WSANO_DATA));
#else
    return (rc == 0);
#endif
}

/** ====================================================================== **/
/** ====================================================================== **/
/** ====================================================================== **/
/** ====================================================================== **/
/** ====================================================================== **/

#ifndef VAL_NO_ASYNC

#define VAL_GAI_DONE         0x0001

#define VAL_AS_CANCEL_DONT_FREE 0x01000000

struct val_gai_status_s {
    char             *nodename;
    char             *servname;
    const struct addrinfo  *hints;

    val_context_t    *context;
    struct addrinfo  *res;
    val_status_t      val_status;
    val_async_status *inet_status;
    val_async_status *inet6_status;

    u_int             flags;
    val_gai_callback  callback;
    void             *callback_data;
};

static void
_cancel_vgai( val_gai_status *vgai, int flags )
{
    vgai->flags |= VAL_AS_CANCEL_DONT_FREE;

    if (NULL != vgai->inet_status) {
        val_async_cancel(vgai->context, vgai->inet_status, flags);
        vgai->inet_status = NULL;
    }

    if (NULL != vgai->inet6_status) {
        val_async_cancel(vgai->context, vgai->inet6_status, flags);
        vgai->inet6_status = NULL;
    }

    vgai->flags &= ~VAL_AS_CANCEL_DONT_FREE;
}

static void
_free_vgai( val_gai_status *vgai )
{
    if (NULL == vgai || vgai->flags & VAL_AS_CANCEL_DONT_FREE)
        return;

    _cancel_vgai( vgai, VAL_AS_CANCEL_NO_CALLBACKS);

    if (NULL != vgai->nodename) {
        free(vgai->nodename);
        vgai->nodename = NULL;
    }

    if (NULL != vgai->servname) {
        free(vgai->servname);
        vgai->servname = NULL;
    }

    if (NULL != vgai->res) {
        val_freeaddrinfo(vgai->res);
        vgai->res = NULL;
    }

    free(vgai);
}

void
val_getaddrinfo_cancel(val_gai_status *status, int flags)
{
    if (NULL == status)
        return;
    _cancel_vgai(status, flags);
    _free_vgai(status);
}

/*
 * our internal callback for request completion, which in turns calls
 * original caller vgai_callback.
 */
static int
_vgai_async_callback(val_async_status *as, int event,
                     val_context_t *ctx, void *cb_data, val_cb_params_t *cbp)
{
    int                rc, gai_rc;
    val_gai_status    *vgai;

    vgai = (val_gai_status *)cb_data;
    if (NULL == vgai) {
        val_log(ctx, LOG_DEBUG, "val_getaddrinfo no callback data!");
        return VAL_NO_ERROR;
    }
    gai_rc = EAI_FAIL;

    val_log(ctx, LOG_DEBUG,
            "val_getaddrinfo async callback for %p, %s %s(%d)", as,
            vgai->nodename, p_type(cbp->type_h), cbp->type_h);


    if (0 == vgai->val_status) /* recently created */
        vgai->val_status = VAL_VALIDATED_ANSWER;

    /*
     * get answer_chain from result_chain
     */
    rc = val_get_answer_from_result(ctx, vgai->nodename, cbp->class_h,
                                    cbp->type_h, &cbp->results, &cbp->answers,
                                    0);
    if (VAL_NO_ERROR != rc) {
        val_log(ctx, LOG_DEBUG,
                "val_gai_callback: val_get_answer_from_result() returned=%d", rc);
    }
    else {
        /*
         * get addrinfo from results
         */
        gai_rc = get_addrinfo_from_result(ctx, cbp->answers, vgai->servname,
                                          vgai->hints, &vgai->res,
                                          &vgai->val_status);
        val_log(ctx, LOG_DEBUG,
                "val_gai_callback get_addrinfo_from_result() returned=%d with val_status=%d",
                gai_rc, vgai->val_status);
    }

    /*
     * clear async_status ptr, as it will be freed after this callback 
     * completes.
     */
    if (ns_t_a == cbp->type_h) {
        vgai->inet_status = NULL;
        if (rc != VAL_NO_ERROR) {
            if (vgai->inet6_status) {
                val_async_cancel(vgai->context, vgai->inet6_status,
                                 VAL_AS_CANCEL_NO_CALLBACKS);
                vgai->inet6_status = NULL;
            }
        }
    }
    else if (ns_t_aaaa == cbp->type_h) {
        vgai->inet6_status = NULL;
        if (rc != VAL_NO_ERROR) {
            if (vgai->inet_status) {
                val_async_cancel(vgai->context, vgai->inet_status,
                                 VAL_AS_CANCEL_NO_CALLBACKS);
                vgai->inet_status = NULL;
            }
        }
    }

    /*
     * if both async_status ptr are NULL, we're done and should call
     * our callback.
     */
    if (NULL != vgai->inet6_status || NULL != vgai->inet_status)
        return VAL_NO_ERROR;

    if (NULL == vgai->callback) {
        val_log(ctx, LOG_DEBUG, "val_getaddrinfo async NULL callback!");
    } else {
        if (VAL_AS_EVENT_CANCELED == event)
            gai_rc = VAL_AS_EVENT_CANCELED;
        (*vgai->callback)(vgai->callback_data, gai_rc, vgai->res,
                          vgai->val_status);
        /** let caller keep res structure */
        vgai->res = NULL;
    }

    _free_vgai(vgai);

    return VAL_NO_ERROR;
}

/*
 * Function: val_getaddrinfo_submit
 *
 * Purpose: submit asynchronous request for getaddrinfo style resoloution
 *
 * Parameters: context -- context for request. May be NULL, in which case
 *                        the default context will be used.
 *             nodename, servname, hints_in -- see getaddrinfo man page
 *             callback -- val_gai_callback function which will be called when
 *                         the request completes
 *             callback_data -- optional void pointer which will also be
 *                              passed to the callback. Not used internally,
 *                              strictly for caller to pass context to callback.
 *             val_gai_flags -- flags affecting function operation
 *             status -- opaque val_gai_status object which caller can use to
 *                       cancel request
 *
 * Returns: VAL_NO_ERROR -- successful submission
 *          VAL_BAD_ARGUMENT -- need callback and nodename or servname
 *
 *          May return other validator errors from internal function calls
 *
 * Note: caller assumes responsibility for the memory for the addrinfo
 *       linked list passed to the callback function.
 */
int
val_getaddrinfo_submit(val_context_t * context, const char *nodename,
                       const char *servname, const struct addrinfo *hints_in,
                       val_gai_callback callback, void *callback_data,
                       unsigned int val_gai_flags, val_gai_status **status)
{
    val_gai_status        *vgai = NULL;
    int                    vretval = VAL_NO_ERROR, rc, have4 = 1, have6 = 1;
    struct addrinfo       *res = NULL;
    const struct addrinfo *hints;
    struct addrinfo        default_hints;
    val_context_t         *ctx;
    val_status_t           val_status;

    if (((NULL == nodename) && (NULL == servname)) || (NULL == callback))
        return VAL_BAD_ARGUMENT;

    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL)
        return VAL_INTERNAL_ERROR;

    /*
     * use a default hints structure if one is not available.
     */
    if (hints_in == NULL) {
        memset(&default_hints, 0, sizeof(default_hints));
        hints = &default_hints;
    } else {
        hints = hints_in;
    }

    /** check we have a supported family */
    if (hints->ai_family != AF_UNSPEC &&
        hints->ai_family != AF_INET && hints->ai_family != AF_INET6) {

        (*callback)(callback_data, EAI_NONAME, NULL, VAL_UNTRUSTED_ANSWER);
        goto done;
    }

    /** try local sources first */
    rc = _getaddrinfo_local(ctx, nodename, servname, hints, &res, &val_status);
    if (EAI_AGAIN != rc) {
        /** _getaddrinfo_local returns eai rc, not libval */
        (*callback)(callback_data, rc, res, val_status);
        goto done;
    }

    vgai = (val_gai_status *)calloc(1, sizeof(val_gai_status));
    if (NULL == vgai) {
        vretval = VAL_ENOMEM;
        goto done;
    }

    vgai->context = ctx;
    vgai->flags = val_gai_flags;
    vgai->callback = callback;
    vgai->callback_data = callback_data;
    vgai->hints = hints;
    if (servname)
        vgai->servname = (char *)strdup(servname);
    if (nodename)
        vgai->nodename = (char *)strdup(nodename);

#ifdef AI_ADDRCONFIG
    if (hints->ai_flags & AI_ADDRCONFIG) {
        have4 = val_context_ip4(ctx);
        have6 = val_context_ip6(ctx);
    }
#endif

    /*
     * Check if we need to return IPv4 addresses based on the hints
     */
    if ((hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET)
#ifdef AI_ADDRCONFIG
        && (have4 != 0)
#endif
        ) {

        val_log(ctx, LOG_DEBUG,
                "val_getaddrinfo_submit(): checking for A records");

        rc = val_async_submit(ctx, nodename, ns_c_in, ns_t_a, 0,
                              &_vgai_async_callback, vgai, &vgai->inet_status);
        if (VAL_NO_ERROR != rc) {
            vgai->flags |= VAL_GAI_DONE;
            vretval = rc;
            goto done;
        }
    }

#ifdef VAL_IPV6
    /*
     * Check if we need to return IPv6 addresses based on the hints
     */
    if ((hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET6)
#ifdef AI_ADDRCONFIG
        && (have6 != 0)
#endif
        ) {

        val_log(ctx, LOG_DEBUG,
                "val_getaddrinfo_submit(): checking for AAAA records");

        rc = val_async_submit(ctx, nodename, ns_c_in, ns_t_aaaa, 0,
                              &_vgai_async_callback, vgai, &vgai->inet6_status);
        if (VAL_NO_ERROR != rc) {
            vgai->flags |= VAL_GAI_DONE;
            vretval = rc;
            val_async_cancel(ctx, vgai->inet_status,
                             VAL_AS_CANCEL_NO_CALLBACKS);
            goto done;
        }
        // XXX SK: Are these two lines really required?
        vgai->inet6_status->val_as_result_cb = &_vgai_async_callback;
        vgai->inet6_status->val_as_cb_user_ctx = vgai;
    }
#endif

done:
    CTX_UNLOCK_POL(ctx);

    if (VAL_NO_ERROR == vretval)
        *status = vgai;
    else
        _free_vgai( vgai );

    return vretval;
}                               /* val_getaddrinfo_submit() */

#endif /* VAL_NO_ASYNC */
