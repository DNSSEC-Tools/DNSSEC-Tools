/*
 * Copyright 2005-2009 SPARTA, Inc.  All rights reserved.
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
#include "validator-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <resolv.h>

#include <validator/validator.h>
#include <validator/resolver.h>
#include "val_policy.h"
#include <errno.h>

#ifndef HAVE_FREEADDRINFO

/* 
 * define this freeaddrinfo if we don't have it already available
 */
void
freeaddrinfo(struct addrinfo *ainfo)
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

#endif

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
    } else if (PF_INET6 == saddr->sa_family) {
        ((struct sockaddr_in6 *) saddr)->sin6_port = portnum;
    }
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
            freeaddrinfo(a1);
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
    int ret;

    if (res == NULL) 
        return 0;

    val_log(ctx, LOG_DEBUG, "get_addrinfo_from_etc_hosts(): Parsing /etc/hosts");

    /*
     * Parse the /etc/hosts/ file 
     */
    hs = parse_etc_hosts(nodename);

    while (hs) {
        int             alias_index = 0;
        struct in_addr  ip4_addr;
        struct in6_addr ip6_addr;
        struct hosts   *h_prev = hs;
        struct addrinfo *ainfo;

        ainfo =
            (struct addrinfo *) malloc(sizeof(struct addrinfo));
        if (!ainfo) {
            if (retval)
                freeaddrinfo(retval);
            return EAI_MEMORY;
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
        memset(&ip4_addr, 0, sizeof(struct in_addr));
        memset(&ip6_addr, 0, sizeof(struct in6_addr));

        /*
         * Check if the address is an IPv4 address 
         */
        if (inet_pton(AF_INET, hs->address, &ip4_addr) > 0) {
            struct sockaddr_in *saddr4 =
                (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
            if (saddr4 == NULL) {
                if (retval)
                    freeaddrinfo(retval);
                freeaddrinfo(ainfo);
                return EAI_MEMORY;
            }
            memset(saddr4, 0, sizeof(struct sockaddr_in));
            ainfo->ai_family = AF_INET;
            saddr4->sin_family = AF_INET;
            ainfo->ai_addrlen = sizeof(struct sockaddr_in);
            memcpy(&(saddr4->sin_addr), &ip4_addr, sizeof(struct in_addr));
            ainfo->ai_addr = (struct sockaddr *) saddr4;
            ainfo->ai_canonname = NULL;
        }
        /*
         * Check if the address is an IPv6 address 
         */
        else if (inet_pton(AF_INET6, hs->address, &ip6_addr) > 0) {
            struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)
                malloc(sizeof(struct sockaddr_in6));
            if (saddr6 == NULL) {
                if (retval)
                    freeaddrinfo(retval);
                freeaddrinfo(ainfo);
                return EAI_MEMORY;
            }
            memset(saddr6, 0, sizeof(struct sockaddr_in6));
            ainfo->ai_family = AF_INET6;
            saddr6->sin6_family = AF_INET6;
            ainfo->ai_addrlen = sizeof(struct sockaddr_in6);
            memcpy(&(saddr6->sin6_addr), &ip6_addr,
                   sizeof(struct in6_addr));
            ainfo->ai_addr = (struct sockaddr *) saddr6;
            ainfo->ai_canonname = NULL;
        } else {
            val_log(ctx, LOG_WARNING, 
                    "get_addrinfo_from_etc_hosts(): Host is nether an A nor an AAAA address");
            freeaddrinfo(ainfo);
            continue;
        }

        /*
         * Expand the results based on servname and hints 
         */
        if ((ret = process_service_and_hints(servname, hints, &ainfo)) != 0) {
            freeaddrinfo(ainfo);
            if (retval)
                freeaddrinfo(retval);
            val_log(ctx, LOG_INFO, 
                    "get_addrinfo_from_etc_hosts(): Failed in process_service_and_hints()");
            return ret;
        }

        if (retval) {
            retval = append_addrinfo(retval, ainfo);
        } else {
            retval = ainfo;
        }

        hs = hs->next;
        FREE_HOSTS(h_prev);
    }

    val_log(ctx, LOG_DEBUG, "get_addrinfo_from_etc_hosts(): Parsing /etc/hosts OK");

    *res = retval;
    if (retval) {
        return 0;
    } else {
        return EAI_NONAME;
    }
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
        return 0;

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
             * Loop for each rr in the linked list of val_rr_rec structures 
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
                        freeaddrinfo(ainfo);
                        return EAI_MEMORY;
                    }
                    val_log(ctx, LOG_DEBUG, "get_addrinfo_from_result(): rrset of type A found");
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
                else if (result->val_ans_type == ns_t_aaaa) {
                    struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)
                        malloc(sizeof(struct sockaddr_in6));
                    if (saddr6 == NULL) {
                        freeaddrinfo(ainfo);
                        return EAI_MEMORY;
                    }
                    val_log(ctx, LOG_DEBUG, "get_addrinfo_from_result(): rrset of type AAAA found");
                    saddr6->sin6_family = AF_INET6;
                    ainfo->ai_family = AF_INET6;
                    ainfo->ai_addrlen = sizeof(struct sockaddr_in6);
                    memcpy(&(saddr6->sin6_addr.s6_addr), rr->rr_data,
                           rr->rr_length);
                    ainfo->ai_addr = (struct sockaddr *) saddr6;
                } else {
                    freeaddrinfo(ainfo);
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
                    freeaddrinfo(ainfo);
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
 *                     using freeaddrinfo().
 *
 * Returns: 0 on success and a non-zero value on error.
 *
 * See also: val_getaddrinfo()
 */

static int
get_addrinfo_from_dns(val_context_t * ctx,
                      const char *nodename,
                      const char *servname,
                      const struct addrinfo *hints,
                      struct addrinfo **res,
                      val_status_t *val_status)
{
    struct val_answer_chain *results = NULL;
    struct addrinfo *ainfo = NULL;
    int    ret = EAI_FAIL;

    val_log(ctx, LOG_DEBUG, "get_addrinfo_from_dns() called");

    *val_status = VAL_VALIDATED_ANSWER;

    if (res == NULL ||
        (hints != NULL && 
         hints->ai_family != AF_UNSPEC &&
         hints->ai_family != AF_INET &&
         hints->ai_family != AF_INET6)) {

        *val_status = VAL_UNTRUSTED_ANSWER;
        return EAI_NONAME; 
    }
    
    /*
     * Check if we need to return IPv4 addresses based on the hints 
     */
    if (hints == NULL || hints->ai_family == AF_UNSPEC
        || hints->ai_family == AF_INET) {

        val_log(ctx, LOG_DEBUG, "get_addrinfo_from_dns(): checking for A records");

        if ((VAL_NO_ERROR == 
                    val_get_rrset(ctx, nodename, ns_c_in, ns_t_a, 0, &results)) 
                && results) {
            
            ret = get_addrinfo_from_result(ctx, results, servname,
                                         hints, &ainfo, val_status);

            val_log(ctx, LOG_DEBUG, 
                    "get_addrinfo_from_dns(): get_addrinfo_from_result() returned=%d with val_status=%d",
                    ret, *val_status);

            val_free_answer_chain(results);
            results = NULL;
        } 
    } 

#ifdef VAL_IPV6
    /*
     * Check if we need to return IPv6 addresses based on the hints 
     */
    if (hints == NULL || hints->ai_family == AF_UNSPEC
        || hints->ai_family == AF_INET6) {

        val_log(ctx, LOG_DEBUG, "get_addrinfo_from_dns(): checking for AAAA records");
        
        if ((VAL_NO_ERROR == 
                    val_get_rrset(ctx, nodename, ns_c_in, ns_t_aaaa, 0, &results)) 
                && results) {
            ret = get_addrinfo_from_result(ctx, results, servname,
                                         hints, &ainfo, val_status);

            val_log(ctx, LOG_DEBUG, 
                    "get_addrinfo_from_dns(): get_addrinfo_from_result() returned=%d with val_status=%d",
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
 *                using freeaddrinfo().
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
    struct in_addr  ip4_addr;
    struct in6_addr ip6_addr;
    struct addrinfo *ainfo4 = NULL;
    struct addrinfo *ainfo6 = NULL;
    int             is_ip4 = 0;
    int             is_ip6 = 0;
    int             retval = 0;
    const char     *localhost4 = "127.0.0.1";
    const char     *localhost6 = "::1";
    const char     *nname = nodename;
    struct addrinfo default_hints;
    const struct addrinfo *cur_hints;
    val_status_t local_ans_status = VAL_OOB_ANSWER;
    int trusted = 0;
    val_context_t *ctx = NULL;
    
    if (context == NULL) {
        if (VAL_NO_ERROR != (retval = val_create_context(NULL, &ctx))) {
            val_log(ctx, LOG_DEBUG, "val_getaddrinfo: context could not be created");
            return EAI_FAIL; 
        } 
    } else {
        ctx = context;
    }
    val_log(ctx, LOG_DEBUG,
            "val_getaddrinfo called with nodename = %s, servname = %s",
            nodename == NULL ? "(null)" : nodename,
            servname == NULL ? "(null)" : servname);


    if (VAL_NO_ERROR == val_is_local_trusted(ctx, &trusted)) {
        if (trusted) {
            local_ans_status = VAL_TRUSTED_ANSWER;
        }
    }
    if (res == NULL || val_status == NULL)
        return 0;

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
        return EAI_NONAME;
    }

    memset(&ip4_addr, 0, sizeof(struct in_addr));
    memset(&ip6_addr, 0, sizeof(struct in6_addr));

    /*
     * if nodename is blank or hints includes ipv4 or unspecified,
     * use IPv4 localhost 
     */
    if (NULL == nodename &&
        (AF_INET == cur_hints->ai_family ||
         AF_UNSPEC == cur_hints->ai_family)
        ) {
        nname = localhost4;
    }

    /*
     * check for IPv4 addresses 
     */
    if (NULL != nname && inet_pton(AF_INET, nname, &ip4_addr) > 0) {

        struct sockaddr_in *saddr4 =
            (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
        if (saddr4 == NULL) {
            return EAI_MEMORY;
        }
        ainfo4 =
            (struct addrinfo *) malloc(sizeof(struct addrinfo));
        if (ainfo4 == NULL) {
            free(saddr4);
            return EAI_MEMORY;
        }

        is_ip4 = 1;

        memset(ainfo4, 0, sizeof(struct addrinfo));
        memset(saddr4, 0, sizeof(struct sockaddr_in));

        saddr4->sin_family = AF_INET;
        ainfo4->ai_family = AF_INET;
        memcpy(&(saddr4->sin_addr), &ip4_addr, sizeof(struct in_addr));
        ainfo4->ai_addr = (struct sockaddr *) saddr4;
        saddr4 = NULL;
        ainfo4->ai_addrlen = sizeof(struct sockaddr_in);
        ainfo4->ai_canonname = NULL;

        if ((retval = process_service_and_hints(servname, cur_hints, &ainfo4))
            != 0) {
            freeaddrinfo(ainfo4);
            val_log(ctx, LOG_INFO, 
                    "val_getaddrinfo(): Failed in process_service_and_hints()");
            return retval;
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

    /*
     * Check for IPv6 address 
     */
    if (nname != NULL && inet_pton(AF_INET6, nname, &ip6_addr) > 0) {

        struct sockaddr_in6 *saddr6 =
            (struct sockaddr_in6 *) malloc(sizeof(struct sockaddr_in6));
        if (saddr6 == NULL) {
            return EAI_MEMORY;
        }
        ainfo6 =
            (struct addrinfo *) malloc(sizeof(struct addrinfo));
        if (ainfo6 == NULL) {
            free(saddr6);
            return EAI_MEMORY;
        }

        is_ip6 = 1;

        memset(ainfo6, 0, sizeof(struct addrinfo));
        memset(saddr6, 0, sizeof(struct sockaddr_in6));

        saddr6->sin6_family = AF_INET6;
        ainfo6->ai_family = AF_INET6;
        memcpy(&(saddr6->sin6_addr), &ip6_addr, sizeof(struct in6_addr));
        ainfo6->ai_addr = (struct sockaddr *) saddr6;
        saddr6 = NULL;
        ainfo6->ai_addrlen = sizeof(struct sockaddr_in6);
        ainfo6->ai_canonname = NULL;

        if ((retval = process_service_and_hints(servname, cur_hints, &ainfo6))
            != 0) {
            freeaddrinfo(ainfo6);
            val_log(ctx, LOG_INFO, 
                    "val_getaddrinfo(): Failed in process_service_and_hints()");
            return retval;
        }

        if (NULL != *res) {
            *res = append_addrinfo(*res, ainfo6);
        } else {
            *res = ainfo6;
        }
        retval = 0;
    }

    if (*res) {
        *val_status = VAL_TRUSTED_ANSWER;
        return retval;
    } 
    if (nodename) {

        /*
         * If nodename was specified and was not an IPv4 or IPv6
         * address, get its information from local store or from dns
         * or return error if AI_NUMERICHOST specified
         */
        if (cur_hints->ai_flags & AI_NUMERICHOST)
            return EAI_NONAME;
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
            retval = get_addrinfo_from_dns(ctx, nodename, servname,
                                           cur_hints, res, val_status);
        }
    }

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
                socklen_t salen,
                char *host,
                size_t hostlen,
                char *serv,
                size_t servlen, int flags, val_status_t * val_status)
{

    const int       addr_size = 100;
    char            domain_string[addr_size], number_string[addr_size];
    const u_char   *theAddress = NULL;
    int             theAddressFamily;
    int             val_rnc_status = 0, ret_status = 0;

    struct val_answer_chain *res;
    struct val_answer_chain *val_res = NULL;
    int retval;
    val_context_t *ctx = NULL;
    
    if (context == NULL) {
        if (VAL_NO_ERROR != (retval = val_create_context(NULL, &ctx))) {
            return EAI_FAIL; 
        } 
    } else {
        ctx = context;
    }
    val_log(ctx, LOG_DEBUG,
            "val_getnameinfo called with host = %s, serv = %s",
            host == NULL ? "(null)" : host,
            serv == NULL ? "(null)" : serv);


    *val_status = VAL_UNTRUSTED_ANSWER;

    /*
     * check misc parameters, there should be at least one of host or
     * server, check if flags indicate host is required 
     */
    if (!val_status || !sa)
      return EAI_FAIL;

    if (!host && !serv) 
      return EAI_NONAME;
    
    /*
     * should the services be looked up 
     */
    if (serv && servlen > 0) {
        struct servent *sent;
        int port = ((const struct sockaddr_in*)sa)->sin_port;

        val_log(ctx, LOG_DEBUG, 
            "val_getnameinfo(): get service for port(%d)",ntohs(port));
        if (flags & NI_DGRAM)
            sent = getservbyport(port, "udp");
        else
            sent = getservbyport(port, NULL);

        if (!sent)
            return EAI_FAIL;

        if (flags & NI_NUMERICSERV) {
            val_log(ctx, LOG_DEBUG, "val_getnameinfo(): NI_NUMERICSERV");
            snprintf(serv, servlen, "%d", ntohs(sent->s_port));
        } else {
            strncpy(serv, sent->s_name, servlen);
        }
        val_log(ctx, LOG_DEBUG, "val_getnameinfo(): service is %s : %s ",
                serv, sent->s_proto);
    }

    /*
     * should the host be looked up 
     */
    if (!host || hostlen == 0) {
        *val_status = VAL_TRUSTED_ANSWER;
        return 0;
    }

    /*
     * get the address values, only support IPv4 and IPv6 
     */
    if (AF_INET == sa->sa_family && salen >= sizeof(struct sockaddr_in)) {
        theAddress =
            (const u_char *) &((const struct sockaddr_in *) sa)->sin_addr;
        theAddressFamily = AF_INET;
    } else if (AF_INET6 == sa->sa_family
               && salen >= sizeof(struct sockaddr_in6)) {
        static const u_char _ipv6_wrapped_ipv4[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff };
        theAddress =
            (const u_char *) &((const struct sockaddr_in6 *) sa)->sin6_addr;
        if (!(flags & NI_NUMERICHOST) &&
            (0 == memcmp(&((const struct sockaddr_in6 *) sa)->sin6_addr,
                         _ipv6_wrapped_ipv4, sizeof(_ipv6_wrapped_ipv4)))) {
            val_log(ctx, LOG_DEBUG, "val_getnameinfo(): ipv4 wrapped addr\n");
            theAddress += sizeof(_ipv6_wrapped_ipv4);
            theAddressFamily = AF_INET;
        }
        else
            theAddressFamily = AF_INET6;
            
    } else {
        val_log(ctx, LOG_DEBUG, "val_getnameinfo(): Address family %d not known or length %d too small.", sa->sa_family, salen);
        return (EAI_FAMILY);
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
            return ret_status;
    }

    /*
     * set numeric value initially for either NI_NUMERICHOST or failed lookup
     */
    strncpy(host, number_string, hostlen);

    val_log(ctx, LOG_DEBUG, "val_getnameinfo(): pre-val flags(%d)\n", flags);

    if ((flags & NI_NUMERICHOST) && !(flags & NI_NAMEREQD)) {
        *val_status = VAL_TRUSTED_ANSWER;
        return 0;
    }

    val_log(ctx, LOG_DEBUG, "val_getnameinfo(): val_get_rrset host flags(%d)\n", flags);
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
        return EAI_FAIL;
    }

    if (!val_res) {
        val_log(ctx, LOG_ERR, "val_getnameinfo(): EAI_MEMORY\n");
        *val_status = VAL_UNTRUSTED_ANSWER;
        return EAI_MEMORY;
    }

    val_rnc_status = 0;

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
                val_rnc_status = EAI_NODATA;
            } else { 
                val_rnc_status = EAI_NONAME;
            }
            break;
        } 
    }
    val_free_answer_chain(val_res);

    val_log(ctx, LOG_DEBUG,
          "val_getnameinfo(): val_get_rrset for host %s, returned %s with lookup status %d and validator status %d : %s",
          domain_string, host,
          val_rnc_status, 
          *val_status, p_val_status(*val_status));


    return val_rnc_status;

}                               // val_getnameinfo
