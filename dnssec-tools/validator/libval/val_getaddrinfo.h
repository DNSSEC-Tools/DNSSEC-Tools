/*
 * Copyright 2006 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_GETADDRINFO_H
#define VAL_GETADDRINFO_H

/*
 * from val_getaddrinfo.c 
 */
struct val_addrinfo {
    int             ai_flags;
    int             ai_family;
    int             ai_socktype;
    int             ai_protocol;
    size_t          ai_addrlen;
    struct sockaddr *ai_addr;
    char           *ai_canonname;
    struct val_addrinfo *ai_next;
    val_status_t    val_status;
};
/**
 * val_getaddrinfo: A validating getaddrinfo function.
 *                  Based on getaddrinfo() as defined in RFC3493.
 *
 * Parameters:
 *     Note: All the parameters, except the val_status parameter,
 *     ----  are similar to the getaddrinfo function.
 *
 *     [IN]  ctx: The validation context.
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
 *                structures, linked by the ai_next member.  This output
 *                value can be used in the val_get_addrinfo_val_status()
 *                and the val_dupaddrinfo() functions.
 *
 * Return value: This function returns 0 if it succeeds, or one of the
 *               non-zero error codes if it fails.  See man getaddrinfo
 *               for more details.
 */

int             val_getaddrinfo(const val_context_t * ctx,
                                const char *nodename,
                                const char *servname,
                                const struct addrinfo *hints,
                                struct val_addrinfo **res);

/*
 * A function to free memory allocated by val_getaddrinfo()
 */
void            free_val_addrinfo(struct val_addrinfo *ainfo);

/**************************************************************/
#if 0
/*
 * The following three functions are to be implemented to
 * * conform to version 00 of the validator draft
 */
/*
 * A DNSSEC-aware function to perform address to name translation
 */
struct hostent *val_gethostbyaddr(const val_context_t * ctx,
                                  const char *addr,
                                  int len,
                                  int type, val_status_t * val_status);

/*
 * A thread-safe, re-entrant version of val_gethostbyaddr 
 */
int             val_gethostbyaddr_r(const val_context_t * ctx,
                                    const char *addr,
                                    int len,
                                    int type,
                                    struct hostent *ret,
                                    char *buf,
                                    int buflen,
                                    struct hostent **result,
                                    int *h_errnop,
                                    val_status_t * val_status);

/*
 * An address-to-name and service translation function 
 */
int             val_getnameinfo(const val_context_t * ctx,
                                const struct sockaddr *sa,
                                socklen_t salen,
                                char *host,
                                size_t hostlen,
                                char *serv,
                                size_t servlen,
                                int flags, val_status_t * val_status);

#endif
/**************************************************************/


#endif
