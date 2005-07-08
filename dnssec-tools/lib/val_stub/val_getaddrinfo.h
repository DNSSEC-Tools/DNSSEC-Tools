/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the header file for a validating getaddrinfo function.
 * Applications should be able to use this in place of getaddrinfo
 * with minimal change.
 */

#ifndef VAL_GETADDRINFO_H
#define VAL_GETADDRINFO_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/**
 * val_getaddrinfo: A validating getaddrinfo function.
 *                  Based on getaddrinfo() as defined in RFC3493.
 *
 * Parameters:
 *     Note: All the parameters, except the dnssec_status parameter,
 *     ----  are similar to the getaddrinfo function.
 *
 *     [IN]  node: Specifies either a numerical network address (dotted-
 *                decimal format for IPv4, hexadecimal format for IPv6)
 *                or a network hostname, whose network addresses are
 *                looked up and resolved.
 *                node or service parameter, but not both, may be NULL.
 *     [IN]  service: Used to set the port number in the network address
 *                of each socket structure returned.  If service is NULL
 *                the  port  number will be left uninitialized.
 *     [IN]  hints: Specifies  the  preferred socket type, or protocol.
 *                A NULL hints specifies that any network address or
 *                protocol is acceptable.
 *     [OUT] res: Points to a dynamically-allocated link list of addrinfo
 *                structures, linked by the ai_next member.
 *     [OUT] dnssec_status: Points to a pre-allocated (by the caller) int
 *                value where the result of DNSSEC validation will be stored.
 *                If DNSSEC validation is successful, it will
 *                contain VALIDATE_SUCCESS.  If there is a
 *                failure, it will contain the validator error code.
 *
 * Return value: This function returns 0 if it succeeds, or one of the
 *               non-zero error codes if it fails.  See man getaddrinfo
 *               for more details.
 */
struct int val_getaddrinfo ( const char *nodename, const char *servname,
			     const struct addrinfo *hints,
			     struct addrinfo **res, int *dnssec_status );
#endif
