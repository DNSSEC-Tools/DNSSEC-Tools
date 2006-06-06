
/*
 * Portions Copyright (c) 1995, 1996, 1997 by Trusted Information Systems, Inc.
 *
 * Permission to use, copy modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND TRUSTED INFORMATION SYSTEMS
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
 * TRUSTED INFORMATION SYSTEMS BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THE SOFTWARE.
 */
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef RESOLVER_H
#define RESOLVER_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef MEMORY_DEBUGGING
#define MALLOC(s) my_malloc(s, __FILE__, __LINE__)
#define FREE(p) my_free(p,__FILE__,__LINE__)
#define STRDUP(p) my_strdup(p,__FILE__,__LINE__)
#else
#define MALLOC(s) malloc(s)
#define FREE(p) free(p)
#define STRDUP(p) strdup(p)
#endif

#define RES_RETRY 1

#ifndef RES_USE_DNSSEC
#define RES_USE_DNSSEC  0x00200000
#endif

#if 0
#ifndef MAXDNAME
#define MAXDNAME    256
#endif                
#endif

#define ZONE_USE_NOTHING        0x00000000
#define ZONE_USE_TSIG           0x00000001


#define SR_ZI_STATUS_UNSET      0
#define SR_ZI_STATUS_PERMANENT      1
#define SR_ZI_STATUS_LEARNED        2


#define EDNS_UDP_SIZE 4096 
#define DNAME_MAX	1024

#ifndef ns_t_dnskey
#define ns_t_dnskey	48
#endif
#ifndef ns_t_rrsig
#define ns_t_rrsig	46
#endif
#ifndef ns_t_nsec
#define ns_t_nsec	47
#endif
#ifndef ns_t_ds
#define ns_t_ds		43	
#endif

/* Resolver errors */
#define SR_UNSET    0

#define SR_CALL_ERROR             1
#define SR_TSIG_ERROR             2
#define SR_MEMORY_ERROR           3
#define SR_NO_ANSWER              4  /* No answer received */
#define SR_NO_ANSWER_YET          5 
#define SR_MKQUERY_INTERNAL_ERROR 6
#define SR_TSIG_INTERNAL_ERROR    7
#define SR_SEND_INTERNAL_ERROR    8 
#define SR_RCV_INTERNAL_ERROR     9 
#define SR_WRONG_ANSWER           10 /*Message is not a response to a query*/
#define SR_HEADER_BADSIZE         11 /*Message size not consistent with record counts*/
#define SR_NXDOMAIN               12 /*RCODE set to NXDOMAIN w/o appropriate records*/
#define SR_FORMERR                13 /*RCODE set to FORMERR*/
#define SR_SERVFAIL               14 /*RCODE set to SERVFAIL*/
#define SR_NOTIMPL                15 /*RCODE set to NOTIMPL*/
#define SR_REFUSED                16 /*RCODE set to REFUSED*/
#define SR_GENERIC_FAILURE        17 /*Look at RCODE*/
#define SR_EDNS_VERSION_ERROR     18
#define SR_UNSUPP_EDNS0_LABEL     19
#define SR_SUSPICIOUS_BIT         20
#define SR_NAME_EXPANSION_FAILURE 21
#define SR_LAST_ERROR             22 

struct name_server
{
    u_int8_t        *ns_name_n;
    void            *ns_tsig;
    u_int32_t       ns_security_options;
    u_int32_t       ns_status;
    struct name_server  *ns_next;
    int         ns_number_of_addresses;
    struct sockaddr     ns_address[1];
	u_long  ns_options;
	int ns_retrans;
	int ns_retry;
};


/* Interfaces to the resolver */
int query_send( const char*     name,
            const u_int16_t     type_h,
            const u_int16_t     class_h,
            struct name_server  *nslist,
			int                 *trans_id);
int response_recv(int           *trans_id,
            struct name_server  **respondent,
			u_int8_t		    **answer,
			u_int			*answer_length);
int get (   const char      *name_n,
            const u_int16_t     type_h,
            const u_int16_t     class_h,
            struct name_server  *nslist,
            struct name_server  **server,
            u_int8_t            **response,
            u_int               *response_length);
void print_response (u_int8_t *ans, int resplen);
int clone_ns(struct name_server **cloned_ns, struct name_server *ns);
int clone_ns_list(struct name_server **ns_list, struct name_server *orig_ns_list);
void free_name_server (struct name_server **ns);
void free_name_servers (struct name_server **ns);


#endif /* RESOLVER_H */
