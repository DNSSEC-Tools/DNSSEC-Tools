
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
 * Copyright 2005-2008 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef RESOLVER_H
#define RESOLVER_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

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

#ifndef NS_MAXDNAME
#define NS_MAXDNAME 1025        /* maximum domain name */
#endif
#ifndef NS_MAXCDNAME
#define NS_MAXCDNAME    255     /* maximum compressed domain name */
#endif

/** START:some missing macros on OpenBSD 3.9 */
#ifndef NS_CMPRSFLGS
#define NS_CMPRSFLGS   0xc0
#endif
#if !defined(NS_MAXCDNAME) && defined (MAXCDNAME)
#define NS_MAXCDNAME MAXCDNAME
#endif
#if !defined(NS_INT16SZ) && defined(INT16SZ)
#define NS_INT16SZ INT16SZ
#define NS_INT32SZ INT32SZ
#endif
/** END:some missing macros on OpenBSD 3.9 */

#define ZONE_USE_NOTHING        0x00000000
#define ZONE_USE_TSIG           0x00000001


#define SR_ZI_STATUS_UNSET      0
#define SR_ZI_STATUS_PERMANENT      1
#define SR_ZI_STATUS_LEARNED        2


#define DNAME_MAX     1024

#ifndef ns_t_dnskey
#define ns_t_dnskey   48
#endif
#ifndef ns_t_rrsig
#define ns_t_rrsig    46
#endif
#ifndef ns_t_nsec
#define ns_t_nsec     47
#endif

#ifdef LIBVAL_NSEC3
#ifndef ns_t_nsec3
#define ns_t_nsec3   50
#endif
#endif

#ifdef LIBVAL_DLV
#ifndef ns_t_dlv
#define ns_t_dlv 32769
#endif
#endif

#ifndef ns_t_ds
#define ns_t_ds       43
#endif

/* query types for which edns0 is required */
#ifdef LIBVAL_DLV
#define DNSSEC_METADATA_QTYPE(type) \
    ((type == ns_t_rrsig || type == ns_t_dnskey || type == ns_t_ds || type == ns_t_dlv))
#else
#define DNSSEC_METADATA_QTYPE(type) \
    ((type == ns_t_rrsig || type == ns_t_dnskey || type == ns_t_ds))
#endif

/*
 * Resolver errors 
 */
#define SR_UNSET    0

#define SR_INTERNAL_ERROR         1
#define SR_CALL_ERROR             SR_INTERNAL_ERROR
#define SR_MEMORY_ERROR           SR_INTERNAL_ERROR
#define SR_MKQUERY_INTERNAL_ERROR SR_INTERNAL_ERROR
#define SR_TSIG_INTERNAL_ERROR    SR_INTERNAL_ERROR
#define SR_SEND_INTERNAL_ERROR    SR_INTERNAL_ERROR
#define SR_RCV_INTERNAL_ERROR     SR_INTERNAL_ERROR

#define SR_TSIG_ERROR             2
#define SR_NO_ANSWER              3     /* No answer received */
#define SR_NO_ANSWER_YET          4     /* No answer as yet, but this value will change */
#define SR_HEADER_ERROR           5     /* some inconsistency in the DNS response header */
#define SR_DNS_GENERIC_ERROR      6     /*Look at RCODE */
#define SR_EDNS_VERSION_ERROR     7
#define SR_UNSUPP_EDNS0_LABEL     8
#define SR_NAME_EXPANSION_FAILURE 9 
#define SR_NXDOMAIN               10    /*RCODE set to NXDOMAIN w/o appropriate records */
#define SR_FORMERR                11    /*RCODE set to FORMERR */
#define SR_SERVFAIL               12    /*RCODE set to SERVFAIL */
#define SR_NOTIMPL                13    /*RCODE set to NOTIMPL */
#define SR_REFUSED                14    /*RCODE set to REFUSED */

struct name_server {
    u_char          ns_name_n[NS_MAXCDNAME];
    void           *ns_tsig;
    u_int32_t       ns_security_options;
    u_int32_t       ns_status;
    u_long          ns_options;
    int             ns_retrans;
    int             ns_retry;

    struct name_server *ns_next;

    /*
     * NOTE: ns_address MUST be last element
     */
    int             ns_number_of_addresses;
    struct sockaddr_storage **ns_address;
    /*
     * DO NOT ADD MEMBERS BELOW ns_addresses
     */
};


/*
 * Interfaces to the resolver 
 */
int             query_send(const char *name,
                           const u_int16_t type_h,
                           const u_int16_t class_h,
                           struct name_server *nslist, 
                           int edns0_size,
                           int *trans_id);
int             response_recv(int *trans_id,
                              fd_set *pending_desc,
                              struct timeval *closest_event,
                              struct name_server **respondent,
                              u_char ** answer, size_t * answer_length);
void            wait_for_res_data(fd_set * pending_desc, 
                                  struct timeval *closest_event);
int             get(const char *name_n,
                    const u_int16_t type_h,
                    const u_int16_t class_h,
                    struct name_server *nslist,
                    int edns0_size,
                    struct name_server **server,
                    u_char ** response, size_t * response_length);
void            print_response(u_char * ans, size_t resplen);
int             clone_ns(struct name_server **cloned_ns,
                         struct name_server *ns);
int             clone_ns_list(struct name_server **ns_list,
                              struct name_server *orig_ns_list);
void            free_name_server(struct name_server **ns);
void            free_name_servers(struct name_server **ns);

#ifndef HAVE_DECL_NS_NTOP
int             ns_name_ntop(const u_char * src, char *dst, size_t dstsiz);
#endif
#ifndef HAVE_DECL_NS_NAME_UNPACK
int             ns_name_unpack(const u_char * msg, const u_char * eom,
                               const u_char * src, u_char * dst,
                               size_t dstsiz);
#endif
#ifndef HAVE_DECL_NS_SAMENAME
int             ns_samename(const char *a, const char *b);
int             ns_samedomain(const char *a, const char *b);
#endif
#ifndef HAVE_DECL_NS_NAME_PTON
int             ns_name_pton(const char *src, u_char * dst, size_t dstsiz);
#endif
#ifndef HAVE_DECL_NS_PARSE_TTL
int             ns_parse_ttl(const char *src, u_long * dst);
#endif

u_int16_t       res_nametoclass(const char *buf, int *successp);
u_int16_t       res_nametotype(const char *buf, int *successp);

#ifndef HAVE_DECL_P_SECTION
const char     *p_section(int section, int opcode);
#endif

const char     *p_class(int class);

#undef p_type
#define p_type(type) p_sres_type(type)
const char     *p_sres_type(int type);

#endif                          /* RESOLVER_H */
