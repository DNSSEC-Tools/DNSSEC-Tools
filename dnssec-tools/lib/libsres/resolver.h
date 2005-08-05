
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

#ifdef MEMORY_DEBUGGING
#define MALLOC(s) my_malloc(s, __FILE__, __LINE__)
#define FREE(p) my_free(p,__FILE__,__LINE__)
#define STRDUP(p) my_strdup(p,__FILE__,__LINE__)
#else
#define MALLOC(s) malloc(s)
#define FREE(p) free(p)
#define STRDUP(p) strdup(p)
#endif

#ifndef RES_USE_DNSSEC
#define RES_USE_DNSSEC  0x00200000
#endif

#ifndef MAXDNAME
#define MAXDNAME    256
#endif                

#define ZONE_USE_NOTHING        0x00000000
#define ZONE_USE_TSIG           0x00000001

/* Credibility values of an RRset - from DNSIND-Clarify */
#define SR_CRED_UNSET            0
#define SR_CRED_FILE             1 /* From locally trusted file */
/* Data is from an authoritative server */
#define SR_CRED_AUTH_ANS         3
#define SR_CRED_AUTH_AUTH        4
/* Data is from a cache somewhere, or was at best an after thought */
#define SR_CRED_NONAUTH_ANS      6
#define SR_CRED_AUTH_ADD         7
#define SR_CRED_NONAUTH_AUTH         7
#define SR_CRED_NONAUTH_ADD      7

                                                                                                                          
/* Section values of an RRset */
#define SR_FROM_UNSET            0
#define SR_FROM_QUERY            1
#define SR_FROM_ANSWER           2
#define SR_FROM_AUTHORITY        3
#define SR_FROM_ADDITIONAL       4 

/* Kinds of answers */
#define SR_ANS_UNSET             0
#define SR_ANS_STRAIGHT          1
#define SR_ANS_CNAME             2
#define SR_ANS_NACK_NXT          3
#define SR_ANS_NACK_SOA          4


/* The data arrived covered by a transaction sig */
#define SR_TSIG_PROTECTED       20
#define SR_TSIG_PROTECTED_ANSWER    SR_TSIG_PROTECTED + SR_ANS_STRAIGHT
#define SR_TSIG_PROTECTED_CNAME     SR_TSIG_PROTECTED + SR_ANS_CNAME
#define SR_TSIG_PROTECTED_NXT       SR_TSIG_PROTECTED + SR_ANS_NACK_NXT
#define SR_TSIG_PROTECTED_SOA       SR_TSIG_PROTECTED + SR_ANS_NACK_SOA

#define SR_WRONG 35
 
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
#define ns_t_ds	43	
#endif

/* Resolver errors */
#define NO_DATA_IN_ANSWER   XX // no data for type
#define LAME_DELEGATION XX
#define ANSWER_REFUSED  XX // Generic header error
#define NO_GLUE XX
#define GLUE_MISMATCH   XX
#define DUPLICATE_RR    XX

#define SR_UNSET    0
#define SR_NULLPTR_ERROR    2
#define SR_CALL_ERROR   3
#define SR_INITIALIZATION_ERROR      4
#define SR_HEADER_ERROR 5
#define SR_TSIG_ERROR   6
#define SR_MEMORY_ERROR     7
#define SR_INTERNAL_ERROR   8
#define SR_MESSAGE_ERROR         9
#define SR_DATA_MISSING_ERROR       10
#define SR_REFERRAL_ERROR       11
#define SR_NO_ANSWER    12
#define SR_EMPTY_NXDOMAIN       60
/* Unstable states (i.e., used internally only) */
#define SR_DATA_UNCHECKED       66
#define SR_PROCESS_ERROR    -9



struct name_server
{
    u_int8_t        *ns_name_n;
    void            *ns_tsig_key;
    u_int32_t       ns_security_options;
    u_int32_t       ns_status;
    struct name_server  *ns_next;
    int         ns_number_of_addresses;
    struct sockaddr     ns_address[1];
};

/* Structures used in the interface */
                                                                                                                          
struct rr_rec
{
    u_int16_t       rr_rdata_length_h;  /* RDATA length */
    u_int8_t        *rr_rdata;      /* Raw RDATA */
	int				status;
    struct rr_rec       *rr_next;
};
                                                                                                                          
struct rrset_rec
{
    u_int8_t        *rrs_name_n;    /* Owner */
    u_int16_t       rrs_type_h; /* ns_t_... */
    u_int16_t       rrs_class_h;    /* ns_c_... */
    u_int32_t       rrs_ttl_h;  /* Received ttl */
    u_int8_t        rrs_cred;   /* SR_CRED_... */
    u_int8_t        rrs_status; /* SR_anything else */
    u_int8_t        rrs_section;    /* SR_FROM_... */
    u_int8_t        rrs_ans_kind;   /* SR_ANS_... */
    struct rr_rec       *rrs_data;  /* All data RR's */
    struct rr_rec       *rrs_sig;   /* All signatures */
    struct rrset_rec    *rrs_next;
};

struct qname_chain
{
    u_int8_t        qc_name_n[MAXDNAME];
    struct qname_chain  *qc_next;
};

struct domain_info
{
    char          *di_requested_name_h;
    u_int16_t       di_requested_type_h;
    u_int16_t       di_requested_class_h;
    struct  rrset_rec   *di_rrset;
    struct qname_chain  *di_qnames;
    char            *di_error_message;
};

struct res_policy {
	struct name_server *ns;
};


/* Interfaces to the resolver */
int get (   const char      *name_n,
            const u_int16_t     type_h,
            const u_int16_t     class_h,
            struct res_policy   *respol,
            struct name_server  **server,
            u_int8_t            **response,
            u_int32_t           *response_length,
            char                **error_msg);
void print_response (u_int8_t *ans, int resplen);


#endif /* RESOLVER_H */
