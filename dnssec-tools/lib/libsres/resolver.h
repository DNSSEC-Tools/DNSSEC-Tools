
/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
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


 
#define EDNS_UDP_SIZE 512 
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
    char            *di_requested_name_h;
    u_int16_t       di_requested_type_h;
    u_int16_t       di_requested_class_h;
    struct  rrset_rec   *di_rrset;
    struct qname_chain  *di_qnames;
    char            *di_error_message;
};

struct res_policy {
	struct name_server *ns;
};


#endif /* RESOLVER_H */
