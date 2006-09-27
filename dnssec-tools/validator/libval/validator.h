
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VALIDATOR_H
#define VALIDATOR_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <syslog.h>
#include <val_errors.h>

#include <arpa/nameser.h>
#include <netdb.h>


#if !defined(NS_INT16SZ) && defined(INT16SZ)
#define NS_INT16SZ INT16SZ
#define NS_INT32SZ INT32SZ
#endif

#define VAL_GET16(s, cp) do { \
        register const u_char *t_cp = (const u_char *)(cp); \
        (s) = ((u_int16_t)t_cp[0] << 8) \
            | ((u_int16_t)t_cp[1]) \
            ; \
        (cp) += NS_INT16SZ; \
} while (0)

#define VAL_GET32(l, cp) do { \
        register const u_char *t_cp = (const u_char *)(cp); \
        (l) = ((u_int32_t)t_cp[0] << 24) \
            | ((u_int32_t)t_cp[1] << 16) \
            | ((u_int32_t)t_cp[2] << 8) \
            | ((u_int32_t)t_cp[3]) \
            ; \
        (cp) += NS_INT32SZ; \
} while (0)

#if !defined(NS_PUT16) && defined(PUTSHORT)
#define NS_PUT16 PUTSHORT
#define NS_PUT32 PUTLONG
#endif


#ifdef MEMORY_DEBUGGING
#define MALLOC(s) my_malloc(s, __FILE__, __LINE__)
#define FREE(p) my_free(p,__FILE__,__LINE__)
#define STRDUP(p) my_strdup(p,__FILE__,__LINE__)
#else
#define MALLOC(s) malloc(s)
#define FREE(p) free(p)
#define STRDUP(p) strdup(p)
#endif

#define DNS_PORT	53
#define VAL_CONFIGURATION_FILE	"/etc/dnsval.conf"
#define RESOLV_CONF             "/etc/resolv.conf"
#define ROOT_HINTS            	"/etc/root.hints"
#define VAL_LOG_OPTIONS LOG_PID

#define VALIDATOR_LOG_PORT 1053
#define VALIDATOR_LOG_SERVER "127.0.0.1"

    /*
     * Query states 
     */
#define Q_INIT	1
#define Q_SENT	2
#define Q_WAIT_FOR_GLUE 3
#define Q_ANSWERED 4
#define Q_ERROR_BASE 5

    /*
     * Credibility values of an RRset - from DNSIND-Clarify 
     */
#define SR_CRED_UNSET            0
#define SR_CRED_FILE             1      /* From locally trusted file */
    /*
     * Data is from an authoritative server 
     */
#define SR_CRED_AUTH_ANS         3
#define SR_CRED_AUTH_AUTH        4
    /*
     * Data is from a cache somewhere, or was at best an after thought 
     */
#define SR_CRED_NONAUTH_ANS      6
#define SR_CRED_AUTH_ADD         7
#define SR_CRED_NONAUTH_AUTH     7
#define SR_CRED_NONAUTH_ADD      7

    /*
     * Kinds of answers 
     */
#define SR_ANS_UNSET             0
#define SR_ANS_STRAIGHT          1
#define SR_ANS_CNAME             2
#define SR_ANS_NACK_NSEC         3
#ifdef LIBVAL_NSEC3
#define SR_ANS_NACK_NSEC3        4
#endif
#define SR_ANS_NACK_SOA          5
#define SR_ANS_BARE_RRSIG        6

    /*
     * Policies associated with Keys 
     */
#define	CANNOT_BE_USED			0x00
#define CAN_SIGN_KEY			0x01
#define CAN_SIGN_ZONE			0x02
#define CAN_SIGN_ZONE_AND_KEY 	CAN_SIGN_KEY|CAN_SIGN_ZONE

#define SIGNBY              18
#define ENVELOPE            10
#define RRSIGLABEL			3
#define TTL					4
#define VAL_CTX_IDLEN       20
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

    /*
     * Algorithm definitions for DS digest 
     */
#define ALG_DS_HASH_SHA1 1

#ifdef LIBVAL_NSEC3
#define ALG_NSEC3_HASH_SHA1 1
#endif

    /*
     * Algorithm definitions for NSEC3 digest 
     */
#ifdef LIBVAL_NSEC3
#define ALG_NSEC_HASH_SHA1 1
#endif

    /*
     * DNSSEC Algorithm definitions 
     */
#define ALG_RSAMD5  1
#define ALG_DH      2
#define ALG_DSASHA1 3
#define ALG_RSASHA1 5
#ifdef LIBVAL_NSEC3
#define ALG_NSEC3_DSASHA1 131
#define ALG_NSEC3_RSASHA1 133
#endif

    /*
     * Section values of an RRset 
     */
#define VAL_FROM_UNSET            0
#define VAL_FROM_QUERY            1
#define VAL_FROM_ANSWER           2
#define VAL_FROM_AUTHORITY        3
#define VAL_FROM_ADDITIONAL       4


    /*
     * Flags for API functions 
     */
#define VAL_QUERY_MERGE_RRSETS 0x01

    /*
     * policies are defined for the following
     */

#define P_TRUST_ANCHOR				0
#define P_PREFERRED_SEP				1
#define P_MUST_VERIFY_COUNT			2
#define P_PREFERRED_ALGO_DATA		3
#define P_PREFERRED_ALGO_KEYS		4
#define P_PREFERRED_ALGO_DS			5
#define P_CLOCK_SKEW				6
#define	P_EXPIRED_SIGS				7
#define P_USE_TCP					8
#define P_ZONE_SECURITY_EXPECTATION 9
#define MAX_POL_TOKEN	 			10

#ifdef LIBVAL_NSEC3
#define P_NSEC3_MAX_ITER            10
#undef  MAX_POL_TOKEN
#define MAX_POL_TOKEN	 		    11
#endif

#ifdef DLV
#define P_DLV_TRUST_POINTS		    10
#define P_DLV_MAX_VALIDATION_LINKS  11
#undef  MAX_POL_TOKEN
#define MAX_POL_TOKEN	 		    12
#endif

#define RETRIEVE_POLICY(ctx, index, type)	\
			(ctx == NULL) ? NULL : \
                        (!ctx->e_pol[index])? NULL:(type)(ctx->e_pol[index])
#define VAL_R_TRUST_FLAG 0x80
#define SET_RESULT_TRUSTED(status)	status |= VAL_R_TRUST_FLAG
#define SET_MASKED_STATUS(st, new_val) st = (st & VAL_R_TRUST_FLAG) | new_val
#define CHECK_MASKED_STATUS(st, chk_val) ((st & VAL_R_TRUST_FLAG) == chk_val)

    typedef u_int8_t val_status_t;
    typedef u_int16_t val_astatus_t;

    struct val_query_chain;     /* forward declaration */
    struct _val_authentication_chain;    /* forward declaration */


#define policy_entry_t void*
    /*
     * The above is a generic data type for a policy entry
     * typecasted to one of the types defined in val_policy.h: 
     */

    /*
     * Response structures  
     */
    struct rr_rec {
        u_int16_t       rr_rdata_length_h;      /* RDATA length */
        u_int8_t       *rr_rdata;       /* Raw RDATA */
        val_astatus_t   rr_status;
        struct rr_rec  *rr_next;
    };

    struct val_rrset {
        /*
         * Header 
         */
        u_int8_t       *val_msg_header;
        u_int16_t       val_msg_headerlen;

        /*
         * Answer 
         */
        u_int8_t       *val_rrset_name_n;       /* Owner */
        u_int16_t       val_rrset_class_h;      /* ns_c_... */
        u_int16_t       val_rrset_type_h;       /* ns_t_... */
        u_int32_t       val_rrset_ttl_h;        /* Received ttl */
        u_int8_t        val_rrset_section;      /* VAL_FROM_... */
        struct rr_rec  *val_rrset_data; /* All data RR's */
        struct rr_rec  *val_rrset_sig;  /* All signatures */
    };

    struct rrset_rec {
        struct val_rrset rrs;
        u_int8_t       *rrs_zonecut_n;
        struct name_server *rrs_respondent_server;
        u_int8_t        rrs_cred;       /* SR_CRED_... */
        u_int8_t        rrs_ans_kind;   /* SR_ANS_... */
        struct rrset_rec *rrs_next;
    };

    struct policy_list {
        int             index;
        policy_entry_t  pol;
        struct policy_list *next;
    };

    /*
     * This list is ordered from general to more specific --
     * so "mozilla" < "sendmail" < "browser:mozilla"
     */
    struct policy_overrides {
        char           *label;
        int             label_count;
        struct policy_list *plist;
        struct policy_overrides *next;
    };

    typedef struct val_context {

        char            id[VAL_CTX_IDLEN];

        /*
         * resolver policy 
         */
        struct name_server *nslist;

        /*
         * validator policy 
         */
        policy_entry_t  e_pol[MAX_POL_TOKEN];
        struct policy_overrides *pol_overrides;
        struct policy_overrides *cur_override;

        /*
         * caches 
         */
        struct _val_authentication_chain *a_list;
        struct val_query_chain *q_list;

        //XXX Needs a lock variable here

    } val_context_t;


    struct val_rrset_digested {
        struct rrset_rec *ac_data;
        struct val_query_chain *ac_pending_query;
        struct _val_authentication_chain *val_ac_rrset_next;
        struct _val_authentication_chain *val_ac_next;
    };

    struct _val_authentication_chain {
        val_astatus_t   val_ac_status;
        union {
            struct val_rrset *val_ac_rrset;
            struct val_rrset_digested _as;
        };
        struct _val_authentication_chain *val_ac_trust;
    };


    struct query_list {
        u_int8_t        ql_name_n[NS_MAXCDNAME];
        u_int8_t        ql_zone_n[NS_MAXCDNAME];
        u_int16_t       ql_type_h;
        struct query_list *ql_next;
    };

    struct qname_chain {
        u_int8_t        qnc_name_n[NS_MAXCDNAME];
        struct qname_chain *qnc_next;
    };

    struct delegation_info {
        struct query_list *queries;
        struct qname_chain *qnames;
        struct name_server *pending_glue_ns;
        struct val_query_chain *glueptr;
    };

    struct val_query_chain {
        u_char          qc_name_n[NS_MAXCDNAME];
        u_int16_t       qc_type_h;
        u_int16_t       qc_class_h;
        u_int16_t       qc_state;       /* DOS, TIMED_OUT, etc */
        struct name_server *qc_ns_list;
        struct name_server *qc_respondent_server;
        u_int8_t       *qc_zonecut_n;
        struct delegation_info *qc_referral;
        int             qc_trans_id;
        struct _val_authentication_chain *qc_as;
        int             qc_glue_request;
        struct val_query_chain *qc_next;
    };

    struct val_response {
        unsigned char  *vr_response;
        int             vr_length;
        val_status_t    vr_val_status;
        struct val_response *vr_next;
    };

    struct domain_info {
        char           *di_requested_name_h;
        u_int16_t       di_requested_type_h;
        u_int16_t       di_requested_class_h;
        struct rrset_rec *di_rrset;
        struct qname_chain *di_qnames;
        int             di_res_error;
    };

    struct val_authentication_chain {
        val_astatus_t   val_ac_status;
        struct val_rrset *val_ac_rrset;
        struct val_authentication_chain *val_ac_trust;
    };

    struct val_result_chain {
        val_status_t    val_rc_status;
        struct val_authentication_chain *val_rc_trust;
        struct val_result_chain *val_rc_next;
    };

    struct _val_result_chain {
        val_status_t    val_rc_status;
        struct _val_authentication_chain *val_rc_trust;
        struct _val_result_chain *val_rc_next;
    };

    typedef struct val_dnskey_rdata {
        u_int16_t       flags;
        u_int8_t        protocol;
        u_int8_t        algorithm;
        u_int32_t       public_key_len; /* in bytes */
        u_char         *public_key;
        u_int16_t       key_tag;
        struct val_dnskey_rdata *next;
    } val_dnskey_rdata_t;

    typedef struct val_rrsig_rdata {
        u_int16_t       type_covered;
        u_int8_t        algorithm;
        u_int8_t        labels;
        u_int32_t       orig_ttl;
        u_int32_t       sig_expr;
        u_int32_t       sig_incp;
        u_int16_t       key_tag;
        u_char          signer_name[256];       /* null terminated */
        u_int32_t       signature_len;  /* in bytes */
        u_char         *signature;
        struct val_rrsig_rdata *next;
    } val_rrsig_rdata_t;

    typedef struct val_ds_rdata {
        u_int16_t       d_keytag;
        u_int8_t        d_algo;
        u_int8_t        d_type;
        u_int8_t       *d_hash;
        u_int32_t       d_hash_len;
    } val_ds_rdata_t;

#ifdef LIBVAL_NSEC3
    typedef struct val_nsec3_rdata {
        u_int8_t        alg;
        u_int8_t        optout;
        u_int32_t       iterations;
        u_int8_t        saltlen;
        u_int8_t       *salt;
        u_int8_t        nexthashlen;
        u_int8_t       *nexthash;
        u_int16_t       bit_field;
    } val_nsec3_rdata_t;
#endif

    /*
     **********************************
     * APIs exported by the validator
     **********************************
     */
    /*
     * from val_assertion.h 
     */
    int             val_istrusted(val_status_t val_status);
    void            val_free_result_chain(struct val_result_chain
                                          *results);
    int             val_resolve_and_check(val_context_t * context,
                                          u_char * domain_name,
                                          const u_int16_t q_class,
                                          const u_int16_t type,
                                          const u_int8_t flags,
                                          struct val_result_chain
                                          **results);

    /*
     * Flags for val_resolve_and_check 
     */
#define F_DEFAULT 0x00000000
#define F_DONT_VALIDATE 0x00000001

    /*
     * from val_context.h 
     */
    int             val_create_context(char *label,
                                       val_context_t ** newcontext);
    void            val_free_context(val_context_t * context);
    int             val_switch_policy_scope(val_context_t * ctx,
                                            char *label);

    /*
     * from val_policy.c 
     */
    char           *resolver_config_get(void);
    int             resolver_config_set(const char *name);
    char           *root_hints_get(void);
    int             root_hints_set(const char *name);
    char           *dnsval_conf_get(void);
    int             dnsval_conf_set(const char *name);

    /*
     * from val_log.h 
     */
    void            val_log_authentication_chain(const val_context_t * ctx,
                                                 int level,
                                                 u_char * name_n,
                                                 u_int16_t class_h,
                                                 u_int16_t type_h,
                                                 struct val_query_chain
                                                 *queries, struct val_result_chain
                                                 *results);
    const char     *p_query_error(int err);
    const char     *p_as_error(val_astatus_t valerrno);
    const char     *p_val_error(val_status_t err);

    /*
     * from val_x_query.c 
     */
    int             val_query(val_context_t * ctx,
                              const char *domain_name,
                              const u_int16_t q_class,
                              const u_int16_t type,
                              const u_int8_t flags,
                              struct val_response **resp);
    int             val_free_response(struct val_response *resp);
    int             val_res_query(val_context_t * ctx, const char *dname,
                                  int q_class, int type, u_char * answer,
                                  int anslen, val_status_t * val_status);

    /*
     * from val_gethostbyname.c 
     */
#ifndef h_errno                 /* on linux, netdb.h defines this as a macro */
    extern int      h_errno;
#endif
    struct hostent *val_gethostbyname(val_context_t * ctx,
                                      const char *name,
                                      val_status_t * val_status);

    int             val_gethostbyname_r(val_context_t * ctx,
                                        const char *name,
                                        struct hostent *ret,
                                        char *buf,
                                        size_t buflen,
                                        struct hostent **result,
                                        int *h_errnop,
                                        val_status_t * val_status);

    struct hostent *val_gethostbyname2(val_context_t * ctx,
                                       const char *name,
                                       int af, val_status_t * val_status);

    int             val_gethostbyname2_r(val_context_t * ctx,
                                         const char *name,
                                         int af,
                                         struct hostent *ret,
                                         char *buf,
                                         size_t buflen,
                                         struct hostent **result,
                                         int *h_errnop,
                                         val_status_t * val_status);

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
        val_status_t    ai_val_status;
    };

    int             val_getaddrinfo(val_context_t * ctx,
                                    const char *nodename,
                                    const char *servname,
                                    const struct addrinfo *hints,
                                    struct val_addrinfo **res);

    void            free_val_addrinfo(struct val_addrinfo *ainfo);

/***********************************************************/
#if 0
    struct hostent *val_gethostbyaddr(const val_context_t * ctx,
                                      const char *addr,
                                      int len,
                                      int type, val_status_t * val_status);

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

    int             val_getnameinfo(const val_context_t * ctx,
                                    const struct sockaddr *sa,
                                    socklen_t salen,
                                    char *host,
                                    size_t hostlen,
                                    char *serv,
                                    size_t servlen,
                                    int flags, val_status_t * val_status);

#endif
/***********************************************************/

#ifdef __cplusplus
}                               /* extern "C" */
#endif
#endif                          /* VALIDATOR_H */
