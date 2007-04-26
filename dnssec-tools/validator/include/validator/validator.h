
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VALIDATOR_H
#define VALIDATOR_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <validator/val_errors.h>

#include <arpa/nameser.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>

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

#define DNS_PORT                53
#define VAL_LOG_OPTIONS LOG_PID

#define VALIDATOR_LOG_PORT 1053
#define VALIDATOR_LOG_SERVER "127.0.0.1"

    /*
     * Query states 
     */
#define Q_INIT          1
#define Q_SENT          2
#define Q_WAIT_FOR_GLUE 3
#define Q_ANSWERED      4
#define Q_ERROR_BASE    5

#define QUERY_BAD_CACHE_THRESHOLD 5
#define QUERY_BAD_CACHE_TTL 3600

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
#define SR_ANS_DNAME             3
#define SR_ANS_NACK_NSEC         4
#define SR_ANS_NACK_SOA          5
#define SR_ANS_BARE_RRSIG        6
#ifdef LIBVAL_NSEC3
#define SR_ANS_NACK_NSEC3        7
#endif

    /*
     * Policies associated with Keys 
     */
#define CANNOT_BE_USED                  0x00
#define CAN_SIGN_KEY                    0x01
#define CAN_SIGN_ZONE                   0x02
#define CAN_SIGN_ZONE_AND_KEY   CAN_SIGN_KEY|CAN_SIGN_ZONE

#define SIGNBY              18
#define ENVELOPE            10
#define RRSIGLABEL           3
#define TTL                  4
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
     * query flags in the lower nibble
     */
#define VAL_QFLAGS_USERMASK 0x0f
#define VAL_QUERY_DONT_VALIDATE 0x01
#define VAL_QUERY_MERGE_RRSETS 0x02
#ifdef LIBVAL_DLV
#define VAL_QUERY_NO_DLV 0x04 
#endif

    /*  
     * Internal query state in the upper nibble 
     */
#define VAL_QUERY_GLUE_REQUEST (0x10 | VAL_QUERY_DONT_VALIDATE) 
#ifdef LIBVAL_DLV
#define VAL_QUERY_USING_DLV 0x20 
#endif

#define VAL_QFLAGS_AFFECTS_CACHING (0xf0 | VAL_QUERY_DONT_VALIDATE) 


#define MAX_ALIAS_CHAIN_LENGTH 10       /* max length of cname/dname chain */
#define MAX_GLUE_FETCH_DEPTH 10         /* max length of glue dependency chain */

    typedef u_int8_t val_status_t;
    typedef u_int16_t val_astatus_t;

    struct val_query_chain;     /* forward declaration */
    struct val_digested_auth_chain;     /* forward declaration */
    struct val_log;             /* forward declaration */

    typedef struct policy_glob {
        u_int8_t        zone_n[NS_MAXCDNAME];
        long            exp_ttl;
        void *          pol;
        struct policy_glob *next;
    } policy_entry_t;
    
    /*
     * The above is a generic data type for a policy entry
     * typecasted to one of the types defined in val_policy.h: 
     * Policies can be one of the following
     */

#define POL_TRUST_ANCHOR_STR "trust-anchor"
#define POL_PREFERRED_SEP_STR "preferred-sep"
#define POL_MUST_VERIFY_COUNT_STR "must-verify-count"
#define POL_PREFERRED_ALGORITHM_DATA_STR "preferred-algo-data"
#define POL_PREFERRED_ALGORITHM_KEYS_STR "preferred-algo-keys"
#define POL_PREFERRED_ALGORITHM_DS_STR "preferred-algo-ds"
#define POL_CLOCK_SKEW_STR "clock-skew"
#define POL_USE_TCP_STR "use-tcp"
#define POL_PROV_UNSEC_STR "provably-unsecure-status"
#define POL_ZONE_SE_STR "zone-security-expectation"
#ifdef LIBVAL_DLV
#define POL_DLV_TRUST_POINTS_STR  "dlv-trust-points"
#endif
#ifdef LIBVAL_NSEC3
#define POL_NSEC3_MAX_ITER_STR "nsec3-max-iter"
#endif

#define ZONE_PU_TRUSTED_MSG "trusted"
#define ZONE_PU_UNTRUSTED_MSG "untrusted"
#define ZONE_SE_IGNORE_MSG     "ignore"
#define ZONE_SE_TRUSTED_MSG    "trusted"
#define ZONE_SE_DO_VAL_MSG     "validate"
#define ZONE_SE_UNTRUSTED_MSG  "untrusted"

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
        u_int32_t       val_rrset_ttl_x;        /* ttl expire time */
        u_int8_t        val_rrset_section;      /* VAL_FROM_... */
        struct sockaddr *val_rrset_server;      /* respondent server */
        struct rr_rec  *val_rrset_data; /* All data RR's */
        struct rr_rec  *val_rrset_sig;  /* All signatures */
    };

    struct rrset_rec {
        struct val_rrset rrs;
        u_int8_t       *rrs_zonecut_n;
        u_int8_t        rrs_cred;       /* SR_CRED_... */
        u_int8_t        rrs_ans_kind;   /* SR_ANS_... */
        struct rrset_rec *rrs_next;
    };

    struct policy_list {
        int             index;
        policy_entry_t  *pol;
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

#ifndef VAL_NO_THREADS
        /*
         * The read-write locks ensure that validator
         * policy is modified only when there is no
         * "active" val_resolve_and_check() call
         */
        pthread_rwlock_t respol_rwlock;
        pthread_rwlock_t valpol_rwlock;
        /*
         * The mutex lock ensures that changes to the 
         * context cache can only be made by one thread
         * at any given time
         */
        pthread_mutex_t ac_lock;
#endif
        
        char            id[VAL_CTX_IDLEN];
        char            *label;
        char            *dnsval_conf;
        char            *resolv_conf;
        char            *root_conf;

        /*
         * root_hints
         */
        time_t h_timestamp;
        struct name_server *root_ns;

        /*
         * default name server 
         */
        time_t r_timestamp;
        struct name_server *nslist;
        char               *search;
        
        /*
         * validator policy 
         */
        time_t v_timestamp;
        policy_entry_t **e_pol;
        
        /* Query and authentication chain caches */
        struct val_digested_auth_chain *a_list;
        struct val_query_chain *q_list;
    } val_context_t; 

    struct val_rrset_digested {
        struct rrset_rec *ac_data;
        struct val_digested_auth_chain *val_ac_rrset_next;
        struct val_digested_auth_chain *val_ac_next;
    };

    struct val_digested_auth_chain {
        val_astatus_t   val_ac_status;
        union {
            struct val_rrset *val_ac_rrset;
            struct val_rrset_digested _as;
        };
        struct val_query_chain *val_ac_query;
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
        struct rrset_rec *answers;
        struct name_server *pending_glue_ns;
        struct name_server *merged_glue_ns;
        struct rrset_rec *learned_zones;
    };

    struct val_query_chain {
#ifndef VAL_NO_THREADS
        /*
         * The read-write lock ensures that
         * queries are not deleted from the cache while
         * they are still being accessed by some thread 
         */
        pthread_rwlock_t qc_rwlock;
#endif
        u_char          qc_name_n[NS_MAXCDNAME];
        u_char          qc_original_name[NS_MAXCDNAME];
        u_int16_t       qc_type_h;
        u_int16_t       qc_class_h;

        u_int16_t       qc_state;       /* DOS, TIMED_OUT, etc */
        u_int8_t        qc_flags;
        u_int32_t       qc_ttl_x;    /* ttl expiry time */
        int             qc_bad; /* contains "bad" data */
        u_int8_t       *qc_zonecut_n;

        struct delegation_info *qc_referral;
        struct name_server *qc_ns_list;
        struct name_server *qc_respondent_server;
        int    qc_trans_id;

        struct val_digested_auth_chain *qc_ans;
        struct val_digested_auth_chain *qc_proof;
        struct val_query_chain *qc_next;
    };

    struct queries_for_query {
        u_int8_t qfq_flags;
        struct val_query_chain *qfq_query;
        struct queries_for_query *qfq_next;
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
        struct rrset_rec *di_answers;
        struct rrset_rec *di_proofs;
        struct qname_chain *di_qnames;
        int             di_res_error;
    };

    struct val_authentication_chain {
        val_astatus_t   val_ac_status;
        struct val_rrset *val_ac_rrset;
        struct val_authentication_chain *val_ac_trust;
    };

#define MAX_PROOFS 4
    struct val_result_chain {
        val_status_t    val_rc_status;
        struct val_authentication_chain *val_rc_answer;
        int             val_rc_proof_count;
        struct val_authentication_chain *val_rc_proofs[MAX_PROOFS];
        struct val_result_chain *val_rc_next;
    };

    struct val_internal_result {
        val_status_t    val_rc_status;
        int             val_rc_is_proof;
        int             val_rc_consumed;
        u_int8_t        val_rc_flags;
        struct val_digested_auth_chain *val_rc_rrset;
        struct val_internal_result *val_rc_next;
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
        u_int8_t        flags;
        u_int16_t       iterations;
        u_int8_t        saltlen;
        u_int8_t       *salt;
        u_int8_t        nexthashlen;
        u_int8_t       *nexthash;
        u_int16_t       bit_field;
    } val_nsec3_rdata_t;

#define NSEC3_FLAG_OPTOUT 0x01

#endif

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

    /*
     * Logging-related definitions 
     */
    typedef void    (*val_log_logger_t) (struct val_log * logp,
                                         const val_context_t * ctx,
                                         int level,
                                         const char *template, va_list ap);
    typedef void    (*val_log_cb_t) (struct val_log *logp, int level,
                                     const char *buf);

    typedef struct val_log {
        val_log_logger_t logf;  /* log function ptr */
        unsigned char   level;  /* 0 - 9, corresponds w/sylog severities */
        unsigned char   lflags; /* generic log flags */

        void           *a_void; /* logger dependent */

        union {
            struct {
                int             sock;
                struct sockaddr_in server;
            } udp;
            struct {
                char           *name;
                FILE           *fp;
            } file;
            struct {
                int             facility;
            } syslog;
            struct {
                val_log_cb_t    func;
            } cb;
            struct {
                void           *my_ptr;
            } user;
        } opt;
        struct val_log *next;
    } val_log_t;

    char           *get_hex_string(const unsigned char *data, int datalen,
                                   char *buf, int buflen);
    void            val_log_rrset(const val_context_t * ctx, int level,
                                  struct rrset_rec *rrset);
    void            val_log_base64(val_context_t * ctx, int level,
                                   unsigned char *message,
                                   int message_len);
    void            val_log_rrsig_rdata(const val_context_t * ctx,
                                        int level, const char *prefix,
                                        val_rrsig_rdata_t * rdata);
    void            val_log_dnskey_rdata(val_context_t * ctx, int level,
                                         const char *prefix,
                                         val_dnskey_rdata_t * rdata);
    void            val_log_authentication_chain(const val_context_t * ctx,
                                                 int level,
                                                 u_char * name_n,
                                                 u_int16_t class_h,
                                                 u_int16_t type_h,
                                                 struct val_result_chain
                                                 *results);
    void            val_log(const val_context_t * ctx, int level,
                            const char *template, ...);

    val_log_t      *val_log_add_cb(int level, val_log_cb_t func);
    val_log_t      *val_log_add_filep(int level, FILE * p);
    val_log_t      *val_log_add_file(int level, const char *filen);
    val_log_t      *val_log_add_syslog(int level, int facility);
    val_log_t      *val_log_add_network(int level, char *host, int port);
    val_log_t      *val_log_add_optarg(const char *args, int use_stderr);

    int             val_log_debug_level(void);
    void            val_log_set_debug_level(int);
    const char     *val_get_ns_string(struct sockaddr *serv, char *dst,
                                      int size);


    const char     *p_ac_status(val_astatus_t valerrno);
    const char     *p_val_status(val_status_t err);

    /*
     *******************************************
     * Other functions exported by the validator
     *******************************************
     */
    /*
     * from val_assertion.h 
     */
    int             val_istrusted(val_status_t val_status);
    int             val_isvalidated(val_status_t val_status);
    int             val_does_not_exist(val_status_t status); 
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
     * from val_context.h 
     */
    int             val_create_context_with_conf(char *label,
                                                 char *dnsval_conf,
                                                 char *resolv_conf,
                                                 char *root_conf,
                                                 val_context_t ** newcontext);
    int             val_create_context(char *label,
                                       val_context_t ** newcontext);
    void            val_free_context(val_context_t * context);
    int             free_validator_state(void);

    /*
     * from val_policy.h 
     */
    char           *resolv_conf_get(void);
    int             resolv_conf_set(const char *name);
    char           *root_hints_get(void);
    int             root_hints_set(const char *name);
    char           *dnsval_conf_get(void);
    int             dnsval_conf_set(const char *name);
    int             val_add_valpolicy(val_context_t *ctx, char *keyword, char *zone,
                                      char *value, long ttl);

    /*
     * from val_support.h 
     */
    u_int16_t       wire_name_length(const u_int8_t * field);

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
    int             val_res_search(val_context_t * ctx, const char *dname,
                                   int class_h, int type, u_char * answer,
                                   int anslen, val_status_t * val_status);
    int             compose_answer(const u_char * name_n,
                                   const u_int16_t type_h,
                                   const u_int16_t class_h,
                                   struct val_result_chain *results,
                                   struct val_response **f_resp,
                                   u_int8_t flags);
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
    int             val_getaddrinfo(val_context_t * ctx,
                                    const char *nodename,
                                    const char *servname,
                                    const struct addrinfo *hints,
                                    struct val_addrinfo **res,
                                    val_status_t * val_status);

    void            val_freeaddrinfo(struct val_addrinfo *ainfo);

    int             val_getnameinfo(val_context_t * ctx,
                                    const struct sockaddr *sa,
                                    socklen_t salen,
                                    char *host,
                                    size_t hostlen,
                                    char *serv,
                                    size_t servlen,
                                    int flags, val_status_t * val_status);

    /*
     * A thread-safe, re-entrant version of val_gethostbyaddr 
     */
    int             val_gethostbyaddr_r(val_context_t * ctx,
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
     * A old version of gethostbyaddr for use with validator
     */
    struct hostent *val_gethostbyaddr(val_context_t * ctx,
                                      const char *addr,
                                      int len,
                                      int type, val_status_t * val_status);


    /*
     * for backwards compatibility
     */
#define free_val_addrinfo   val_freeaddrinfo
#define p_val_error p_val_status
#define p_as_error p_ac_status

#ifdef __cplusplus
}                               /* extern "C" */
#endif
#endif                          /* VALIDATOR_H */
