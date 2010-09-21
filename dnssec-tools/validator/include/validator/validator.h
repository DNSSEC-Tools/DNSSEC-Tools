
/*
 * Copyright 2005-2009 SPARTA, Inc.  All rights reserved.
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

/* 
 * XXX FreeBSD no longer defines EAI_NODATA. Need to figure out why 
 * this is so. Following is a temporary fix.
 */
#if !defined(EAI_NODATA) && (EAI_NONAME == 8)
#define EAI_NODATA 7
#endif

/*
 * define error codes for val_getaddrinfo and val_getnameinfo which
 * have a DNSSEC validation status.
 */
#if defined(EAI_NODATA)
#define VAL_GETADDRINFO_HAS_STATUS(rc) ( \
	(rc == 0) || (rc == EAI_NONAME) || (rc == EAI_NODATA))
#else
#define VAL_GETADDRINFO_HAS_STATUS(rc) ((rc == 0) || (rc == EAI_NONAME))
#endif

#define VAL_GETNAMEINFO_HAS_STATUS(rc) VAL_GETADDRINFO_HAS_STATUS(rc)

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

/* various constants */
#define DNS_PORT                53
#define VAL_LOG_OPTIONS LOG_PID
#define VALIDATOR_LOG_PORT 1053
#define VALIDATOR_LOG_SERVER "127.0.0.1"
#define VAL_DEFAULT_RESOLV_CONF "/etc/resolv.conf"
#define VAL_CONTEXT_LABEL "VAL_CONTEXT_LABEL"
#define VAL_LOG_TARGET "VAL_LOG_TARGET"

    /*
     * Query states 
     */
#define Q_INIT          1
#define Q_SENT          2
#define Q_WAIT_FOR_GLUE 3
#define Q_ANSWERED      4
#define Q_ERROR_BASE    5
#define Q_QUERY_ERROR (Q_ERROR_BASE + 0) 
#define Q_RESPONSE_ERROR (Q_ERROR_BASE + 1) 
#define Q_WRONG_ANSWER (Q_ERROR_BASE + 2) 
#define Q_REFERRAL_ERROR (Q_ERROR_BASE + 3) 
#define Q_MISSING_GLUE (Q_ERROR_BASE + 4) 
#define Q_CONFLICTING_ANSWERS (Q_ERROR_BASE + 5) 


#define QUERY_BAD_CACHE_THRESHOLD 5
#define QUERY_BAD_CACHE_TTL 60

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
#define SR_ANS_NACK              4
#define SR_ANS_BARE_RRSIG        5


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
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32 
#endif
#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64 
#endif
#define MAX_DIGEST_LENGTH 64

    /*
     * Algorithm definitions for DS digest 
     */
#define ALG_DS_HASH_SHA1 1
#define ALG_DS_HASH_SHA256 2

    /*
     * Algorithm definitions for NSEC3 digest 
     */
#ifdef LIBVAL_NSEC3
#define ALG_NSEC3_HASH_SHA1 1
#endif

    /*
     * DNSSEC Algorithm definitions 
     */
#define ALG_RSAMD5  1
#define ALG_DH      2
#define ALG_DSASHA1 3
#define ALG_RSASHA1 5
#ifdef LIBVAL_NSEC3
#define ALG_NSEC3_DSASHA1 6 
#define ALG_NSEC3_RSASHA1 7 
#endif
#define ALG_RSASHA256 8
#define ALG_RSASHA512 10 
    /*
     * Section values of an RRset 
     */
#define VAL_FROM_UNSET            0
#define VAL_FROM_ANSWER           1
#define VAL_FROM_AUTHORITY        2
#define VAL_FROM_ADDITIONAL       3
#define VAL_FROM_QUERY            4

    /*
     * user query flags in the lower two bytes 
     */
#define VAL_QFLAGS_ANY 0xffffffff
#define VAL_QFLAGS_USERMASK 0x0000ffff
#define VAL_QFLAGS_STATE 0xffff0000
#define VAL_QFLAGS_CACHE_MASK   VAL_QFLAGS_USERMASK

#define VAL_QUERY_NO_AC_DETAIL 0x00000001
#define VAL_QUERY_NO_EDNS0 0x00000002
#define VAL_QUERY_DONT_VALIDATE 0x00000004 

    /*  
     * Internal query state in the upper two bytes 
     */
#define VAL_QUERY_GLUE_REQUEST (0x00010000 | VAL_QUERY_DONT_VALIDATE)
#define VAL_QUERY_USING_DLV 0x00020000 
#define VAL_QUERY_NO_DLV 0x00040000 


#define MAX_ALIAS_CHAIN_LENGTH 10       /* max length of cname/dname chain */
#define MAX_GLUE_FETCH_DEPTH 10         /* max length of glue dependency chain */

    typedef u_int8_t val_status_t;
    typedef u_int16_t val_astatus_t;

    struct val_log;             /* forward declaration */
    struct val_context;         /* forward declaration */
    typedef struct val_context val_context_t;

    typedef struct policy_entry {
        u_char        zone_n[NS_MAXCDNAME];
        long            exp_ttl;
        void *          pol;
        struct policy_entry *next;
    } policy_entry_t;
  
    typedef struct global_opt {
        int local_is_trusted;
        long edns0_size;    
        int env_policy;
        int app_policy;
        char *log_target;
    } global_opt_t;

    typedef struct {
        policy_entry_t *pe;
        int index;
    }  val_policy_handle_t;

    typedef struct {
        char *keyword;
        char *zone;
        char *value;
        long ttl;
    } libval_policy_definition_t;

    /*
     * The above is a generic data type for a policy entry
     * typecasted to one of the types defined in val_policy.h: 
     * Policies can be one of the following
     */
#define POL_TRUST_ANCHOR_STR "trust-anchor"
#define POL_CLOCK_SKEW_STR "clock-skew"
#define POL_PROV_INSEC_STR "provably-insecure-status"
#define POL_ZONE_SE_STR "zone-security-expectation"
#ifdef LIBVAL_DLV
#define POL_DLV_TRUST_POINTS_STR  "dlv-trust-points"
#endif
#ifdef LIBVAL_NSEC3
#define POL_NSEC3_MAX_ITER_STR "nsec3-max-iter"
#endif

#define GOPT_TRUST_OOB_STR "trust-oob-answers"
#define GOPT_EDNS0_SIZE_STR "edns0-size"
#define TRUST_OOB_GOPT_YES_STR "yes"
#define TRUST_OOB_GOPT_NO_STR "no"
#define GOPT_ENV_POL_STR "env-policy"
#define GOPT_APP_POL_STR "app-policy"
#define GOPT_ENABLE_STR "enable"
#define GOPT_DISBLE_STR "disable"
#define GOPT_OVERRIDE_STR "override"
#define GOPT_LOGTARGET_STR "log"

#define VAL_POL_GOPT_DISABLE 0 
#define VAL_POL_GOPT_ENABLE 1
#define VAL_POL_GOPT_OVERRIDE 2


#define ZONE_PU_TRUSTED_MSG "trusted"
#define ZONE_PU_UNTRUSTED_MSG "untrusted"
#define ZONE_SE_IGNORE_MSG     "ignore"
#define ZONE_SE_DO_VAL_MSG     "validate"
#define ZONE_SE_UNTRUSTED_MSG  "untrusted"

/* 
 * The following policies are deprecated. 
 * They are defined here for backwards compatibility
 */
#define GOPT_TRUST_LOCAL_STR "trust-local-answers"

    /*
     * Response structures  
     */
    struct val_rr_rec {
        size_t rr_rdata_length;      /* RDATA length */
        u_char *rr_rdata;       /* Raw RDATA */
        struct val_rr_rec  *rr_next;
        val_astatus_t   rr_status;
    };

    struct val_rrset_rec {
        int val_rrset_rcode;
        char  *val_rrset_name;       /* Owner */
        int val_rrset_class;      /* ns_c_... */
        int val_rrset_type;       /* ns_t_... */
        long val_rrset_ttl;        /* Received ttl */
        int  val_rrset_section;      /* VAL_FROM_... */
        struct sockaddr *val_rrset_server;      /* respondent server */
        struct val_rr_rec  *val_rrset_data; /* All data RR's */
        struct val_rr_rec  *val_rrset_sig;  /* All signatures */
    };

    struct policy_list {
        int             index;
        policy_entry_t  *pol;
        struct policy_list *next;
    };

    struct dnsval_list {
        char   *dnsval_conf;
        time_t v_timestamp;
        struct dnsval_list *next;
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

    struct qname_chain {
        u_char        qnc_name_n[NS_MAXCDNAME];
        struct qname_chain *qnc_next;
    };

    struct val_response {
        u_char  *vr_response;
        size_t  vr_length;
        val_status_t    vr_val_status;
    };

    struct val_authentication_chain {
        val_astatus_t   val_ac_status;
        struct val_rrset_rec *val_ac_rrset;
        struct val_authentication_chain *val_ac_trust;
    };

    struct rr_rec {
        size_t rr_length;
        u_char *rr_data;
        struct rr_rec *rr_next;
    };

#define MAX_PROOFS 4
    struct val_result_chain {
        val_status_t val_rc_status;
        char  *val_rc_alias;
        struct val_rrset_rec *val_rc_rrset; 
        struct val_authentication_chain *val_rc_answer;
        int    val_rc_proof_count;
        struct val_authentication_chain *val_rc_proofs[MAX_PROOFS];
        struct val_result_chain *val_rc_next;
    };

    struct val_answer_chain {
        val_status_t   val_ans_status;
        char *val_ans_name;
        int val_ans_class;
        int val_ans_type;
        struct rr_rec *val_ans;
        struct val_answer_chain *val_ans_next;
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
        u_char         *d_hash;
        u_int32_t       d_hash_len;
    } val_ds_rdata_t;

#ifdef LIBVAL_NSEC3
    typedef struct val_nsec3_rdata {
        u_int8_t        alg;
        u_int8_t        flags;
        u_int16_t       iterations;
        u_int8_t        saltlen;
        u_char         *salt;
        u_int8_t        nexthashlen;
        u_char         *nexthash;
        u_int16_t       bit_field;
    } val_nsec3_rdata_t;

#define NSEC3_FLAG_OPTOUT 0x01

#endif

    /*
     * Logging-related definitions 
     */
    typedef void    (*val_log_logger_t) (struct val_log * logp,
                                         const val_context_t * ctx,
                                         int level,
                                         const char *format, va_list ap);
    typedef void    (*val_log_cb_t) (struct val_log *logp, int level,
                                     const char *buf);

    typedef struct val_log {
        val_log_logger_t logf;  /* log function ptr */
        u_char   level;  /* 0 - 9, corresponds w/sylog severities */
        u_char   lflags; /* generic log flags */

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

    char           *get_hex_string(const u_char *data, size_t datalen,
                                   char *buf, size_t buflen);
    void            val_log_rrsig_rdata(const val_context_t * ctx,
                                        int level, const char *prefix,
                                        val_rrsig_rdata_t * rdata);
    void            val_log_dnskey_rdata(val_context_t * ctx, int level,
                                         const char *prefix,
                                         val_dnskey_rdata_t * rdata);
    void            val_log_authentication_chain(const val_context_t * ctx,
                                                 int level,
                                                 const char * name,
                                                 int class_h,
                                                 int type_h,
                                                 struct val_result_chain
                                                 *results);
    void            val_log(const val_context_t * ctx, int level,
                            const char *format, ...);

    val_log_t      *val_log_add_cb(val_log_t **log_head, int level, val_log_cb_t func);
    val_log_t      *val_log_add_filep(val_log_t **log_head, int level, FILE * p);
    val_log_t      *val_log_add_file(val_log_t **log_head, int level, const char *filen);
    val_log_t      *val_log_add_syslog(val_log_t **log_head, int level, int facility);
    val_log_t      *val_log_add_network(val_log_t **log_head, int level, char *host, int port);
    val_log_t      *val_log_add_optarg_to_list(val_log_t **list_head,
                                        const char *args, int use_stderr);
    val_log_t      *val_log_add_optarg(const char *args, int use_stderr);

    int             val_log_debug_level(void);
    void            val_log_set_debug_level(int);
    const char     *val_get_ns_string(struct sockaddr *serv, char *dst,
                                      size_t size);


    const char     *p_ac_status(val_astatus_t valerrno);
    const char     *p_val_status(val_status_t err);
    const char     *p_val_err(int err);

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
                                          const char * domain_name,
                                          int qclass,
                                          int qtype,
                                          u_int32_t flags,
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
    int             val_free_validator_state(void);

    /*
     * from val_policy.h 
     */
    char           *resolv_conf_get(void);
    int             resolv_conf_set(const char *name);
    char           *root_hints_get(void);
    int             root_hints_set(const char *name);
    char           *dnsval_conf_get(void);
    int             dnsval_conf_set(const char *name);
    int             val_add_valpolicy(val_context_t *context, 
                                      void *policy_defintion,
                                      val_policy_handle_t **pol);
    int             val_remove_valpolicy(val_context_t *context, 
                                      val_policy_handle_t *pol);
    /*
     * from val_support.h 
     */
    size_t       wire_name_length(const u_char * field);

    /*
     * from val_x_query.c 
     */
    int             val_res_query(val_context_t * ctx, const char *dname,
                                  int q_class, int type, u_char * answer,
                                  int anslen, val_status_t * val_status);
    int             val_res_search(val_context_t * ctx, const char *dname,
                                   int class_h, int type, u_char * answer,
                                   int anslen, val_status_t * val_status);
    int             compose_answer(const char * name,
                                   int type_h,
                                   int class_h,
                                   struct val_result_chain *results,
                                   struct val_response *f_resp);
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
                                    struct addrinfo **res,
                                    val_status_t * val_status);
#ifndef HAVE_FREEADDRINFO
    void            freeaddrinfo(struct addrinfo *ainfo);
#endif

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
     * A generic high-level function to return data for a given
     * name, class, type tuple. 
     */
    int val_get_rrset(val_context_t *ctx,
                      const char *name,
                      int classid,
                      int type,
                      u_int32_t flags,
                      struct val_answer_chain **answers);

    void val_free_answer_chain(struct val_answer_chain *answers);


    /*
     * for backwards compatibility
     */
#define p_val_error p_val_status
#define p_as_error p_ac_status

#ifdef __cplusplus
}                               /* extern "C" */
#endif
#endif                          /* VALIDATOR_H */
