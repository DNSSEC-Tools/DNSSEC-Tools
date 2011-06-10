
/*
 * Copyright 2005-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VALIDATOR_H
#define VALIDATOR_H

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>

#include <validator/val_errors.h>

#ifdef __cplusplus
extern          "C" {
#endif

/*
 * Section values of an RRset 
 */
#define VAL_FROM_UNSET            0
#define VAL_FROM_ANSWER           1
#define VAL_FROM_AUTHORITY        2
#define VAL_FROM_ADDITIONAL       3
#define VAL_FROM_QUERY            4


/*
 * Bitmasks for various sets of query flags 
 */
#define VAL_QFLAGS_ANY          0xffffffff
/*
 * Flags in this bit mask are checked when finding
 * a matching record in the query cache 
 */
#define VAL_QFLAGS_CACHE_MASK   0x0000ffff
#define VAL_QUERY_NO_AC_DETAIL  0x00000001
#define VAL_QUERY_DONT_VALIDATE 0x00000002 
#define VAL_QUERY_NO_DLV        0x00000004 
#define VAL_QUERY_USING_DLV     0x00000008 
#define VAL_QUERY_ASYNC         0x00000010
/*
 * Flags in this bit mask are not checked when finding
 * a matching record in the query cache 
 */
#define VAL_QFLAGS_NOCACHE_MASK     0xffff0000
#define VAL_QUERY_NO_EDNS0          0x00010000
#define VAL_QUERY_EDNS0_FALLBACK    0x00020000 
#define VAL_QUERY_NO_EDNS0_FALLBACK 0x00040000
#define VAL_QUERY_GLUE_REQUEST      0x00080000
#define VAL_QUERY_RECURSE           0x00100000
#define VAL_QUERY_REFRESH_QCACHE    0x00200000

#define VAL_QFLAGS_USERMASK (VAL_QUERY_NO_AC_DETAIL |\
                             VAL_QUERY_DONT_VALIDATE |\
                             VAL_QUERY_NO_DLV |\
                             VAL_QUERY_ASYNC |\
                             VAL_QUERY_NO_EDNS0_FALLBACK |\
                             VAL_QUERY_RECURSE |\
                             VAL_QUERY_REFRESH_QCACHE)

#ifndef LOG_EMERG
#define LOG_EMERG 0
#define LOG_ALERT 1
#define LOG_CRIT 2
#define LOG_ERR 3
#define LOG_WARNING 4
#define LOG_NOTICE 5
#define LOG_INFO 6
#define LOG_DEBUG 7
#endif

/* Application MUST define these types */
struct hostent;
struct addrinfo;
struct sockaddr;
struct timeval;
struct fd_set;

/* validator return types */
typedef unsigned char val_status_t;
typedef unsigned short val_astatus_t;

/* opaque types */
struct val_context;
typedef struct val_context val_context_t;
struct val_policy_handle;
typedef struct val_policy_handle val_policy_handle_t;
struct val_log;
typedef struct val_log val_log_t;
struct queries_for_query;

/*
 * Validator policies can be one of the following
 */
#define POL_TRUST_ANCHOR_STR "trust-anchor"
#define POL_CLOCK_SKEW_STR "clock-skew"
#define POL_PROV_INSEC_STR "provably-insecure-status"
#define POL_ZONE_SE_STR "zone-security-expectation"
#define POL_DLV_TRUST_POINTS_STR  "dlv-trust-points"
#define POL_NSEC3_MAX_ITER_STR "nsec3-max-iter"
#define GOPT_TRUST_OOB_STR "trust-oob-answers"
#define GOPT_EDNS0_SIZE_STR "edns0-size"
#define GOPT_YES_STR "yes"
#define GOPT_NO_STR "no"
#define GOPT_ENV_POL_STR "env-policy"
#define GOPT_APP_POL_STR "app-policy"
#define GOPT_ENABLE_STR "enable"
#define GOPT_DISBLE_STR "disable"
#define GOPT_OVERRIDE_STR "override"
#define GOPT_LOGTARGET_STR "log"
#define GOPT_CLOSEST_TA_ONLY_STR "closest-ta-only"

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
        unsigned char *rr_rdata;       /* Raw RDATA */
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

    struct val_response {
        unsigned char  *vr_response;
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
        unsigned char *rr_data;
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
        unsigned short flags;
        unsigned char  protocol;
        unsigned char  algorithm;
        unsigned int   public_key_len; /* in bytes */
        unsigned char  *public_key;
        unsigned short key_tag;
        struct val_dnskey_rdata *next;
    } val_dnskey_rdata_t;

    typedef struct val_rrsig_rdata {
        unsigned short type_covered;
        unsigned char  algorithm;
        unsigned char  labels;
        unsigned int   orig_ttl;
        unsigned int   sig_expr;
        unsigned int   sig_incp;
        unsigned short key_tag;
        unsigned char  signer_name[256];       /* null terminated */
        unsigned int   signature_len;  /* in bytes */
        unsigned char  *signature;
        struct val_rrsig_rdata *next;
    } val_rrsig_rdata_t;

    typedef struct val_ds_rdata {
        unsigned short d_keytag;
        unsigned char  d_algo;
        unsigned char  d_type;
        unsigned char  *d_hash;
        unsigned int   d_hash_len;
    } val_ds_rdata_t;

    typedef struct val_nsec3_rdata {
        unsigned char  alg;
        unsigned char  flags;
        unsigned short iterations;
        unsigned char  saltlen;
        unsigned char  *salt;
        unsigned char  nexthashlen;
        unsigned char  *nexthash;
        unsigned short bit_field;
    } val_nsec3_rdata_t;

    typedef void    (*val_log_logger_t) (struct val_log * logp,
                                         const val_context_t * ctx,
                                         int level,
                                         const char *format, va_list ap);

    typedef void    (*val_log_cb_t) (struct val_log *logp, int level,
                                                     const char *buf);


    char           *get_hex_string(const unsigned char *data, size_t datalen,
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
    int             val_log_highest_debug_level(void);
    const char     *val_get_ns_string(struct sockaddr *serv, char *dst,
                                      size_t size);


    const char     *p_ac_status(val_astatus_t valerrno);
    const char     *p_val_status(val_status_t err);
    const char     *p_val_err(int err);

#ifndef VAL_NO_ASYNC
    /*
     * asynchronous status
     */
#define VAL_AS_CTX_USER_SUPPLIED     0x00000001 /* i.e. don't delete it! */
#define VAL_AS_IGNORE_CACHE          0x00000002
#define VAL_AS_NO_NEW_QUERIES        0x00000004
#define VAL_AS_DONE                  0x00000008 /* have results/answers */
#define VAL_AS_CB_COMPLETED          0x00000010 /* called user callbacks */
#define VAL_AS_NO_ANSWERS            0x00000020 /* don't care about answers */
#define VAL_AS_NO_CALLBACKS          0x00000040 /* don't call callbacks */

    typedef struct val_async_status_s val_async_status;
    typedef int (*val_cb_results)(val_async_status *as);

    struct val_async_status_s {
        val_context_t                 *val_as_ctx;
        unsigned int                  val_as_flags;

        unsigned char                 val_as_inflight;
        struct queries_for_query      *val_as_top_q;
        struct queries_for_query      *val_as_queries;

        unsigned char                 *val_as_domain_name_n;
        int                           val_as_class;
        int                           val_as_type;

        struct val_result_chain       *val_as_results;
        struct val_answer_chain       *val_as_answers;

        val_cb_results                val_as_result_cb;
        void                          *val_as_cb_user_ctx;

        struct val_async_status_s     *val_as_next;
    };

    int             val_async_submit(val_context_t * ctx,
                                     const char * domain_name, int qclass,
                                     int qtype, unsigned int flags,
                                     val_async_status **async_status);
    int             val_async_check(val_context_t *context,
                                    fd_set *pending_desc, int *nfds,
                                    unsigned int flags);
    int             val_async_select_info(val_context_t *context,
                                    fd_set *fds,
                                    int *num_fds,
                                    struct timeval *timeout);
#endif /* VAL_NO_ASYNC */

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
                                          unsigned int flags,
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
     * from val_x_query.c 
     */
    int             val_res_query(val_context_t * ctx, const char *dname,
                                  int q_class, int type, unsigned char * answer,
                                  int anslen, val_status_t * val_status);
    int             val_res_search(val_context_t * ctx, const char *dname,
                                   int class_h, int type, unsigned char * answer,
                                   int anslen, val_status_t * val_status);
    int             compose_answer(const char * name,
                                   int type_h,
                                   int class_h,
                                   struct val_result_chain *results,
                                   struct val_response *f_resp);
    /*
     * from val_gethostbyname.c 
     */
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

    int             val_getnameinfo(val_context_t * ctx,
                                    const struct sockaddr *sa,
                                    size_t salen,
                                    char *host,
                                    size_t hostlen,
                                    char *serv,
                                    size_t servlen,
                                    int flags, val_status_t * val_status);

    int             val_getaddrinfo_has_status(int rc);

#define VAL_GETADDRINFO_HAS_STATUS val_getaddrinfo_has_status 
#define VAL_GETNAMEINFO_HAS_STATUS val_getaddrinfo_has_status 

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
                      unsigned int flags,
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
