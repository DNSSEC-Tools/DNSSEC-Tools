
/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VALIDATOR_H
#define VALIDATOR_H

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>

/*
 * XXX fd_set cannot be forward declared
 */
#ifndef WIN32
#include <sys/select.h>
#endif

#include <validator/val_errors.h>

#ifdef __cplusplus
extern          "C" {
#endif

/* 
 * Application is responsible for pointing to the definitions of these types 
 * if it plans on using them 
 */
struct hostent;
struct addrinfo;
struct sockaddr;
struct timeval;

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
 * Flags in this bit mask MUST match when finding
 * a record in the query cache. If they are not
 * requested they cannot match. 
 */
#define VAL_QFLAGS_CACHE_MASK       0x0000ffff
#define VAL_QUERY_AC_DETAIL         0x00000001
#define VAL_QUERY_DONT_VALIDATE     0x00000002 
#define VAL_QUERY_NO_DLV            0x00000004 
#define VAL_QUERY_USING_DLV         0x00000008 
#define VAL_QUERY_ASYNC             0x00000010
#define VAL_QUERY_NO_EDNS0_FALLBACK 0x00000020
#define VAL_QUERY_SKIP_RESOLVER     0x00000040
#define VAL_QUERY_MARK_FOR_DELETION 0x00000080
#define VAL_QUERY_IGNORE_SKEW       0x00000100

/*
 * Flags in this bit mask MUST match if they
 * are requested, they MAY match if these flags are
 * not requested 
 */
#define VAL_QFLAGS_CACHE_PREF_MASK  0x00ff0000
#define VAL_QUERY_ITERATE           0x00010000
#define VAL_QUERY_SKIP_CACHE        0x00020000
/* for backwards compatibility */
#define VAL_QUERY_RECURSE VAL_QUERY_ITERATE 

/*
 * Flags in this bit mask are ignored when finding
 * a matching record in the query cache 
 */
#define VAL_QFLAGS_NOCACHE_MASK     0xff000000
#define VAL_QUERY_EDNS0_FALLBACK    0x01000000 //obsolete
#define VAL_QUERY_GLUE_REQUEST      0x02000000
#define VAL_QUERY_CHECK_ALL_RRSIGS  0x04000000
#define VAL_QUERY_SEC_LEAF          0x08000000


#define VAL_QFLAGS_USERMASK (VAL_QUERY_AC_DETAIL |\
                             VAL_QUERY_DONT_VALIDATE |\
                             VAL_QUERY_NO_DLV |\
                             VAL_QUERY_ASYNC |\
                             VAL_QUERY_NO_EDNS0_FALLBACK |\
                             VAL_QUERY_SKIP_RESOLVER |\
                             VAL_QUERY_IGNORE_SKEW|\
                             VAL_QUERY_ITERATE |\
                             VAL_QUERY_SKIP_CACHE |\
                             VAL_QUERY_CHECK_ALL_RRSIGS)

#define VAL_LOG_EMERG 0
#define VAL_LOG_ALERT 1
#define VAL_LOG_CRIT 2
#define VAL_LOG_ERR 3
#define VAL_LOG_WARNING 4
#define VAL_LOG_NOTICE 5
#define VAL_LOG_INFO 6
#define VAL_LOG_DEBUG 7

/* validator return types */
typedef unsigned char val_status_t;
typedef unsigned short val_astatus_t;

/* opaque types */
struct libval_context;
typedef struct libval_context val_context_t;

struct val_policy_handle;
typedef struct val_policy_handle val_policy_handle_t;
struct val_log;
typedef struct val_log val_log_t;
struct queries_for_query;


struct zone_ns_map_t {
    u_char        zone_n[NS_MAXCDNAME];
    struct name_server *nslist;
    struct zone_ns_map_t *next;
};

/* validator context options */
typedef struct val_global_opt {
    int local_is_trusted;
    long edns0_size;
    int env_policy;
    int app_policy;
    char *log_target;
    int closest_ta_only;
    int rec_fallback;
    long max_refresh;
    int proto;
} val_global_opt_t;

/*
 * Dynamic policy can be configured with the following flags
 * in vc_polflags
 */
#define CTX_DYN_POL_VAL_OVR  0x00000001
#define CTX_DYN_POL_RES_OVR  0x00000002
#define CTX_DYN_POL_GLO_OVR  0x00000004
#define CTX_DYN_POL_RES_NRD  0x00000008

typedef struct val_context_opt {
    unsigned int vc_qflags;
    unsigned int vc_polflags;
    char *vc_valpol;
    char *vc_nslist;
    char *vc_val_conf;
    char *vc_res_conf;
    char *vc_root_conf;
    val_global_opt_t *vc_gopt;
} val_context_opt_t;


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
#define GOPT_ENV_POL_STR "env-policy"
#define GOPT_APP_POL_STR "app-policy"
#define GOPT_LOGTARGET_STR "log"
#define GOPT_CLOSEST_TA_ONLY_STR "closest-ta-only"
#define GOPT_REC_FALLBACK "rec-fallback"
#define GOPT_MAX_REFRESH_STR "max-refresh"
#define GOPT_PROTO "proto"
/* 
 * The following policies are deprecated. 
 * They are defined here for backwards compatibility
 */
#define GOPT_TRUST_LOCAL_STR "trust-local-answers"


#define GOPT_YES_STR "yes"
#define GOPT_NO_STR "no"
#define GOPT_ENABLE_STR "enable"
#define GOPT_DISBLE_STR "disable"
#define GOPT_OVERRIDE_STR "override"
#define GOPT_PROTO_IPV6_STR "ipv6"
#define GOPT_PROTO_IPV4_STR "ipv4"
#define GOPT_PROTO_ANY_STR "any"

#define VAL_POL_GOPT_UNSET -100

#define VAL_POL_GOPT_DISABLE 0 
#define VAL_POL_GOPT_ENABLE 1
#define VAL_POL_GOPT_OVERRIDE 2

#define VAL_POL_GOPT_MAXREFRESH 60

#define VAL_POL_GOPT_PROTO_ANY 0 
#define VAL_POL_GOPT_PROTO_IPV4 1 
#define VAL_POL_GOPT_PROTO_IPV6 2 

#define ZONE_PU_TRUSTED_MSG "trusted"
#define ZONE_PU_UNTRUSTED_MSG "untrusted"
#define ZONE_SE_IGNORE_MSG     "ignore"
#define ZONE_SE_DO_VAL_MSG     "validate"
#define ZONE_SE_UNTRUSTED_MSG  "untrusted"

#ifndef NS_MAXDNAME
#define NS_MAXDNAME 1025
#endif


    /*
     * Response structures  
     */

    /*
     * WARNING: DO NOT change the order of struct members in this
     * struct. At certain times 'struct val_rr_rec' is typecast to
     * 'struct rr_rec' 
     */
    struct val_rr_rec {
        size_t rr_rdata_length;      /* RDATA length */
        unsigned char *rr_rdata;       /* Raw RDATA */
        struct val_rr_rec  *rr_next;
        val_astatus_t   rr_status;
    };

    struct val_rrset_rec {
        int val_rrset_rcode;
        char val_rrset_name[NS_MAXDNAME];/* Owner */
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

    /*
     * WARNING: DO NOT change the order of struct members in this
     * struct. At certain times 'struct val_rr_rec' is typecast to
     * 'struct rr_rec' 
     */
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
        char val_ans_name[NS_MAXDNAME];
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
    void            val_log_ap(const val_context_t * ctx, int level,
                               const char *log_template, va_list ap);

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
#define VAL_AS_IGNORE_CACHE          0x00000001
#define VAL_AS_NO_NEW_QUERIES        0x00000002
#define VAL_AS_NO_ANSWERS            0x00000004 /* don't care about answers */
#define VAL_AS_NO_CALLBACKS          0x00000008 /* don't call callbacks */
#define VAL_AS_NO_CANCEL_CALLBACKS   0x00000010 /* no cb if req cancelled */

#define VAL_AS_DONE                  0x01000000 /* have results/answers */
#define VAL_AS_CALLBACK_CALLED       0x02000000 /* called user callbacks */
#define VAL_AS_INFLIGHT              0x04000000 /* called user callbacks */

    /*
     * asynchronous events
     */
#define VAL_AS_EVENT_COMPLETED             0x01
#define VAL_AS_EVENT_CANCELED              0x02

    /** opaque status object for async request */
    typedef struct val_async_status_s val_async_status;

    typedef struct val_cb_params_s {
        val_status_t             val_status;
        char                    *name;
        int                      class_h;
        int                      type_h;
        int                      retval;
        struct val_result_chain *results;
        struct val_answer_chain *answers;
    } val_cb_params_t;

    typedef int (*val_async_event_cb)(val_async_status *async_status,
                                      int event, val_context_t *ctx,
                                      void *cb_data, val_cb_params_t *cbp);

    int             val_async_submit(val_context_t * ctx,
                                     const char * domain_name, int class_h,
                                     int type_h, unsigned int flags,
                                     val_async_event_cb callback, void *cb_data,
                                     val_async_status **async_status);
    int             val_async_check_wait(val_context_t *context,
                                         fd_set *pending_desc, int *nfds,
                                         struct timeval *tv, unsigned int flags);
    int             val_async_select(val_context_t *context, fd_set *pending,
                                     int *nfds, struct timeval *timeout,
                                     unsigned int flags);
    int             val_async_select_info(val_context_t *context,
                                    fd_set *fds,
                                    int *num_fds,
                                    struct timeval *timeout);

    /*
     * cancellation flags
     */
#define VAL_AS_CANCEL_NO_CALLBACKS     0x00000001 /* no cb if req completed */
#define VAL_AS_CANCEL_RESERVED_MASK    0xFF000000 /* one byte internal use */

    int             val_async_cancel(val_context_t *context,
                                     val_async_status *as,
                                     unsigned int flags);
    int             val_async_cancel_all(val_context_t *context, unsigned int flags);
    unsigned int    val_async_getflags(val_async_status *as);

    /*
     * backwards compatibility
     */
    /** val_async_check: use val_async_check_wait instead */
    int             val_async_check(val_context_t *context,
                                    fd_set *pending_desc, int *nfds,
                                    unsigned int flags);

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
                                          int class_h,
                                          int type_h,
                                          unsigned int flags,
                                          struct val_result_chain
                                          **results);


    /*
     * from val_context.h 
     */
    int             val_create_context_with_conf(const char *label,
                                                 char *dnsval_conf,
                                                 char *resolv_conf,
                                                 char *root_conf,
                                                 val_context_t ** newcontext);
    int             val_create_context_ex(const char *label,
                                          val_context_opt_t *opt,
                                          val_context_t ** newcontext);
    int             val_create_context(const char *label,
                                       val_context_t ** newcontext);
    void            val_free_context(val_context_t * context);
    int             val_free_validator_state(void);

#define VAL_CTX_FLAG_SET        0x01
#define VAL_CTX_FLAG_RESET      0x02
    int             val_context_setqflags(val_context_t *context,
                                          unsigned char action,
                                          unsigned int flags);

    int             val_context_store_ns_for_zone(val_context_t *context, 
                                                  char * zone, char *resp_server,
                                                  int recursive);
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
    struct name_server *val_get_nameservers(val_context_t *ctx);
    /*
     * from val_x_query.c 
     */
    int             val_res_query(val_context_t * ctx, const char *dname,
                                  int class_h, int type_h, unsigned char * answer,
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

    void            val_freeaddrinfo(struct addrinfo *ainfo);

#define VAL_GETADDRINFO_HAS_STATUS val_getaddrinfo_has_status 
#define VAL_GETNAMEINFO_HAS_STATUS val_getaddrinfo_has_status 

    typedef struct val_gai_status_s val_gai_status;
    typedef int (*val_gai_callback)(void *callback_data, int eai_retval,
                                    struct addrinfo *res,
                                    val_status_t val_status);

    int             val_getaddrinfo_submit(val_context_t * context,
                                           const char *nodename,
                                           const char *servname,
                                           const struct addrinfo *hints_in,
                                           val_gai_callback callback,
                                           void *callback_data,
                                           unsigned int vgai_flags,
                                           val_gai_status **status);
    /** flags can be VAL_AS_CANCEL_NO_CALLBACKS */
    void            val_getaddrinfo_cancel(val_gai_status *status, int flags);

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
                      int class_h,
                      int type_h,
                      unsigned int flags,
                      struct val_answer_chain **answers);

    void val_free_answer_chain(struct val_answer_chain *answers);

    int  val_create_rr_otw( char *name,
                   int type_h,
                   int class_h,
                   long ttl,
                   size_t rdatalen,
                   unsigned char *rdata,
                   size_t *buflen,
                   unsigned char **buf);

    /*
     * utility functions. mostly used internal to libval.
     */
    int val_get_answer_from_result(val_context_t *context, const char *name,
                                   int class_h, int type_h,
                                   struct val_result_chain **results,
                                   struct val_answer_chain **answers,
                                   unsigned int vgafr_flags);


    /*
     * for backwards compatibility
     */
#define p_val_error p_val_status
#define p_as_error p_ac_status

#ifdef __cplusplus
}                               /* extern "C" */
#endif
#endif                          /* VALIDATOR_H */
