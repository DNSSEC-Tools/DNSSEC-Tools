/*
 * Copyright 2007-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

#ifndef _VALIDATOR_INTERNAL_H
#define _VALIDATOR_INTERNAL_H

#include "validator/validator.h"
#include "validator/resolver.h"

#ifdef __cplusplus
extern          "C" {
#endif

/* various constants */
#define DNS_PORT                53
#define VAL_LOG_OPTIONS LOG_PID
#define VALIDATOR_LOG_PORT 1053
#define VALIDATOR_LOG_SERVER "127.0.0.1"
#define VAL_DEFAULT_RESOLV_CONF "/etc/resolv.conf"
#define VAL_CONTEXT_LABEL "VAL_CONTEXT_LABEL"
#define VAL_LOG_TARGET "VAL_LOG_TARGET"
#define QUERY_BAD_CACHE_THRESHOLD 5
#define QUERY_BAD_CACHE_TTL 60
#define MAX_ALIAS_CHAIN_LENGTH 10       /* max length of cname/dname chain */
#define MAX_GLUE_FETCH_DEPTH 10         /* max length of glue dependency chain */
#define IPADDR_STRING_MAX 128

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
#define SR_CRED_AUTH_ADD         5
/*
 * Data was not authoritive, but was recieved iteratively 
 */
#define SR_CRED_ITER_ANS         6
#define SR_CRED_ITER_AUTH        6
#define SR_CRED_ITER_ADD         6
/*
 * Data is from a cache somewhere, or was at best an after thought 
 */
#define SR_CRED_NONAUTH          7
#define SR_CRED_NONAUTH_ANS      7
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
#ifndef ALG_DS_HASH_SHA1
#define ALG_DS_HASH_SHA1 1
#endif
#ifndef ALG_DS_HASH_SHA256
#define ALG_DS_HASH_SHA256 2
#endif

/*
 * Algorithm definitions for NSEC3 digest 
 */
#ifdef LIBVAL_NSEC3
#define ALG_NSEC3_HASH_SHA1 1
#endif
#define NSEC3_FLAG_OPTOUT 0x01

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

/* query types for which edns0 is required */
#ifdef LIBVAL_DLV
#define DNSSEC_METADATA_QTYPE(type) \
        ((type == ns_t_rrsig || type == ns_t_dnskey || type == ns_t_ds || type == ns_t_dlv))
#else
#define DNSSEC_METADATA_QTYPE(type) \
        ((type == ns_t_rrsig || type == ns_t_dnskey || type == ns_t_ds))
#endif


    struct query_list {
        u_char        ql_name_n[NS_MAXCDNAME];
        u_char        ql_zone_n[NS_MAXCDNAME];
        u_int16_t     ql_type_h;
        struct query_list *ql_next;
    };

    struct qname_chain {
        u_char        qnc_name_n[NS_MAXCDNAME];
        struct qname_chain *qnc_next;
    };

    struct delegation_info {
        struct query_list *queries;
        struct qname_chain *qnames;
        struct rrset_rec *answers;
        struct rrset_rec *proofs;
        struct name_server *cur_pending_glue_ns;
        struct name_server *pending_glue_ns;
        struct name_server *merged_glue_ns;
        u_char             *saved_zonecut_n;
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
        u_int32_t       qc_flags;
        u_int32_t       qc_ttl_x;    /* ttl expiry time */
        int             qc_bad; /* contains "bad" data */
        u_char         *qc_zonecut_n;

        struct delegation_info *qc_referral;
        struct name_server *qc_ns_list;
        struct name_server *qc_respondent_server;
        unsigned long qc_respondent_server_options;
        int    qc_trans_id;             //  synchronous queries only
        struct expected_arrival *qc_ea; // asynchronous queries only

        struct val_digested_auth_chain *qc_ans;
        struct val_digested_auth_chain *qc_proof;
        struct val_query_chain *qc_next;
    };

    typedef struct policy_entry {
        u_char        zone_n[NS_MAXCDNAME];
        long            exp_ttl;
        void *          pol;
        struct policy_entry *next;
    } policy_entry_t;

    typedef struct libval_policy_definition{
        char *keyword;
        char *zone;
        char *value;
        long ttl;
    } libval_policy_definition_t;

    typedef struct global_opt {
        int local_is_trusted;
        long edns0_size;
        int env_policy;
        int app_policy;
        char *log_target;
        int closest_ta_only;
        int rec_fallback;
    } global_opt_t;


    struct val_policy_handle {
        policy_entry_t *pe;
        int index;
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

    struct val_log {
        val_log_logger_t logf;  /* log function ptr */
        u_char   level;  /* 0 - 9, corresponds w/sylog severities */
        u_char   lflags; /* generic log flags */

        void           *a_void; /* logger dependent */

        union {
            struct {
                SOCKET             sock;
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
    };


    struct val_context {

#ifndef VAL_NO_THREADS
        /*
         * The read-write locks ensure that validator
         * policy is modified only when there is no
         * "active" val_resolve_and_check() call
         */
        pthread_rwlock_t pol_rwlock;
        /*
         * The mutex lock ensures that changes to the 
         * context cache and async query list can only be
         * made by one thread at any given time
         */
        pthread_mutex_t ac_lock;
#endif

        char  id[VAL_CTX_IDLEN];
        char  *label;

        /*
         * root_hints
         */
        char   *root_conf;
        struct name_server *root_ns;
        time_t h_timestamp;

        /*
         * default name server 
         */
        char   *resolv_conf;
        time_t r_timestamp;
        struct name_server *nslist;
        char   *search;
        
        /*
         * validator policy 
         */
        struct dnsval_list *dnsval_l;
        policy_entry_t **e_pol;
        global_opt_t *g_opt;
        struct val_log *val_log_targets;
        
        /* Query cache */
        struct val_query_chain *q_list;

#ifndef VAL_NO_ASYNC
        /* in flight async queries */
        val_async_status       *as_list;
#endif

        u_int32_t default_qflags;

#ifdef HAVE_PTHREAD_H 
        pthread_mutex_t ref_lock;
#endif
        int   refcount;
    } ; 

#ifndef VAL_NO_ASYNC
    struct val_async_status_s {
        val_context_t                 *val_as_ctx;
        unsigned int                  val_as_flags;

        unsigned char                 val_as_inflight;
        struct queries_for_query      *val_as_top_q;
        struct queries_for_query      *val_as_queries;

        char                          *val_as_name;
        int                           val_as_class;
        int                           val_as_type;

        int                           val_as_retval;
        struct val_result_chain       *val_as_results;
        struct val_answer_chain       *val_as_answers;

        val_async_event_cb             val_as_result_cb;
        void                          *val_as_cb_user_ctx;

        struct val_async_status_s     *val_as_next;
    };
#endif

    struct val_rrset_digested {
        struct rrset_rec *ac_data;
        struct val_digested_auth_chain *val_ac_rrset_next;
        struct val_digested_auth_chain *val_ac_next;
    };

    struct rrset_rec {
        int       rrs_rcode;
        u_char   *rrs_name_n;       /* Owner */
        u_int16_t rrs_class_h;      /* ns_c_... */
        u_int16_t rrs_type_h;       /* ns_t_... */
        u_int32_t rrs_ttl_h;        /* Received ttl */
        u_int32_t rrs_ttl_x;        /* ttl expire time */
        u_char  rrs_section;      /* VAL_FROM_... */
        struct sockaddr *rrs_server;      /* respondent server */
        unsigned long rrs_ns_options;
        struct val_rr_rec  *rrs_data; /* All data RR's */
        struct val_rr_rec  *rrs_sig;  /* All signatures */
        u_char *rrs_zonecut_n;
        u_char rrs_cred;       /* SR_CRED_... */
        u_char rrs_ans_kind;   /* SR_ANS_... */
        struct rrset_rec *rrs_next;
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

    struct val_digested_auth_chain {
        val_astatus_t   val_ac_status;
        struct val_rrset_digested val_ac_rrset;
        struct val_query_chain *val_ac_query;
    };

    struct queries_for_query {
        u_int32_t qfq_flags;
        struct val_query_chain *qfq_query;
        struct queries_for_query *qfq_next;
    };

    struct val_internal_result {
        val_status_t    val_rc_status;
        int             val_rc_is_proof;
        int             val_rc_consumed;
        u_int32_t       val_rc_flags;
        struct val_digested_auth_chain *val_rc_rrset;
        struct val_internal_result *val_rc_next;
    };


#ifdef __cplusplus
}                               /* extern "C" */
#endif


#endif /* _VALIDATOR_INTERNAL_H */

