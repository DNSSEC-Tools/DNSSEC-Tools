/*
 * Copyright 2007-2009 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VALIDATOR_INTERNALS_H
#define VALIDATOR_INTERNALS_H

#ifndef VAL_NO_THREADS
#include <pthread.h>
#endif

#ifdef __cplusplus
extern          "C" {
#endif

    struct query_list {
        u_char        ql_name_n[NS_MAXCDNAME];
        u_char        ql_zone_n[NS_MAXCDNAME];
        u_int16_t     ql_type_h;
        struct query_list *ql_next;
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
        int    qc_trans_id;

        struct val_digested_auth_chain *qc_ans;
        struct val_digested_auth_chain *qc_proof;
        struct val_query_chain *qc_next;
    };

    struct val_context {

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
        val_log_t *val_log_targets;
        
        /* Query cache */
        struct val_query_chain *q_list;
    }; 

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
        u_int8_t  rrs_section;      /* VAL_FROM_... */
        struct sockaddr *rrs_server;      /* respondent server */
        struct val_rr_rec  *rrs_data; /* All data RR's */
        struct val_rr_rec  *rrs_sig;  /* All signatures */
        u_char *rrs_zonecut_n;
        u_int8_t rrs_cred;       /* SR_CRED_... */
        u_int8_t rrs_ans_kind;   /* SR_ANS_... */
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
#endif                          /* VALIDATOR_H */
