
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VALIDATOR_H
#define VALIDATOR_H

#include <arpa/nameser.h>
#include <stdlib.h>

#define VAL_CONFIGURATION_FILE	"/etc/dnsval.conf"
#define RESOLV_CONF             "/etc/resolv.conf"

#define DNS_PORT	53
#ifdef MEMORY_DEBUGGING
#define MALLOC(s) my_malloc(s, __FILE__, __LINE__)
#define FREE(p) my_free(p,__FILE__,__LINE__)
#define STRDUP(p) my_strdup(p,__FILE__,__LINE__)
#else
#define MALLOC(s) malloc(s)
#define FREE(p) free(p)
#define STRDUP(p) strdup(p)
#endif

/* Policies associated with Keys */
#define	CANNOT_BE_USED			0x00				
#define CAN_SIGN_KEY			0x01
#define CAN_SIGN_ZONE			0x02
#define CAN_SIGN_ZONE_AND_KEY 	CAN_SIGN_KEY|CAN_SIGN_ZONE 

/* Different validation result types */
#define ANSWER	XX
#define CNAME	XX
#define DNAME	XX
#define NSEC_PROOF	XX
#define SOA_PROOF	XX

/* Assertion Initial states */
#define A_DONT_KNOW 0 
#define A_CAN_VERIFY 1 
#define A_WAIT_FOR_TRUST 2 
#define A_WAIT_FOR_RRSIG  3
#define A_INIT 4
#define A_NEGATIVE_PROOF 5 
#define A_LAST_STATE  10 /* Closest round number above A_NEGATIVE_PROOF */

/* Query states */
#define Q_INIT	1
#define Q_SENT	2
#define Q_ANSWERED 3
#define Q_ERROR_BASE 4

#define SIGNBY              18
#define ENVELOPE            10
#define RRSIGLABEL			3
#define TTL					4

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
#ifndef DLV
#define MAX_POL_TOKEN	 			10	
#else
#define P_DLV_TRUST_POINTS			10
#define P_DLV_MAX_VALIDATION_LINKS	11
#define MAX_POL_TOKEN	 			12
#endif


#define policy_entry_t void* 
/* 
 * The above is a generic data type for a policy entry
 * typecasted to one of the types defined in val_policy.h: 
 */



struct policy_list {
	int index; 
	policy_entry_t pol;
	struct policy_list *next;
};

/* 
 * This list is ordered from general to more specific --
 * so "mozilla" < "sendmail" < "browser:mozilla"
 */
struct policy_overrides{
	char *label;
	int label_count;
	struct policy_list *plist;
	struct policy_overrides *next;
};


typedef struct val_context {
	/* resolver policy */
	struct name_server *nslist;

	/* validator policy */
	policy_entry_t e_pol[MAX_POL_TOKEN];
	struct policy_overrides *pol_overrides;
	struct policy_overrides *cur_override;
} val_context_t;

#define RETRIEVE_POLICY(ctx, index, type)	\
			(!ctx->e_pol[index])? NULL:(type)(ctx->e_pol[index])

struct query_chain; /* forward declaration */

struct assertion_chain {

	u_int16_t ac_state;
	struct rrset_rec *ac_data;
	struct query_chain *ac_pending_query;
	struct assertion_chain *ac_more_data;
	struct assertion_chain *ac_trust;
	struct assertion_chain *ac_next;
};

struct query_list
{
    u_int8_t            ql_name_n[MAXDNAME];
    u_int8_t            ql_zone_n[MAXDNAME];
    u_int16_t           ql_type_h;
    struct query_list   *ql_next;
};

struct qname_chain
{
    u_int8_t        qnc_name_n[MAXDNAME];
    struct qname_chain  *qnc_next;
};

struct delegation_info {
	struct query_list   *queries;
	struct qname_chain  *qnames;
	struct rrset_rec    *answers;
	struct rrset_rec    *learned_zones;
};

struct query_chain {
	u_char qc_name_n[MAXCDNAME];
	u_int16_t qc_type_h;
	u_int16_t qc_class_h;
	u_int16_t qc_state; /* DOS, TIMED_OUT, etc */
	struct name_server *qc_ns_list;
	struct delegation_info *qc_referral;
	int qc_trans_id;
	struct assertion_chain *qc_as;
	struct query_chain *qc_next;
};

struct response_t {
	u_int8_t *response;
	int	response_length;
	int validation_result;
};


struct domain_info
{
    char          *di_requested_name_h;
    u_int16_t       di_requested_type_h;
    u_int16_t       di_requested_class_h;
    struct  rrset_rec   *di_rrset;
    struct qname_chain  *di_qnames;
	int				di_res_error;
};

#endif /* VALIDATOR_H */
