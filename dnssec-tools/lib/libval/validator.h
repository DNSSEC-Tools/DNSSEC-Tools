
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VALIDATOR_H
#define VALIDATOR_H

#include <arpa/nameser.h>
#include <netdb.h>
#include <stdlib.h>
#include <val_errors.h>

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

/* Response structures  */
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
    u_int8_t        rrs_section;    /* SR_FROM_... */
    u_int8_t        rrs_ans_kind;   /* SR_ANS_... */
    struct rr_rec       *rrs_data;  /* All data RR's */
    struct rr_rec       *rrs_sig;   /* All signatures */
    struct rrset_rec    *rrs_next;
};

/* Credibility values of an RRset - from DNSIND-Clarify */
#define SR_CRED_UNSET            0
#define SR_CRED_FILE             1 /* From locally trusted file */
/* Data is from an authoritative server */
#define SR_CRED_AUTH_ANS         3
#define SR_CRED_AUTH_AUTH        4
/* Data is from a cache somewhere, or was at best an after thought */
#define SR_CRED_NONAUTH_ANS      6
#define SR_CRED_AUTH_ADD         7
#define SR_CRED_NONAUTH_AUTH     7
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
#define SR_ANS_BARE_RRSIG        5

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

struct val_result {
	struct assertion_chain *as;
	int status;
	int trusted;
	struct val_result *next;
};

/*
 **********************************
 * APIs exported by the validator
 **********************************
 */
/* from val_assertion.h */
void free_query_chain(struct query_chain **queries);
void free_assertion_chain(struct assertion_chain **assertions);
void free_result_chain(struct val_result **results);
int resolve_n_check(	val_context_t	*context,
			u_char *domain_name_n,
			const u_int16_t type,
			const u_int16_t class,
			const u_int8_t flags, 
			struct query_chain **queries,
			struct assertion_chain **assertions,
			struct val_result **results);

/* from val_context.h */
val_context_t *get_context(const char *label);
void destroy_context(val_context_t *context);

/* from val_support.h */
char *p_val_error(int valerrno);

/* from val_query.h */
int val_query ( const char *domain_name, int class, int type,
		unsigned char *answer, int anslen, int flags,
		int *dnssec_status );

/* from val_x_query.h */
int val_x_query(const val_context_t *ctx,
            const char *domain_name,
            const u_int16_t class,
            const u_int16_t type,
            const u_int8_t flags,
            struct response_t *resp,
            int *resp_count);

/* from val_gethostbyname.h */
struct hostent *val_gethostbyname ( const char *name, int *h_errnop );
struct hostent *val_x_gethostbyname ( const val_context_t *ctx, const char *name,
				      int *h_errnop );

/* from val_getaddrinfo.h */
int val_getaddrinfo ( const char *nodename, const char *servname,
		      const struct addrinfo *hints,
		      struct addrinfo **res );
int val_x_getaddrinfo ( const val_context_t *ctx,
		        const char *nodename, const char *servname,
			const struct addrinfo *hints,
			struct addrinfo **res );


#endif /* VALIDATOR_H */
