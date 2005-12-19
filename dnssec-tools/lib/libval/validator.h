
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VALIDATOR_H
#define VALIDATOR_H

#include <syslog.h>
#include <val_errors.h>

#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <netdb.h>

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
#define Q_WAIT_FOR_GLUE 3
#define Q_ANSWERED 4
#define Q_ERROR_BASE 5

#define SIGNBY              18
#define ENVELOPE            10
#define RRSIGLABEL			3
#define TTL					4

#define VAL_CTX_IDLEN 20

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
	struct name_server *rrs_respondent_server;
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

	char id[VAL_CTX_IDLEN];

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
	struct name_server  *pending_glue_ns;
	struct query_chain  *glueptr;
};

struct query_chain {
	u_char qc_name_n[MAXCDNAME];
	u_int16_t qc_type_h;
	u_int16_t qc_class_h;
	u_int16_t qc_state; /* DOS, TIMED_OUT, etc */
	struct name_server *qc_ns_list;
	struct name_server *qc_respondent_server;
	struct delegation_info *qc_referral;
	int qc_trans_id;
	struct assertion_chain *qc_as;
	int qc_glue_request;
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
	int status;
	int trusted;
	struct assertion_chain *as;
	struct val_result *next;
};


typedef struct val_dnskey_rdata {
    u_int16_t        flags;
    u_int8_t         protocol;
    u_int8_t         algorithm;
    u_int32_t        public_key_len;    /* in bytes */
    u_char *         public_key;
    u_int16_t        key_tag;
    struct val_dnskey_rdata* next;
} val_dnskey_rdata_t;
                                                                                                                             
typedef struct val_rrsig_rdata {
    u_int16_t        type_covered;
    u_int8_t         algorithm;
    u_int8_t         labels;
    u_int32_t        orig_ttl;
    u_int32_t        sig_expr;
    u_int32_t        sig_incp;
    u_int16_t        key_tag;
    u_char           signer_name[256]; /* null terminated */
    u_int32_t        signature_len;    /* in bytes */
    u_char *         signature;
    struct val_rrsig_rdata* next;
} val_rrsig_rdata_t;
                                                                                                                             
                                                                                                                             
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif
typedef struct val_ds_rdata {
    u_int16_t d_keytag;
    u_int8_t d_algo;
    u_int8_t d_type;
    u_int8_t d_hash[SHA_DIGEST_LENGTH];
} val_ds_rdata_t;

/*
 **********************************
 * APIs exported by the validator
 **********************************
 */
/* from val_assertion.h */
void free_query_chain(struct query_chain **queries);
void free_assertion_chain(struct assertion_chain **assertions);
void free_result_chain(struct val_result **results);
int resolve_n_check(    val_context_t   *context,
            u_char *domain_name_n,
            const u_int16_t type,
            const u_int16_t class,
            const u_int8_t flags,
            struct query_chain **queries,
            struct assertion_chain **assertions,
            struct val_result **results);

/* from val_context.h */
int get_context(char *label, val_context_t **newcontext);
void destroy_context(val_context_t *context);
int switch_effective_policy(val_context_t *ctx, char *label);

/* from val_log.h */
char *get_hex_string(char *data, int datalen, char *buf, int buflen);
void val_log_rrset(val_context_t *ctx, int level, struct rrset_rec *rrset);
void val_log_base64(val_context_t *ctx, int level, unsigned char * message, int message_len);
void val_log_rrsig_rdata (val_context_t *ctx, int level, const char *prefix, val_rrsig_rdata_t *rdata);
void val_log_dnskey_rdata (val_context_t *ctx, int level, const char *prefix, val_dnskey_rdata_t *rdata);
void val_log_assertion_chain(val_context_t *ctx, int level, u_char *name_n, u_int16_t class_h, u_int16_t type_h,
                struct query_chain *queries, struct val_result *results);
void val_log (val_context_t *ctx, int level, const char *template, ...);
char *p_query_error(int errno);
char *p_val_error(int valerrno);

/* from val_x_query.h */
int val_x_query(val_context_t *ctx,
            const char *domain_name,
            const u_int16_t class,
            const u_int16_t type,
            const u_int8_t flags,
            struct response_t *resp,
            int *resp_count);
                                                                                                                             
int val_query ( const char *domain_name, int class, int type,
        unsigned char *answer, int anslen, int flags,
        int *dnssec_status );

/* from val_gethostbyname.h */
/**
 * A function to extract DNSSEC-validation status information from a
 * (struct hostent *) variable.  Note: This variable must be returned
 * from the val_gethostbyname() function.
 */
int val_get_hostent_dnssec_status ( const struct hostent *hentry );

/* A function to free memory allocated by val_gethostbyname() and
 * val_duphostent()
 */
void val_freehostent ( struct hostent *hentry );

/* A function to duplicate a hostent structure.  Performs a
 * deep-copy of the hostent structure.  The returned value
 * must be freed using the val_freehostent() function.
 */
struct hostent* val_duphostent ( const struct hostent *hentry );

/*
 * Returns the entry from the hosts file and DNS for host with name.
 * If DNSSEC validation is successful, *dnssec_status will contain
 * VALIDATE_SUCCESS
 * If there is a failure, *dnssec_status will contain the validator
 * error code.  Applications can use the FREE_HOSTENT() macro given
 * above to free the returned hostent structure.
 */
struct hostent *val_gethostbyname ( const char *name, int *h_errnop );
struct hostent *val_x_gethostbyname ( val_context_t *ctx, const char *name,
				      int *h_errnop );

/* from val_getaddrinfo.h */

/* val_get_addrinfo_dnssec_status()
 * A function to extract DNSSEC-validation status information from a
 * (struct addrinfo *) variable.  Note: This variable must be returned
 * from the val_getaddrinfo() or the val_dupaddrinfo() function.
 */
int val_get_addrinfo_dnssec_status (const struct addrinfo *ainfo);

/* val_dupaddrinfo();
 * A function to duplicate an addrinfo structure.  Performs a
 * deep-copy of the entire addrinfo list.  The returned value
 * must be freed using the freeaddrinfo() function.    Note: The
 * input parameter must be one previously returned by a call to
 * the val_getaddrinfo() or the val_dupaddrinfo() function.
 */
struct addrinfo* val_dupaddrinfo (const struct addrinfo *ainfo);

/* A function to free memory allocated by val_getaddrinfo() and
 * val_dupaddrinfo()
 */
void val_freeaddrinfo (struct addrinfo *ainfo);

/**
 * val_getaddrinfo: A validating getaddrinfo function.
 *                  Based on getaddrinfo() as defined in RFC3493.
 *
 * Parameters:
 *     Note: All the parameters, except the dnssec_status parameter,
 *     ----  are similar to the getaddrinfo function.
 *
 *     [IN]  node: Specifies either a numerical network address (dotted-
 *                decimal format for IPv4, hexadecimal format for IPv6)
 *                or a network hostname, whose network addresses are
 *                looked up and resolved.
 *                node or service parameter, but not both, may be NULL.
 *     [IN]  service: Used to set the port number in the network address
 *                of each socket structure returned.  If service is NULL
 *                the  port  number will be left uninitialized.
 *     [IN]  hints: Specifies  the  preferred socket type, or protocol.
 *                A NULL hints specifies that any network address or
 *                protocol is acceptable.
 *     [OUT] res: Points to a dynamically-allocated link list of addrinfo
 *                structures, linked by the ai_next member.  This output
 *                value can be used in the val_get_addrinfo_dnssec_status()
 *                and the val_dupaddrinfo() functions.
 *
 * Return value: This function returns 0 if it succeeds, or one of the
 *               non-zero error codes if it fails.  See man getaddrinfo
 *               for more details.
 */
int val_getaddrinfo ( const char *nodename, const char *servname,
		      const struct addrinfo *hints,
		      struct addrinfo **res );

/*
 * val_x_getaddrinfo: Extended version of val_getaddrinfo that provides
 *                    optimization.
 *
 * Parameters:
 *     [IN] ctx: The validation context.
 *
 * Other parameters and return values are similar to the val_getaddrinfo
 * function.
 */
int val_x_getaddrinfo ( val_context_t *ctx,
		        const char *nodename, const char *servname,
			const struct addrinfo *hints,
			struct addrinfo **res );

#define VAL_CONFIGURATION_FILE	"/etc/dnsval.conf"
#define RESOLV_CONF             "/etc/resolv.conf"
#define ROOT_HINTS              "/etc/root.hints"
#define VAL_LOG_MASK	LOG_INFO

#ifdef LOG_TO_NETWORK
#define VALIDATOR_LOG_PORT 1053
#define VALIDATOR_LOG_SERVER "127.0.0.1"
#endif /*LOG_TO_NETWORK*/

#endif /* VALIDATOR_H */
