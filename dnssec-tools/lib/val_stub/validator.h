#ifndef VALIDATOR_H
#define VALIDATOR_H

/* Types of keys in the key store */
#define TRUSTED_KEY XX
#define LEARNED_KEY XX

/* Policies associated with Keys */
#define	CANNOT_BE_USED			0x00				
#define CAN_SIGN_KEY			0x01
#define CAN_SIGN_ZONE			0x02
#define CAN_SIGN_ZONE_AND_KEY 	CAN_SIGN_KEY|CAN_SIGN_ZONE 

/* signature status internal errors */
#define SIG_KEY_NOT_AVAILABLE 	1
#define SIG_BAD_LABEL_COUNT 2
#define SIG_PROCESS_ERR 3 
#define SIG_DS_NOMATCH 4 

/* Different validation result types */
#define ANSWER	XX
#define CNAME	XX
#define DNAME	XX
#define NSEC_PROOF	XX
#define SOA_PROOF	XX

/* Incomplete Assertion states */
#define A_CAN_VERIFY 1 
#define A_WAIT_FOR_TRUST 2 
#define A_WAIT_FOR_RRSIG  3
#define A_INIT 4
/* Complete Assertion states */
#define A_VERIFY_FAILED 6
#define A_VERIFIED 7
#define A_VALIDATED 8
#define A_NOTVALIDATED 9
#define A_BARE_RRSIG 10
#define A_NO_DATA 11
#define A_NO_RRSIG 12
#define A_TRUSTED 13
#define A_NO_TRUST_ANCHOR 14
#define A_NONSENSE_ANSWER	15
#define A_INCOMPLETE	16

/* Query states */
#define Q_INIT	1
#define Q_SENT	2
#define Q_ANSWERED 3
#define Q_ERROR 4


/* Trust anchor matching */
#define EXACT 1
#define NO_MORE	2 /* we don't have this key configured and no point checking further*/
#define NOT_YET 3

#define SIGNBY              18
#define ENVELOPE            10
#define TTL					4





typedef struct val_context {
	struct res_policy *resolver_policy;
} val_context_t;

struct query_chain; /* forward declaration */

struct assertion_chain {

	u_int16_t ac_state;
	struct rrset_rec *ac_data;
	struct query_chain *ac_pending_query;
	struct assertion_chain *ac_more_data;
	struct assertion_chain *ac_trust;
	struct assertion_chain *ac_next;
};


struct query_chain {
	u_char qc_name_n[MAXCDNAME];
	u_int16_t qc_type_h;
	u_int16_t qc_class_h;
	u_int16_t qc_state; /* DOS, TIMED_OUT, etc */
	struct assertion_chain *qc_as;
	struct query_chain *qc_next;
};

struct response_t {
	u_int8_t *response;
	int	response_length;
	int validation_result;
};


#endif /* VALIDATOR_H */
