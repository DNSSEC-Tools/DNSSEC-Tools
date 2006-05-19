
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_ERRORS_H
#define VAL_ERRORS_H

#include <resolver.h>
#include <validator.h>

#define NO_ERROR 0


/*
 *************************************************** 
 * Process error codes 
 *************************************************** 
 */
#define ERROR	-1 /* Generic error */
#define NOT_IMPLEMENTED	-2	/* Functionality not yet implemented */
#define OUT_OF_MEMORY -3 /*Could not allocate memory.*/
#define BAD_ARGUMENT -4 /*Bad arguments passed as parameters.*/
#define INTERNAL_ERROR -5 /*Encountered some internal error.*/
#define NO_PERMISSION	-6 /*No permission to perform operation.*/
#define RESOURCE_UNAVAILABLE -7	/*Some resource (crypto possibly) was unavailable.*/
#define CONF_PARSE_ERROR -8 /*Error in parsing some configuration file.*/ 
#define NO_POLICY -9	/*Could not find one or both of the configuration files*/
#define NO_SPACE -10 /*Not enough space for storing all available answers.*/
#define UNKNOWN_LOCALE -11 /*Could not identify the policy to which we need to switch.*/	

/* 
 *************************************************** 
 * Assertion initial states 
 *************************************************** 
 */
#define A_DONT_KNOW 0 
#define A_CAN_VERIFY 1 
#define A_WAIT_FOR_TRUST 2 
#define A_WAIT_FOR_RRSIG  3
#define A_INIT 4
#define A_NEGATIVE_PROOF 5 
#define A_LAST_STATE  10 /* Closest round number above A_NEGATIVE_PROOF */

/* 
 *************************************************** 
 * Validator return codes 
 *************************************************** 
 */

/* "Cannot do anything further" states */
#define ERROR_BASE    			A_LAST_STATE /* 10 */
#define DATA_MISSING			(ERROR_BASE+1)
#define RRSIG_MISSING 			(ERROR_BASE+2)
#define DNSKEY_MISSING 			(ERROR_BASE+3)
#define DS_MISSING	 			(ERROR_BASE+4)
#define NO_TRUST_ANCHOR 		(ERROR_BASE+5)
#define UNTRUSTED_ZONE	 		(ERROR_BASE+6)
#define IRRELEVANT_PROOF		(ERROR_BASE+7)
#define DNSSEC_VERSION_ERROR	(ERROR_BASE+8)
#define TOO_MANY_LINKS	 		(ERROR_BASE+9)
#define UNKNOWN_DNSKEY_PROTO  	(ERROR_BASE+10)
#define FLOOD_ATTACK_DETECTED	(ERROR_BASE+11)

#define DNS_ERROR_BASE			(ERROR_BASE+15)
/* 
 * DNS errors lie within this range, 
 * there are SR_LAST_ERROR (22) of them in total
 */
#define SR_REFERRAL_ERROR       (SR_LAST_ERROR+1) /* one more DNS error for referral failures */ 
#define SR_MISSING_GLUE         (SR_LAST_ERROR+2) /* one more DNS error for referral failures */ 
#define SR_CONFLICTING_ANSWERS  (SR_LAST_ERROR+3)
#define DNS_ERROR_LAST			(DNS_ERROR_BASE + SR_CONFLICTING_ANSWERS)
#define LAST_ERROR				DNS_ERROR_LAST /* ERROR_BASE+40 */ 

/* "Error, but can prove the chain-of-trust above this" states */
#define FAIL_BASE				LAST_ERROR /* ERROR_BASE+40 */ 
#define DNSKEY_NOMATCH			(FAIL_BASE+1) /*RRSIG was created by a DNSKEY that does not exist in the apex keyset.*/
#define WRONG_LABEL_COUNT  		(FAIL_BASE+2) /*The number of labels on the signature is greater than the the count given in the RRSIG RDATA.*/
#define SECURITY_LAME	  		(FAIL_BASE+3) /*RRSIG created by a key that does not exist in the parent DS record set.*/
#define NOT_A_ZONE_KEY	 		(FAIL_BASE+4) /*The key used to verify the RRSIG is not a zone key, but some other key such as the public key used for TSIG.*/
#define RRSIG_NOTYETACTIVE	 	(FAIL_BASE+5) /*The RRSIG's inception time is in the future.*/
#define RRSIG_EXPIRED	 		(FAIL_BASE+6) /*The RRSIG has expired.*/
#define ALGO_NOT_SUPPORTED	 	(FAIL_BASE+7) /* Algorithm in DNSKEY or RRSIG or DS is not supported.*/
#define UNKNOWN_ALGO	 		(FAIL_BASE+8)	/* Unknown DNSKEY or RRSIG or DS algorithm */ 
#define RRSIG_VERIFIED	 		(FAIL_BASE+9)  /* The RRSIG verified successfully.*/ 
#define RRSIG_VERIFY_FAILED		(FAIL_BASE+10) /*The RRSIG did not verify.*/ 
#define NOT_VERIFIED 			(FAIL_BASE+11) /*Different RRSIGs failed for different reasons */ 
#define KEY_TOO_LARGE			(FAIL_BASE+12) /*The zone is using a key size that is too large as per local policy.*/
#define KEY_TOO_SMALL 			(FAIL_BASE+13) /*The zone is using a key size that is too small as per local policy*/
#define KEY_NOT_AUTHORIZED		(FAIL_BASE+14) /*The zone is using a key that is not authorized as per local policy.*/
#define ALGO_REFUSED			(FAIL_BASE+15) /*Algorithm in DNSKEY or RRSIG or DS is not allowed as per local policy */
#define CLOCK_SKEW				(FAIL_BASE+16) /*Verified but with clock skew taken into account*/
#define DUPLICATE_KEYTAG		(FAIL_BASE+17) /*Two DNSKEYs have the same keytag*/
#define NO_PREFERRED_SEP		(FAIL_BASE+18) /*There is no DNSKEY in the parent DS set that our local policy allows us to traverse*/
#define WRONG_RRSIG_OWNER		(FAIL_BASE+19) /* The RRSIG and the data that it purportedly covers have differing notions of owner name*/
#define RRSIG_ALGO_MISMATCH 	(FAIL_BASE+20) /* The DNSKEY and RRSIG pair have a mismatch in their algorithm.*/
#define KEYTAG_MISMATCH			(FAIL_BASE+21) /* The DNSKEY and RRSIG pair have a mismatch in their key tags*/
#define LAST_FAILURE			(FAIL_BASE+30) /* ERROR_BASE + 70 */

/* success results conditions */
#define VERIFIED				(LAST_FAILURE+1) /* This is a transient state, it will settle at VALIDATED_SUCCESS if the
chain of trust can be completed */ 
#define LOCAL_ANSWER			(LAST_FAILURE+2)	/* Answer obtained locally */
#define TRUST_KEY	 			(LAST_FAILURE+3) /* key is trusted */ 
#define TRUST_ZONE				(LAST_FAILURE+4) /* zone is trusted */
#define BARE_RRSIG 				(LAST_FAILURE+5) /* No DNSSEC validation possible, query was for a RRSIG.*/
#define LAST_SUCCESS			(LAST_FAILURE+10) /* ERROR_BASE + 80 */


/* 
 *************************************************** 
 * Result  codes 
 *************************************************** 
 */

#define R_DONT_KNOW	0

#define R_INDETERMINATE         1         
#define R_INDETERMINATE_DS      R_INDETERMINATE /* Can't prove that the DS is trusted */
#define R_INDETERMINATE_PROOF   R_INDETERMINATE /* Some intermediate Proof of non-existence obtained - dont know if answer exists and proof is bogus or answer is bogus.  */
#define R_INCOMPLETE_PROOF      R_INDETERMINATE /* Proof does not have all required components */
#define R_BOGUS                  2
#define R_BOGUS_PROOF            R_BOGUS /* proof cannot be validated */
#define R_BOGUS_UNPROVABLE       R_BOGUS /* Bogus result */
#define R_BOGUS_PROVABLE	    (R_BOGUS | R_TRUST_FLAG)
#define R_VERIFIED_CHAIN         3 /* All components were verified */
#define R_VALIDATED_CHAIN       (R_VERIFIED_CHAIN | R_TRUST_FLAG)     
#define R_LAST                   4

#define VAL_LOCAL_ANSWER         (R_LAST+1)
#define VAL_BARE_RRSIG           (R_LAST+2)
#define VAL_NONEXISTENT_NAME     (R_LAST+3)
#define VAL_NONEXISTENT_TYPE     (R_LAST+4)
#define VAL_ERROR                (R_LAST+5)
#define VAL_PROVABLY_UNSECURE    (R_LAST+6)


#define VAL_DNS_ERROR_BASE	     (R_LAST+7)
/* 
 * DNS errors lie within this range, 
 */
#define VAL_DNS_ERROR_LAST		(VAL_DNS_ERROR_BASE + DNS_ERROR_LAST)

#define VAL_INDETERMINATE        R_INDETERMINATE
#define VAL_BOGUS                R_BOGUS
#define VAL_NOTRUST              R_VERIFIED_CHAIN
#define VAL_SUCCESS              R_VALIDATED_CHAIN


#endif /* VAL_ERRORS_H */
