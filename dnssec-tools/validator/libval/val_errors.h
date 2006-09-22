
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_ERRORS_H
#define VAL_ERRORS_H

#include <resolver.h>
#include <validator.h>

#define VAL_NO_ERROR 0


/*
 *************************************************** 
 * Process error codes 
 *************************************************** 
 */
#define VAL_GENERIC_ERROR	-1 /* Generic error */
#define VAL_NOT_IMPLEMENTED	-2	/* Functionality not yet implemented */
#define VAL_RESOURCE_UNAVAILABLE -3	/*Some resource (crypto or memory possibly) was unavailable.*/
#define VAL_BAD_ARGUMENT -4 /*Bad arguments passed as parameters.*/
#define VAL_INTERNAL_ERROR -5 /*Encountered some internal error.*/
#define VAL_NO_PERMISSION	-6 /*No permission to perform operation.*/
#define VAL_OUT_OF_MEMORY VAL_RESOURCE_UNAVAILABLE /*Could not allocate memory.*/
#define VAL_CONF_PARSE_ERROR -8 /*Error in parsing some configuration file.*/ 
#define VAL_CONF_NOT_FOUND -9	/*Could not find one or both of the configuration files*/
#define VAL_NO_POLICY -10 /*Could not identify the policy to which we need to switch.*/	

/* 
 *************************************************** 
 * Assertion initial states 
 *************************************************** 
 */
#define VAL_A_DONT_KNOW 0 
#define VAL_A_CAN_VERIFY 1 
#define VAL_A_WAIT_FOR_TRUST 2 
#define VAL_A_WAIT_FOR_RRSIG 3 
#define VAL_A_INIT 4
#define VAL_A_NEGATIVE_PROOF 5 
#define VAL_A_DONT_VALIDATE 6
#define VAL_A_LAST_STATE  10 /* Closest round number above A_NEGATIVE_PROOF */

/* 
 *************************************************** 
 * Validator return codes 
 *************************************************** 
 */

/* "Cannot do anything further" states, but should check proof of non existence */
#define VAL_A_ERROR_BASE VAL_A_LAST_STATE /* 10 */
#define VAL_A_DATA_MISSING (VAL_A_ERROR_BASE+1)
#define VAL_A_RRSIG_MISSING (VAL_A_ERROR_BASE+2)
#define VAL_A_DNSKEY_MISSING (VAL_A_ERROR_BASE+3)
#define VAL_A_DS_MISSING (VAL_A_ERROR_BASE+4)
#define VAL_A_UNTRUSTED_ZONE (VAL_A_ERROR_BASE+5)
#define VAL_A_LAST_ERROR VAL_A_UNTRUSTED_ZONE

/* error and dont want to check if provably unsecure either */
#define VAL_A_BAD_BASE VAL_A_LAST_ERROR
#define VAL_A_IRRELEVANT_PROOF (VAL_A_BAD_BASE+1)
#define VAL_A_DNSSEC_VERSION_ERROR (VAL_A_BAD_BASE+2)
#define VAL_A_TOO_MANY_LINKS (VAL_A_BAD_BASE+3)
#define VAL_A_UNKNOWN_DNSKEY_PROTO (VAL_A_BAD_BASE+4)
#define VAL_A_FLOOD_ATTACK_DETECTED	(VAL_A_BAD_BASE+5)
#define VAL_A_DNS_ERROR_BASE (VAL_A_BAD_BASE+10)
/* 
 * DNS errors lie within this range, 
 * there are SR_LAST_ERROR (22) of them in total
 */
#define SR_REFERRAL_ERROR (SR_LAST_ERROR+1) /* one more DNS error for referral failures */ 
#define SR_MISSING_GLUE (SR_LAST_ERROR+2) /* one more DNS error for referral failures */ 
#define SR_CONFLICTING_ANSWERS (SR_LAST_ERROR+3)
#define VAL_A_DNS_ERROR_LAST (VAL_A_DNS_ERROR_BASE + SR_CONFLICTING_ANSWERS)

#define VAL_A_LAST_BAD VAL_A_DNS_ERROR_LAST /* VAL_A_ERROR_BASE+40 */ 

/* "Error, but can prove the chain-of-trust above this" states */
#define VAL_A_FAIL_BASE VAL_A_LAST_BAD /* VAL_A_ERROR_BASE+40 */ 
#define VAL_A_DNSKEY_NOMATCH (VAL_A_FAIL_BASE+1) /*RRSIG was created by a DNSKEY that does not exist in the apex keyset.*/
#define VAL_A_WRONG_LABEL_COUNT (VAL_A_FAIL_BASE+2) /*The number of labels on the signature is greater than the the count given in the RRSIG RDATA.*/
#define VAL_A_SECURITY_LAME (VAL_A_FAIL_BASE+3) /*RRSIG created by a key that does not exist in the parent DS record set.*/
#define VAL_A_NOT_A_ZONE_KEY (VAL_A_FAIL_BASE+4) /*The key used to verify the RRSIG is not a zone key, but some other key such as the public key used for TSIG.*/
#define VAL_A_RRSIG_NOTYETACTIVE (VAL_A_FAIL_BASE+5) /*The RRSIG's inception time is in the future.*/
#define VAL_A_RRSIG_EXPIRED	(VAL_A_FAIL_BASE+6) /*The RRSIG has expired.*/
#define VAL_A_ALGO_NOT_SUPPORTED (VAL_A_FAIL_BASE+7) /* Algorithm in DNSKEY or RRSIG or DS is not supported.*/
#define VAL_A_UNKNOWN_ALGO (VAL_A_FAIL_BASE+8)	/* Unknown DNSKEY or RRSIG or DS algorithm */ 
#define VAL_A_RRSIG_VERIFIED (VAL_A_FAIL_BASE+9)  /* The RRSIG verified successfully.*/ 
#define VAL_A_RRSIG_VERIFY_FAILED (VAL_A_FAIL_BASE+10) /*The RRSIG did not verify.*/ 
#define VAL_A_NOT_VERIFIED (VAL_A_FAIL_BASE+11) /*Different RRSIGs failed for different reasons */ 
#define VAL_A_KEY_TOO_LARGE (VAL_A_FAIL_BASE+12) /*The zone is using a key size that is too large as per local policy.*/
#define VAL_A_KEY_TOO_SMALL (VAL_A_FAIL_BASE+13) /*The zone is using a key size that is too small as per local policy*/
#define VAL_A_KEY_NOT_AUTHORIZED (VAL_A_FAIL_BASE+14) /*The zone is using a key that is not authorized as per local policy.*/
#define VAL_A_ALGO_REFUSED (VAL_A_FAIL_BASE+15) /*Algorithm in DNSKEY or RRSIG or DS is not allowed as per local policy */
#define VAL_A_CLOCK_SKEW (VAL_A_FAIL_BASE+16) /*Verified but with clock skew taken into account*/
#define VAL_A_DUPLICATE_KEYTAG (VAL_A_FAIL_BASE+17) /*Two DNSKEYs have the same keytag*/
#define VAL_A_NO_PREFERRED_SEP (VAL_A_FAIL_BASE+18) /*There is no DNSKEY in the parent DS set that our local policy allows us to traverse*/
#define VAL_A_WRONG_RRSIG_OWNER (VAL_A_FAIL_BASE+19) /* The RRSIG and the data that it purportedly covers have differing notions of owner name*/
#define VAL_A_RRSIG_ALGO_MISMATCH (VAL_A_FAIL_BASE+20) /* The DNSKEY and RRSIG pair have a mismatch in their algorithm.*/
#define VAL_A_KEYTAG_MISMATCH (VAL_A_FAIL_BASE+21) /* The DNSKEY and RRSIG pair have a mismatch in their key tags*/
#define VAL_A_LAST_FAILURE (VAL_A_FAIL_BASE+30) /* VAL_A_ERROR_BASE + 70 */

/* success or unknown result conditions */
#define VAL_A_VERIFIED (VAL_A_LAST_FAILURE+1) /* This is a transient state, it will settle at
VALIDATED_SUCCESS if the */
#define VAL_A_VERIFIED_LINK (VAL_A_LAST_FAILURE+2) /* This is a transient state, it will settle at VALIDATED_SUCCESS if the chain of trust can be completed */ 
#define VAL_A_LOCAL_ANSWER (VAL_A_LAST_FAILURE+3)	/* Answer obtained locally */
#define VAL_A_TRUST_KEY (VAL_A_LAST_FAILURE+4) /* key is trusted */ 
#define VAL_A_TRUST_ZONE (VAL_A_LAST_FAILURE+5) /* zone is trusted */
#define VAL_A_PROVABLY_UNSECURE (VAL_A_LAST_FAILURE+6)
#define VAL_A_BARE_RRSIG (VAL_A_LAST_FAILURE+7) /* No DNSSEC validation possible, query was for a RRSIG.*/
#define VAL_A_NO_TRUST_ANCHOR (VAL_A_LAST_FAILURE+8) /* No trust anchor available, but components were verified */

/* 
 *************************************************** 
 * Result  codes (ephemeral) 
 *************************************************** 
 */

#define VAL_R_DONT_KNOW	0

#define VAL_R_INDETERMINATE 1         
#define VAL_R_INDETERMINATE_DS VAL_R_INDETERMINATE /* Can't prove that the DS is trusted */
#define VAL_R_INDETERMINATE_PROOF  VAL_R_INDETERMINATE /* Some intermediate Proof of non-existence obtained - dont know if answer exists and proof is bogus or answer is bogus.  */
#define VAL_R_BOGUS 2
#define VAL_R_BOGUS_PROOF VAL_R_BOGUS /* proof cannot be validated */
#define VAL_R_INCOMPLETE_PROOF VAL_R_BOGUS /* Proof does not have all required components */
#define VAL_R_BOGUS_UNPROVABLE VAL_R_BOGUS /* Bogus result */
#define VAL_R_BOGUS_PROVABLE (VAL_R_BOGUS | VAL_R_TRUST_FLAG)
#define VAL_R_VERIFIED_CHAIN 3 /* All components were verified */
#define VAL_R_VALIDATED_CHAIN (VAL_R_VERIFIED_CHAIN | VAL_R_TRUST_FLAG)     
#define VAL_R_PROVABLY_UNSECURE 4
#define VAL_R_LAST 5

/* 
 *************************************************** 
 * Result  codes (final) 
 *************************************************** 
 */

#define VAL_LOCAL_ANSWER (VAL_R_LAST+1)
#define VAL_BARE_RRSIG (VAL_R_LAST+2)
#define VAL_NONEXISTENT_NAME (VAL_R_LAST+3)
#define VAL_NONEXISTENT_TYPE (VAL_R_LAST+4)
#define VAL_ERROR (VAL_R_LAST+5)
#ifdef LIBVAL_NSEC3 
#define VAL_NONEXISTENT_NAME_OPTOUT (VAL_R_LAST+6)
#define VAL_DNS_ERROR_BASE (VAL_R_LAST+7)
#else
#define VAL_DNS_ERROR_BASE (VAL_R_LAST+6)
#endif

/* 
 * DNS errors lie within this range, 
 */
#define VAL_DNS_ERROR_LAST (VAL_DNS_ERROR_BASE + SR_CONFLICTING_ANSWERS)

#define VAL_INDETERMINATE VAL_R_INDETERMINATE
#define VAL_BOGUS VAL_R_BOGUS
#define VAL_PROVABLY_UNSECURE (VAL_R_PROVABLY_UNSECURE | VAL_R_TRUST_FLAG)
#define VAL_NOTRUST VAL_R_VERIFIED_CHAIN 
#define VAL_SUCCESS VAL_R_VALIDATED_CHAIN

#endif /* VAL_ERRORS_H */
