
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
#define VAL_NOT_IMPLEMENTED	-1      /* Functionality not yet implemented */
#define VAL_RESOURCE_UNAVAILABLE -2     /*Some resource (crypto or memory possibly) was unavailable. */
#define VAL_OUT_OF_MEMORY VAL_RESOURCE_UNAVAILABLE      /*Could not allocate memory. */
#define VAL_BAD_ARGUMENT -3     /*Bad arguments passed as parameters. */
#define VAL_INTERNAL_ERROR -4   /*Encountered some internal error. */
#define VAL_NO_PERMISSION	-5      /*No permission to perform operation. */
#define VAL_CONF_PARSE_ERROR -6 /*Error in parsing some configuration file. */
#define VAL_CONF_NOT_FOUND -7   /*Could not find one or both of the configuration files */
#define VAL_NO_POLICY -8       /*Could not identify the policy to which we need to switch. */

/*
 *************************************************** 
 * Assertion initial states 
 *************************************************** 
 */
#define VAL_AC_UNSET 0
#define VAL_AC_CAN_VERIFY 1
#define VAL_AC_WAIT_FOR_TRUST 2
#define VAL_AC_WAIT_FOR_RRSIG 3
#define VAL_AC_INIT 4
#define VAL_AC_NEGATIVE_PROOF 5
#define VAL_AC_IGNORE_VALIDATION 6
#define VAL_AC_TRUSTED_ZONE 7
#define VAL_AC_LAST_STATE  10    /* Closest round number above A_NEGATIVE_PROOF */

/*
 *************************************************** 
 * Validator return codes 
 *************************************************** 
 */

/*
 * "Cannot do anything further" states, but should check proof of non existence 
 */
#define VAL_AC_ERROR_BASE VAL_AC_LAST_STATE       /* 10 */
#define VAL_AC_DATA_MISSING (VAL_AC_ERROR_BASE+1)
#define VAL_AC_RRSIG_MISSING (VAL_AC_ERROR_BASE+2)
#define VAL_AC_DNSKEY_MISSING (VAL_AC_ERROR_BASE+3)
#define VAL_AC_DS_MISSING (VAL_AC_ERROR_BASE+4)
#define VAL_AC_UNTRUSTED_ZONE (VAL_AC_ERROR_BASE+5)
#define VAL_AC_LAST_ERROR VAL_AC_UNTRUSTED_ZONE

/*
 * error and dont want to check if provably unsecure either 
 */
#define VAL_AC_BAD_BASE VAL_AC_LAST_ERROR /* 15 */
#define VAL_AC_UNKNOWN_DNSKEY_PROTOCOL (VAL_AC_BAD_BASE+1)
#define VAL_AC_DNS_ERROR_BASE (VAL_AC_BAD_BASE+10) /* 25 */
/*
 * DNS errors lie within this range, 
 * there are SR_LAST_ERROR (22) of them in total
 */
#define SR_REFERRAL_ERROR (SR_LAST_ERROR+1)     /* one more DNS error for referral failures */
#define SR_MISSING_GLUE (SR_LAST_ERROR+2)       /* one more DNS error for referral failures */
#define SR_CONFLICTING_ANSWERS (SR_LAST_ERROR+3)       
#define VAL_AC_DNS_ERROR_LAST (VAL_AC_DNS_ERROR_BASE + SR_CONFLICTING_ANSWERS)

#define VAL_AC_LAST_BAD VAL_AC_DNS_ERROR_LAST     /* 50 */

/*
 * "Error, but can prove the chain-of-trust above this" states 
 */
#define VAL_AC_FAIL_BASE VAL_AC_LAST_BAD  /* 50 */
#define VAL_AC_NOT_VERIFIED (VAL_AC_FAIL_BASE+1) /*Different RRSIGs failed for different reasons */

/* The signature status contains the following value */
#define VAL_AC_DNSKEY_NOMATCH (VAL_AC_FAIL_BASE+2)        /*RRSIG was created by a DNSKEY that does not exist in the apex keyset. */
#define VAL_AC_WRONG_LABEL_COUNT (VAL_AC_FAIL_BASE+3)     /*The number of labels on the signature is greater than the the count given in the RRSIG RDATA. */
#define VAL_AC_BAD_DELEGATION (VAL_AC_FAIL_BASE+4) /*RRSIG created by a key that does not exist in the parent DS record set.*/
#define VAL_AC_INVALID_KEY (VAL_AC_FAIL_BASE+5)        /*The key used to verify the RRSIG is not a zone key, or could not be parsed etc. */ 
#define VAL_AC_INVALID_RRSIG (VAL_AC_FAIL_BASE+6)        /*The rrsig could not be parsed etc. */ 
#define VAL_AC_RRSIG_NOTYETACTIVE (VAL_AC_FAIL_BASE+7)    /*The RRSIG's inception time is in the future. */
#define VAL_AC_RRSIG_EXPIRED	(VAL_AC_FAIL_BASE+8)     /*The RRSIG has expired. */
#define VAL_AC_ALGORITHM_NOT_SUPPORTED (VAL_AC_FAIL_BASE+9)    /* Algorithm in DNSKEY or RRSIG or DS is not supported. */
#define VAL_AC_UNKNOWN_ALGORITHM (VAL_AC_FAIL_BASE+10)  /* Unknown DNSKEY or RRSIG or DS algorithm */
#define VAL_AC_RRSIG_VERIFY_FAILED (VAL_AC_FAIL_BASE+11)  /*The RRSIG did not verify. */
#define VAL_AC_KEY_TOO_LARGE (VAL_AC_FAIL_BASE+12)        /*The zone is using a key size that is too large as per local policy. */
#define VAL_AC_KEY_TOO_SMALL (VAL_AC_FAIL_BASE+13)        /*The zone is using a key size that is too small as per local policy */
#define VAL_AC_KEY_NOT_AUTHORIZED (VAL_AC_FAIL_BASE+14)   /*The zone is using a key that is not authorized as per local policy. */
#define VAL_AC_ALGORITHM_REFUSED (VAL_AC_FAIL_BASE+15) /*Algorithm in DNSKEY or RRSIG or DS is not allowed as per local policy */
#define VAL_AC_RRSIG_ALGORITHM_MISMATCH (VAL_AC_FAIL_BASE+17)  /* The DNSKEY and RRSIG pair have a mismatch in their algorithm. */
#define VAL_AC_LAST_FAILURE (VAL_AC_FAIL_BASE+30) /* 80 */

/*
 * success or unknown result conditions 
 */
#define VAL_AC_VERIFIED (VAL_AC_LAST_FAILURE+1)   /* This is a transient state, it will settle at
                                                 * VALIDATED_SUCCESS if the */
/* This signature status on success contains the following */
#define VAL_AC_RRSIG_VERIFIED (VAL_AC_LAST_FAILURE+2)        /* The RRSIG verified successfully. */
#define VAL_AC_WCARD_VERIFIED (VAL_AC_LAST_FAILURE+3)        /* The RRSIG verified successfully after wildcard expansion. */
#define VAL_AC_SIGNING_KEY (VAL_AC_LAST_FAILURE+4) 
#define VAL_AC_VERIFIED_LINK (VAL_AC_LAST_FAILURE+5)      /* This is a transient state, it will settle at VALIDATED_SUCCESS if the chain of trust can be completed */
#define VAL_AC_UNKNOWN_ALGORITHM_LINK (VAL_AC_LAST_FAILURE+6)      /* This is a transient state, it will settle at VALIDATED_SUCCESS if the chain of trust can be completed */

#define VAL_AC_LOCAL_ANSWER (VAL_AC_LAST_FAILURE+7)       /* Answer obtained locally */
#define VAL_AC_TRUST_KEY (VAL_AC_LAST_FAILURE+8)  /* key is trusted */
#define VAL_AC_PROVABLY_UNSECURE (VAL_AC_LAST_FAILURE+9)
#define VAL_AC_BARE_RRSIG (VAL_AC_LAST_FAILURE+10) /* No DNSSEC validation possible, query was for a RRSIG. */
#define VAL_AC_NO_TRUST_ANCHOR (VAL_AC_LAST_FAILURE+11)    /* No trust anchor available, but components were verified */

/*
 *************************************************** 
 * Result  codes (ephemeral) 
 *************************************************** 
 */

#define VAL_R_DONT_KNOW	0

#define VAL_R_INDETERMINATE 1
#define VAL_R_INDETERMINATE_DS VAL_R_INDETERMINATE      /* Can't prove that the DS is trusted */
#define VAL_R_INDETERMINATE_PROOF  VAL_R_INDETERMINATE  /* Some intermediate Proof of non-existence obtained - dont know if answer exists and proof is bogus or answer is bogus.  */
#define VAL_R_BOGUS 2
#define VAL_R_BOGUS_PROOF VAL_R_BOGUS   /* proof cannot be validated */
#define VAL_R_INCOMPLETE_PROOF VAL_R_BOGUS      /* Proof does not have all required components */
#define VAL_R_IRRELEVANT_PROOF VAL_R_BOGUS      /* Proof is not relevant */
#define VAL_R_BOGUS_UNPROVABLE VAL_R_BOGUS      /* Bogus result */
#define VAL_R_BOGUS_PROVABLE (VAL_R_BOGUS | VAL_R_TRUST_FLAG)
#define VAL_R_VERIFIED_CHAIN 3  /* All components were verified */
#define VAL_R_VALIDATED_CHAIN (VAL_R_VERIFIED_CHAIN | VAL_R_TRUST_FLAG)
#define VAL_R_PROVABLY_UNSECURE 4
#define VAL_R_IGNORE_VALIDATION 5
#define VAL_R_TRUSTED_ZONE 6
#define VAL_R_LAST 7

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
#define VAL_IGNORE_VALIDATION (VAL_R_IGNORE_VALIDATION | VAL_R_TRUST_FLAG)
#define VAL_TRUSTED_ZONE (VAL_R_TRUSTED_ZONE | VAL_R_TRUST_FLAG)
#define VAL_NOTRUST VAL_R_VERIFIED_CHAIN
#define VAL_SUCCESS VAL_R_VALIDATED_CHAIN

#endif                          /* VAL_ERRORS_H */
