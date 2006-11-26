
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_ERRORS_H
#define VAL_ERRORS_H

#include <resolver.h>
#include <validator.h>

#define VAL_FLAG_CHAIN_COMPLETE 0x80
#define VAL_MASKED_FLAG_CHAIN_COMPLETE 0x7f
#define SET_CHAIN_COMPLETE(status)         status |= VAL_FLAG_CHAIN_COMPLETE
#define SET_MASKED_STATUS(st, new_val)     st = (st & VAL_FLAG_CHAIN_COMPLETE) | new_val
#define CHECK_MASKED_STATUS(st, chk_val) ((st & VAL_MASKED_FLAG_CHAIN_COMPLETE) == chk_val)

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
 * Assertion states 
 *************************************************** 
 */
#define VAL_AC_UNSET                0
#define VAL_AC_CAN_VERIFY           1
#define VAL_AC_WAIT_FOR_TRUST       2
#define VAL_AC_WAIT_FOR_RRSIG       3
#define VAL_AC_INIT                 4
#define VAL_AC_NEGATIVE_PROOF       5

#define VAL_AC_DONT_GO_FURTHER      6 
#define VAL_AC_IGNORE_VALIDATION    (VAL_AC_DONT_GO_FURTHER+0) 
#define VAL_AC_TRUSTED_ZONE         (VAL_AC_DONT_GO_FURTHER+1)
#define VAL_AC_UNTRUSTED_ZONE       (VAL_AC_DONT_GO_FURTHER+2)
#define VAL_AC_LOCAL_ANSWER         (VAL_AC_DONT_GO_FURTHER+3) /* Answer obtained locally */
#define VAL_AC_TRUST_KEY            (VAL_AC_DONT_GO_FURTHER+4)  /* key is trusted */
#define VAL_AC_PROVABLY_UNSECURE    (VAL_AC_DONT_GO_FURTHER+5) 
#define VAL_AC_BARE_RRSIG           (VAL_AC_DONT_GO_FURTHER+6) /* No DNSSEC validation possible, query was for a RRSIG. */
#define VAL_AC_NO_TRUST_ANCHOR      (VAL_AC_DONT_GO_FURTHER+7)    /* No trust anchor available, but components were verified */
#define VAL_AC_LAST_STATE           VAL_AC_NO_TRUST_ANCHOR    

/*
 *************************************************** 
 * Validator return codes 
 *************************************************** 
 */

/*
 * Cannot do anything further, but should check proof of non existence 
 */
#define VAL_AC_ERROR_BASE VAL_AC_LAST_STATE       /* 13 */
#define VAL_AC_DATA_MISSING (VAL_AC_ERROR_BASE+1)
#define VAL_AC_RRSIG_MISSING (VAL_AC_ERROR_BASE+2)
#define VAL_AC_DNSKEY_MISSING (VAL_AC_ERROR_BASE+3)
#define VAL_AC_DS_MISSING (VAL_AC_ERROR_BASE+4)
#define VAL_AC_LAST_ERROR VAL_AC_DS_MISSING

/*
 * Cannot do anything further and should not check proof of non existence 
 */
#define VAL_AC_BAD_BASE VAL_AC_LAST_ERROR /* 17 */
#define VAL_AC_UNKNOWN_DNSKEY_PROTOCOL (VAL_AC_BAD_BASE+1)
#define VAL_AC_DNS_ERROR_BASE (VAL_AC_BAD_BASE+8) /* 25 */
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
 * DNSSEC Error, but can prove the chain-of-trust above this 
 */
#define VAL_AC_FAIL_BASE VAL_AC_LAST_BAD  /* 50 */
#define VAL_AC_NOT_VERIFIED (VAL_AC_FAIL_BASE+1) /*Different RRSIGs failed for different reasons */

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
 * success conditions, but must continue with validation 
 */
#define VAL_AC_VERIFIED (VAL_AC_LAST_FAILURE+1)   /* This is a transient state, it will settle at
                                                 * VALIDATED_SUCCESS if the */
/* This signature status on success contains the following */
#define VAL_AC_RRSIG_VERIFIED (VAL_AC_LAST_FAILURE+2)        /* The RRSIG verified successfully. */
#define VAL_AC_WCARD_VERIFIED (VAL_AC_LAST_FAILURE+3)        /* The RRSIG verified successfully after wildcard expansion. */
#define VAL_AC_SIGNING_KEY (VAL_AC_LAST_FAILURE+4) 
#define VAL_AC_VERIFIED_LINK (VAL_AC_LAST_FAILURE+5)      /* This is a transient state, it will settle at VALIDATED_SUCCESS if the chain of trust can be completed */
#define VAL_AC_UNKNOWN_ALGORITHM_LINK (VAL_AC_LAST_FAILURE+6)      /* This is a transient state, it will settle at VALIDATED_SUCCESS if the chain of trust can be completed */


/*
 *************************************************** 
 * Result  codes 
 *************************************************** 
 */

#define VAL_DONT_KNOW	0

#define VAL_INDETERMINATE 1
#define VAL_INDETERMINATE_DS VAL_INDETERMINATE      /* Can't prove that the DS is trusted */
#define VAL_INDETERMINATE_PROOF  VAL_INDETERMINATE  /* Some intermediate Proof of non-existence obtained - dont know if answer exists and proof is bogus or answer is bogus.  */

#define VAL_BOGUS 2
#define VAL_BOGUS_PROOF VAL_BOGUS   /* proof cannot be validated */
#define VAL_INCOMPLETE_PROOF VAL_BOGUS      /* Proof does not have all required components */
#define VAL_IRRELEVANT_PROOF VAL_BOGUS      /* Proof is not relevant */
#define VAL_BOGUS_UNPROVABLE VAL_BOGUS      /* Bogus result */

#define VAL_VERIFIED_CHAIN 3  /* All components were verified */
#define VAL_NOTRUST VAL_VERIFIED_CHAIN

#define VAL_DNS_ERROR_BASE   4 
/*
 * DNS errors lie within this range, 
 */
#define VAL_DNS_ERROR_LAST (VAL_DNS_ERROR_BASE + SR_CONFLICTING_ANSWERS)

#define VAL_ERROR (VAL_DNS_ERROR_LAST+1) 

#define VAL_DONT_GO_FURTHER   (VAL_DONT_KNOW | VAL_FLAG_CHAIN_COMPLETE)

#define VAL_SUCCESS           (VAL_VERIFIED_CHAIN | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_BOGUS_PROVABLE    (VAL_BOGUS | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_PROVABLY_UNSECURE ((VAL_ERROR+1) | VAL_FLAG_CHAIN_COMPLETE) 
#define VAL_IGNORE_VALIDATION ((VAL_ERROR+2) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_TRUSTED_ZONE      ((VAL_ERROR+3) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_UNTRUSTED_ZONE    ((VAL_ERROR+4) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_LOCAL_ANSWER      ((VAL_ERROR+5) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_BARE_RRSIG        ((VAL_ERROR+6) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_NONEXISTENT_NAME  ((VAL_ERROR+7) | VAL_FLAG_CHAIN_COMPLETE) 
#define VAL_NONEXISTENT_TYPE  ((VAL_ERROR+8) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_NONEXISTENT_NAME_NOCHAIN  ((VAL_ERROR+9)  | VAL_FLAG_CHAIN_COMPLETE) 
#define VAL_NONEXISTENT_TYPE_NOCHAIN  ((VAL_ERROR+10) | VAL_FLAG_CHAIN_COMPLETE)
#ifdef LIBVAL_NSEC3
#define VAL_NONEXISTENT_NAME_OPTOUT   ((VAL_ERROR+11) | VAL_FLAG_CHAIN_COMPLETE) 
#endif


#endif                          /* VAL_ERRORS_H */
