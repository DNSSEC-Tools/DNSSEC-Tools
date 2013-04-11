
/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_ERRORS_H
#define VAL_ERRORS_H

#ifdef __cplusplus
extern          "C" {
#endif

#define VAL_FLAG_CHAIN_COMPLETE 0x80
#define VAL_MASKED_FLAG_CHAIN_COMPLETE 0x7f
#define SET_CHAIN_COMPLETE(status)         (status |= VAL_FLAG_CHAIN_COMPLETE)
#define SET_MASKED_STATUS(st, new_val)     (st = (st & VAL_FLAG_CHAIN_COMPLETE) | new_val)
#define CHECK_MASKED_STATUS(st, chk_val) ((st & VAL_MASKED_FLAG_CHAIN_COMPLETE) == chk_val)

#define VAL_NO_ERROR 0

/*
 *************************************************** 
 * Process error codes 
 *************************************************** 
 */
#define VAL_NOT_IMPLEMENTED	-1 
#define VAL_ENOSYS VAL_NOT_IMPLEMENTED

#define VAL_RESOURCE_UNAVAILABLE -2 
#define VAL_OUT_OF_MEMORY VAL_RESOURCE_UNAVAILABLE 
#define VAL_ENOMEM VAL_RESOURCE_UNAVAILABLE

#define VAL_BAD_ARGUMENT -3  
#define VAL_EINVAL VAL_BAD_ARGUMENT

#define VAL_INTERNAL_ERROR -4 

#define VAL_NO_PERMISSION	-5 
#define VAL_EACCESS VAL_NO_PERMISSION

#define VAL_CONF_PARSE_ERROR -6

#define VAL_CONF_NOT_FOUND -7 
#define VAL_ENOENT VAL_CONF_NOT_FOUND

#define VAL_NO_POLICY -8 


/*
 *************************************************** 
 * Validator states 
 *************************************************** 
 */

#define VAL_AC_UNSET   0

/*
 * Transient states
 */
#define VAL_AC_CAN_VERIFY           1
#define VAL_AC_WAIT_FOR_TRUST       2
#define VAL_AC_WAIT_FOR_RRSIG       3
#define VAL_AC_TRUST_NOCHK          4
#define VAL_AC_INIT                 5
#define VAL_AC_NEGATIVE_PROOF       6
#define VAL_AC_DONT_GO_FURTHER      7

/*
 * End states 
 */

#define VAL_AC_IGNORE_VALIDATION    (VAL_AC_DONT_GO_FURTHER+0)
#define VAL_AC_UNTRUSTED_ZONE       (VAL_AC_DONT_GO_FURTHER+1)
#define VAL_AC_PINSECURE            (VAL_AC_DONT_GO_FURTHER+2)
#define VAL_AC_BARE_RRSIG           (VAL_AC_DONT_GO_FURTHER+3) 
#define VAL_AC_NO_LINK              (VAL_AC_DONT_GO_FURTHER+4)
#define VAL_AC_TRUST_ANCHOR         VAL_AC_NO_LINK  /* backwards compatibility */
#define VAL_AC_TRUST                (VAL_AC_DONT_GO_FURTHER+5) 
#define VAL_AC_LAST_STATE           VAL_AC_TRUST


/*
 * Cannot do anything further, but should check proof of non existence 
 */
#define VAL_AC_ERROR_BASE VAL_AC_LAST_STATE     /* 12 */
#define VAL_AC_RRSIG_MISSING (VAL_AC_ERROR_BASE+1)
#define VAL_AC_DNSKEY_MISSING (VAL_AC_ERROR_BASE+2)
#define VAL_AC_DS_MISSING (VAL_AC_ERROR_BASE+3)
#define VAL_AC_LAST_ERROR VAL_AC_DS_MISSING


/*
 * Cannot do anything further and should not check proof of non existence 
 */
#define VAL_AC_BAD_BASE VAL_AC_LAST_ERROR       /* 15 */
#define VAL_AC_DATA_MISSING (VAL_AC_BAD_BASE+1)
#define VAL_AC_DNS_ERROR (VAL_AC_BAD_BASE+2)
#define VAL_AC_LAST_BAD VAL_AC_DNS_ERROR 


/*
 * DNSSEC Error, but can prove the chain-of-trust above this 
 */

#define VAL_AC_FAIL_BASE VAL_AC_LAST_BAD        /* 17 */
#define VAL_AC_NOT_VERIFIED (VAL_AC_FAIL_BASE+1) 

/* -- only related to signature */
#define VAL_AC_WRONG_LABEL_COUNT (VAL_AC_FAIL_BASE+2)  
#define VAL_AC_INVALID_RRSIG (VAL_AC_FAIL_BASE+3)     
#define VAL_AC_RRSIG_NOTYETACTIVE (VAL_AC_FAIL_BASE+4) 
#define VAL_AC_RRSIG_EXPIRED	(VAL_AC_FAIL_BASE+5)  
#define VAL_AC_RRSIG_VERIFY_FAILED (VAL_AC_FAIL_BASE+6) 
#define VAL_AC_RRSIG_ALGORITHM_MISMATCH (VAL_AC_FAIL_BASE+7) 
#define VAL_AC_DNSKEY_NOMATCH (VAL_AC_FAIL_BASE+8) 

/* -- only related to key */
#define VAL_AC_UNKNOWN_DNSKEY_PROTOCOL (VAL_AC_FAIL_BASE+9)
#define VAL_AC_DS_NOMATCH (VAL_AC_FAIL_BASE+10)  
#define VAL_AC_INVALID_KEY (VAL_AC_FAIL_BASE+11)

/* -- only related to DS */
#define VAL_AC_INVALID_DS (VAL_AC_FAIL_BASE+12)

/* -- related to signature, key and DS */
#define VAL_AC_ALGORITHM_NOT_SUPPORTED (VAL_AC_FAIL_BASE+13) 

#define VAL_AC_LAST_FAILURE (VAL_AC_ALGORITHM_NOT_SUPPORTED)       /* 30 */



/*
 * success conditions, but must continue with validation 
 */

#define VAL_AC_VERIFIED (VAL_AC_LAST_FAILURE+1) 


/* -- only related to the signature */
#define VAL_AC_RRSIG_VERIFIED (VAL_AC_LAST_FAILURE+2)  
#define VAL_AC_WCARD_VERIFIED (VAL_AC_LAST_FAILURE+3) 
#define VAL_AC_RRSIG_VERIFIED_SKEW (VAL_AC_LAST_FAILURE+4)  
#define VAL_AC_WCARD_VERIFIED_SKEW (VAL_AC_LAST_FAILURE+5) 

/* -- only related to the key */
#define VAL_AC_TRUST_POINT (VAL_AC_LAST_FAILURE+6)
#define VAL_AC_SIGNING_KEY (VAL_AC_LAST_FAILURE+7)
#define VAL_AC_VERIFIED_LINK (VAL_AC_LAST_FAILURE+8) 
#define VAL_AC_UNKNOWN_ALGORITHM_LINK (VAL_AC_LAST_FAILURE+9) /* Obsolete */


/*
 *************************************************** 
 * Result  codes 
 *************************************************** 
 */

#define VAL_DONT_KNOW	0

/* This is a transient state. It will settle at VAL_SUCCESS. */
#define VAL_BARE_TRUST_KEY   (VAL_DONT_KNOW | VAL_FLAG_CHAIN_COMPLETE)

#define VAL_BOGUS 1
#define VAL_BOGUS_PROOF VAL_BOGUS  
#define VAL_INCOMPLETE_PROOF VAL_BOGUS
#define VAL_IRRELEVANT_PROOF VAL_BOGUS 

/* 
 * This is a transient state. It will settle either at 
 * VAL_PINSECURE*, if we find the offending
 * link in the authentication chain to be that for an unknown
 * algorithm in the DS, or at VAL_BOGUS.
 */
#define VAL_BOGUS_PROVABLE    (VAL_BOGUS | VAL_FLAG_CHAIN_COMPLETE)

#define VAL_DNS_ERROR 2 

#define VAL_NOTRUST 3

#define VAL_SUCCESS                     VAL_FLAG_CHAIN_COMPLETE
#define VAL_NONEXISTENT_NAME            ((4) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_NONEXISTENT_TYPE            ((5) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_NONEXISTENT_NAME_NOCHAIN    ((6)  | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_NONEXISTENT_TYPE_NOCHAIN    ((7) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_PINSECURE                   ((8) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_PINSECURE_UNTRUSTED         ((9) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_BARE_RRSIG                  ((10) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_IGNORE_VALIDATION           ((11) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_UNTRUSTED_ZONE              ((12) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_OOB_ANSWER                  ((13) | VAL_FLAG_CHAIN_COMPLETE)

#define VAL_TRUSTED_ANSWER              ((14) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_VALIDATED_ANSWER            ((15) | VAL_FLAG_CHAIN_COMPLETE)
#define VAL_UNTRUSTED_ANSWER            ((16) | VAL_FLAG_CHAIN_COMPLETE)

#ifdef __cplusplus
}                               /* extern "C" */
#endif

#endif                          /* VAL_ERRORS_H */
