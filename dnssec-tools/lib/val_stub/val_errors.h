
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_ERRORS_H
#define VAL_ERRORS_H

#include "validator.h"

char *p_val_error(int valerrno);


/*
 *************************************************** 
 * Process error codes 
 *************************************************** 
 */
#define ERROR	-1 /* Generic error */
#define NOT_IMPLEMENTED	-2	/* Functionality not yet implemented */
#define OUT_OF_MEMORY -3
#define BAD_ARGUMENT -4
#define INTERNAL_ERROR -5
#define NO_PERMISSION	-6
#define RESOURCE_UNAVAILABLE -7	
#define CONF_PARSE_ERROR -8 
#define NO_POLICY -9	
#define NO_SPACE -10
#define CONTEXT_ERROR -11

#define MALFORMED_LOCALE -20
#define UNKNOWN_LOCALE	-21
#define FILE_ERROR	-22

/* 
 *************************************************** 
 * Validator return codes 
 *************************************************** 
 */
#define NO_ERROR 0

#define ERROR_BASE    			A_LAST_STATE /* 10 */
/* "Cannot do anything further" states */
#define DATA_MISSING			ERROR_BASE+2
#define DNSKEY_MISSING			ERROR_BASE+3 
#define	DS_MISSING				ERROR_BASE+4	
#define NSEC_MISSING 			ERROR_BASE+5
#define RRSIG_MISSING 			ERROR_BASE+6
#define NO_TRUST_ANCHOR 		ERROR_BASE+7
#define UNTRUSTED_ZONE	 		ERROR_BASE+8
#define IRRELEVANT_PROOF		ERROR_BASE+9
#define GENERIC_ERROR 			ERROR_BASE+10
#define HEADER_ERROR			ERROR_BASE+11		
#define EDNS_VERSION_ERROR		ERROR_BASE+12	
#define UNSUPP_ENDS0_LABEL		ERROR_BASE+13
#define DNSSEC_VERSION_ERROR	ERROR_BASE+14
#define SUSPICIOUS_BIT			ERROR_BASE+15
#define NAME_EXPANSION_FAILURE	ERROR_BASE+16
#define TOO_MANY_LINKS	 		ERROR_BASE+17 
#define UNKNOWN_DNSKEY_PROTO  	ERROR_BASE+18
#define FLOOD_ATTACK_DETECTED	ERROR_BASE+19	

#define DNS_ERROR_BASE			ERROR_BASE+20
/* 
 * DNS errors lie within this range, 
 * there are SR_LAST_ERROR of them in total
 */
#define LAST_ERROR				DNS_ERROR_BASE+SR_LAST_ERROR 

/* "Error, but can prove the chain-of-trust above this" states */
#define FAIL_BASE				LAST_ERROR /* ERROR_BASE+40 */ 
#define DNSKEY_NOMATCH			FAIL_BASE+1		
#define WRONG_LABEL_COUNT  		FAIL_BASE+2
#define VERIFY_PROC_ERROR	 	FAIL_BASE+3
#define SECURITY_LAME	  		FAIL_BASE+4	/*DNSKEY-DS mapping failure */ 
#define NOT_A_ZONE_KEY	 		FAIL_BASE+5
#define RRSIG_NOTYETACTIVE	 	FAIL_BASE+6
#define RRSIG_EXPIRED	 		FAIL_BASE+7
#define ALGO_NOT_SUPPORTED	 	FAIL_BASE+8
#define UNKNOWN_ALGO	 		FAIL_BASE+9	/* DNSKEY or RRSIG or DS */ 
#define RRSIG_VERIFIED	 		FAIL_BASE+10
#define RRSIG_VERIFY_FAILED		FAIL_BASE+11
#define NOT_VERIFIED 			FAIL_BASE+12 	/* One or more failures */ 
#define KEY_TOO_LARGE			FAIL_BASE+13 
#define KEY_TOO_SMALL 			FAIL_BASE+14
#define KEY_NOT_AUTHORIZED		FAIL_BASE+15
#define ALGO_REFUSED			FAIL_BASE+16
#define CLOCK_SKEW				FAIL_BASE+17
#define DUPLICATE_KEYTAG		FAIL_BASE+18
#define NO_PREFERRED_SEP		FAIL_BASE+19
#define WRONG_RRSIG_OWNER		FAIL_BASE+20
#define RRSIG_ALGO_MISMATCH 	FAIL_BASE+21
#define KEYTAG_MISMATCH			FAIL_BASE+22
#define LAST_FAILURE			FAIL_BASE+30 /* ERROR_BASE + 70 */

/* success results conditions */
#define VERIFIED				LAST_FAILURE+1 
#define VALIDATE_SUCCESS  		LAST_FAILURE+2	/* TRUSTED AND no error */
#define LOCAL_ANSWER			LAST_FAILURE+3	/* Answer obtained locally */
#define TRUST_KEY	 			LAST_FAILURE+4 
#define TRUST_ZONE				LAST_FAILURE+5 
#define BARE_RRSIG 				LAST_FAILURE+6
#define LAST_SUCCESS			LAST_FAILURE+10 /* ERROR_BASE + 80 */

/* failure result conditions */
#define BOGUS  					LAST_SUCCESS+1	/* NOT_VERIFIED but not trusted */
#define VALIDATION_ERROR  		LAST_SUCCESS+2	
#define INCOMPLETE_PROOF 		LAST_SUCCESS+3	/* Proof does not have all required components */
#define NONEXISTENT_NAME 		LAST_SUCCESS+4	/* TRUSTED AND proof present */
#define NONEXISTENT_TYPE 		LAST_SUCCESS+5	/* TRUSTED AND proof present */
#define BOGUS_PROOF 			LAST_SUCCESS+6	/* proof cannot be validated */
#define INDETERMINATE_DS 		LAST_SUCCESS+7	/* Can't prove that the DS is trusted */
#define INDETERMINATE_PROOF		LAST_SUCCESS+8	/* Some intermediate Proof of non-existence obtained 
													- dont know if answer exists and proof is bogus
													  or answer is bogus.  */
#define INDETERMINATE_ERROR		LAST_SUCCESS+9	/* Error sequence */
#define INDETERMINATE_TRUST		LAST_SUCCESS+10 /* Dont know if trust is absent or answer is bogus */
#define INDETERMINATE_ZONE		LAST_SUCCESS+11 /* Dont know if zone is unsigned or sigs have been stripped */
#define INDETERMINATE	INDETERMINATE_TRUST


#endif /* VAL_ERRORS_H */
