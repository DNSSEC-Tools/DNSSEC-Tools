
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_ERRORS_H
#define VAL_ERRORS_H

#include "validator.h"

char *p_val_error(int valerrno);

/* 
 ***********************************
 * Return values
 ***********************************
 */

#define NO_ERROR 0
#define NOT_IMPLEMENTED	-1	/* Functionality not yet implemented */
#define OUT_OF_MEMORY -2
#define BAD_ARGUMENT -3
#define INTERNAL_ERROR -4
#define NO_PERMISSION	-5
#define RESOURCE_UNAVAILABLE -6	
#define CONF_PARSE_ERROR -7 
#define NO_POLICY -8	
#define NO_SPACE -9
#define CONTEXT_ERROR -10

#define MALFORMED_LOCALE -20
#define UNKNOWN_LOCALE	-21
#define FILE_ERROR	-22


/* 
 ***********************************
 * Validator states 
 ***********************************
 */


#define ERROR_BASE    			A_LAST_STATE
/* "Cannot do anything further" states */
#define BARE_RRSIG 				ERROR_BASE+1
#define A_NO_DATA 				ERROR_BASE+2
#define DNSKEY_MISSING			ERROR_BASE+3 
#define	DS_MISSING				ERROR_BASE+4	
#define NSEC_MISSING 			ERROR_BASE+5
#define RRSIG_MISSING 			ERROR_BASE+6
#define NO_TRUST_ANCHOR 		ERROR_BASE+7
#define IRRELEVANT_DATA			ERROR_BASE+8
#define IRRELEVANT_PROOF		ERROR_BASE+9
#define A_ERROR  				ERROR_BASE+10
#define HEADER_ERROR			ERROR_BASE+11		
#define EDNS_VERSION_ERROR		ERROR_BASE+12	
#define UNSUPP_ENDS0_LABEL		ERROR_BASE+13
#define DNSSEC_VERSION_ERROR	ERROR_BASE+14
#define SUSPICIOUS_BIT			ERROR_BASE+15
#define NAME_EXPANSION_FAILURE	ERROR_BASE+16
#define TOO_MANY_LINKS	 		ERROR_BASE+17
#define UNKNOWN_DNSKEY_PROTO  	ERROR_BASE+18
#define FLOOD_ATTACK_DETECTED	ERROR_BASE+19	
#define DNS_FAILURE				ERROR_BASE+20	
#define LAST_ERROR				DNS_FAILURE

#define FAIL_BASE				LAST_ERROR
/* "Error, but can prove the chain-of-trust above this" states */
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
#define LAST_FAILURE			KEYTAG_MISMATCH

/* success results conditions */
#define VERIFIED				LAST_FAILURE+1 
#define VALIDATE_SUCCESS  		LAST_FAILURE+2	/* TRUSTED AND no error */
#define A_LOCAL 				LAST_FAILURE+3	/* Answer obtained locally */
#define LAST_SUCCESS			A_LOCAL

/* failure result conditions */
#define BOGUS  					LAST_SUCCESS+1	/* NOT_VERIFIED but not trusted */
#define INCOMPLETE_PROOF 		LAST_SUCCESS+2	/* Proof does not have all required components */
#define NONEXISTENT  			LAST_SUCCESS+3	/* TRUSTED AND proof present */
#define BOGUS_PROOF 			LAST_SUCCESS+4	/* proof cannot be validated */
#define INDETERMINATE_DS 		LAST_SUCCESS+5	/* Can't prove that the DS is trusted */
#define INDETERMINATE_PROOF		LAST_SUCCESS+6	/* Some intermediate Proof of non-existence obtained 
													- dont know if answer exists and proof is bogus
													  or answer is bogus.  */
#define INDETERMINATE_ERROR		LAST_SUCCESS+7	/* Error sequence */
#define INDETERMINATE_TRUST		LAST_SUCCESS+8	/* Dont know if trust is absent or answer is bogus */
#define INDETERMINATE_ZONE		LAST_SUCCESS+9	/* Dont know if zone is unsigned or sigs have been stripped */
#define INDETERMINATE	INDETERMINATE_TRUST


/*
// need more info about when these conditions can occur
#define OVERREACHING_NSEC	XX
#define UNAUTHORIZED_SIGNER	28
#define CONFLICTING_PROOFS	34 
#define TRUST_ANCHOR_TIMEOUT	XX	
#define WAITING 41
#define WAKEUP 42
#define INSUFFICIENT_DATA	XX
*/


#endif /* VAL_ERRORS_H */
