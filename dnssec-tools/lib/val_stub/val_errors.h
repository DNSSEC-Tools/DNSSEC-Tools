
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_ERRORS_H
#define VAL_ERRORS_H


/* 
 ***********************************
 * Validator return values
 ***********************************
 */
/* Generic */
#define NO_ERROR 0

/* 
 ***********************************
 * Validator error values
 ***********************************
 */

#define NOT_IMPLEMENTED	-1	/* Functionality not yet implemented */
#define OUT_OF_MEMORY -2
#define BAD_ARGUMENT -3
#define INTERNAL_ERROR -4
#define NO_PERMISSION	-5
#define RESOURCE_UNAVAILABLE -6	
#define CONF_PARSE_ERROR -7 
#define NO_POLICY -8	

#define MALFORMED_LOCALE -20
#define UNKNOWN_LOCALE	-21
#define FILE_ERROR	-22

/* 
 ***********************************
 * Validator results
 ***********************************
 */

/* Validation of an RR/message */
#define VALIDATE_SUCCESS	 1
#define BOGUS	 2
#define INDETERMINATE	 3 /* 
							* Don't know if zone is unsigned or signatures 
							* and other records have been stripped 
							*/
#define PROVABLY_UNSECURE	 4
#define SECURITY_LAME	 5 /*DNSKEY-DS mapping failure */
#define NAME_EXPANSION_FAILURE	 6


/* 
 ***********************************
 * Transient results
 ***********************************
 */



#define NO_PREFERRED_SEP	 7
#define NO_TRUST_ANCHOR	 8
#define TOO_MANY_LINKS	 9
#define TRUST_ANCHOR_TIMEOUT	10
/* Non-existence */
#define OVERREACHING_NSEC	11
#define NSEC_POINTING_UPWARDS	12
#define IRRELEVANT_PROOF	13
#define INCOMPLETE_PROOF	14
#define PROVED_OWNERNAME_MISSING	15
#define PROVED_TYPE_MISSING	16



/* Verification of signatures */
#define RRSIG_VERIFIED	17
#define RRSIG_VERIFY_FAILED	18
#define BARE_RRSIG	19
#define RRSIG_EXPIRED	20
#define RRSIG_NOTYETACTIVE	21
#define KEY_TOO_LARGE 22
#define KEY_TOO_SMALL 23
#define KEY_NOT_AUTHORIZED 24
#define NOT_A_ZONE_KEY	25
#define CLOCK_SKEW		26 
#define ALGO_REFUSED	27
#define UNAUTHORIZED_SIGNER	28

#define RRSIG_MISSING	29
#define DNSKEY_MISSING	30
#define	DS_MISSING	31
#define NSEC_MISSING 32
#define DUPLICATE_KEYTAG	33
#define CONFLICTING_PROOFS	34 /* Two validated NSECs describe different things */

#define UNKNOWN_ALGO	35 /* DNSKEY or RRSIG or DS */
#define ALGO_NOT_SUPPORTED	36
#define WRONG_RRSIG_OWNER	37
#define KEYTAG_MISMATCH	38
#define UNKNOWN_DNSKEY_PROTO 39
#define DNS_FAILURE	40
#define WAITING 41
#define WAKEUP 42
#define FLOOD_ATTACK_DETECTED	43	


#define INSUFFICIENT_DATA	XX


/* 
 ***********************************
 * Parsing messages
 ***********************************
 */
#define HEADER_ERROR	XX // Generic header error
#define WRONG_LABEL_COUNT	XX
#define EDNS_VERSION_ERROR	XX
#define UNSUPP_ENDS0_LABEL	XX
#define DNSSEC_VERSION_ERROR	XX 
#define SUSPICIOUS_BIT	XX  // Information hiding?

char *p_val_error(int errno);

#endif /* VAL_ERRORS_H */
