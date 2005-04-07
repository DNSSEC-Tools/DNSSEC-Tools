/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is a header file for data structures and functions for parsing
 * DNSSEC Resource Records.
 */

#ifndef VAL_PARSE_H
#define VAL_PARSE_H

#include <arpa/nameser.h>
#include <resolver.h>

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

/* Parse a domain name */
int val_parse_dname(const unsigned char *buf, int buflen, int offset,
		    char *dname);

/* Parse the rdata portion of a DNSKEY resource record */
int val_parse_dnskey_rdata (const unsigned char *buf, int buflen,
			    val_dnskey_rdata_t *rdata);

/* Parse the rdata portion of an RRSIG resource record */
int val_parse_rrsig_rdata (const unsigned char *buf, int buflen,
			   val_rrsig_rdata_t *rdata);

/* Get rrset in canonical form */
int val_get_canon_rrset (struct rrset_rec *rrset,
			 const unsigned int orig_ttl,
			 unsigned char *rrBuf,
			 int BUFLEN);
#endif
