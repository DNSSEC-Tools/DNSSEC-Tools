/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is header file for the RSA/MD5 algorithm support.
 */

#ifndef VAL_RSAMD5_H
#define VAL_RSAMD5_H

#include <val_parse.h>

int rsamd5_sigverify (const unsigned char *data,
		       int data_len,
		       const val_dnskey_rdata_t dnskey,
		       const val_rrsig_rdata_t rrsig);
u_int16_t rsamd5_keytag (const unsigned char *pubkey,
			 int pubkey_len);
#endif
