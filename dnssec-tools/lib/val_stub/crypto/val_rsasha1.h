/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is header file for the RSA/SHA-1 algorithm support.
 */

#ifndef VAL_RSASHA1_H
#define VAL_RSASHA1_H

#include <val_parse.h>

int rsasha1_sigverify (const unsigned char *data,
		       int data_len,
		       const val_dnskey_rdata_t dnskey,
		       const val_rrsig_rdata_t rrsig);

#endif
