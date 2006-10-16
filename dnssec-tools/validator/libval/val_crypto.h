/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 */

#ifndef VAL_CRYPTO_H
#define VAL_CRYPTO_H

#include <val_parse.h>

int dsasha1_sigverify (val_context_t *ctx,
				const unsigned char *data,
		       int data_len,
		       const val_dnskey_rdata_t dnskey,
		       const val_rrsig_rdata_t rrsig);

int rsamd5_sigverify (val_context_t *ctx,
				const unsigned char *data,
		      int data_len,
		      const val_dnskey_rdata_t dnskey,
		      const val_rrsig_rdata_t rrsig);

u_int16_t rsamd5_keytag (const unsigned char *pubkey,
			 int pubkey_len);

int rsasha1_sigverify (val_context_t *ctx,
				const unsigned char *data,
		       int data_len,
		       const val_dnskey_rdata_t dnskey,
		       const val_rrsig_rdata_t rrsig);

int ds_sha_hash_is_equal(u_int8_t * name_n, 
                     u_int8_t *rrdata, 
                     u_int16_t  rrdatalen,
                     u_int8_t * ds_hash);
#ifdef LIBVAL_NSEC3 
u_int8_t * nsec3_sha_hash_compute( u_int8_t *qc_name_n, u_int8_t *salt, u_int8_t saltlen,
        u_int16_t iter, u_int8_t **hash, u_int8_t *hashlen);
#endif

char    * get_base64_string(unsigned char *message, int message_len, char *buf,
                  int bufsize);

int decode_base64_key(char *keyptr, u_char *public_key, int keysize);

#endif
