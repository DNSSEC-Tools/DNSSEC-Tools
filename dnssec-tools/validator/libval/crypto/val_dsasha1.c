/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the implementation for the DSA/SHA-1 algorithm signature
 * verification
 *
 * See RFC 2536
 */
#include "validator-config.h"

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/objects.h> /* For NID_sha1 */
#include <strings.h>
#include <string.h>
#include <ctype.h>

#include <validator.h>
#include <val_log.h>
#include "val_dsasha1.h"

/* Returns VAL_NO_ERROR on success, other values on failure */
static int dsasha1_parse_public_key (const unsigned char *buf,
				     int buflen,
				     DSA *dsa)
{
	u_int8_t T;
	int index = 0;
	BIGNUM *bn_p, *bn_q, *bn_g, *bn_y;
	
	if (!dsa) {
		return VAL_INTERNAL_ERROR;
	}
	
	T = (u_int8_t)(buf[index]);
	index++;
	
	bn_q = BN_bin2bn(buf + index, 20, NULL);
	index += 20;
	
	bn_p = BN_bin2bn(buf + index, 64 + (T*8), NULL);
	index += (64 + (T*8));
	
	bn_g = BN_bin2bn(buf + index, 64 + (T*8), NULL);
	index += (64 + (T*8));
	
	bn_y = BN_bin2bn(buf + index, 64 + (T*8), NULL);
	index += (64 + (T*8));
	
	dsa->p       = bn_p;
	dsa->q       = bn_q;
	dsa->g       = bn_g;
	dsa->pub_key = bn_y;
	
	return VAL_NO_ERROR; /* success */
}

int dsasha1_sigverify (val_context_t *ctx,
				const unsigned char *data,
		       int data_len,
		       const val_dnskey_rdata_t dnskey,
		       const val_rrsig_rdata_t rrsig)
{
	char buf[1028];
	int buflen = 1024;
	DSA *dsa = NULL;
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
	
	val_log(ctx, LOG_DEBUG, "dsasha1_sigverify(): parsing the public key...");
	if ((dsa = DSA_new()) == NULL) {
		val_log(ctx, LOG_DEBUG, "dsasha1_sigverify could not allocate dsa structure.");
		return VAL_OUT_OF_MEMORY;
	};
	
	if (dsasha1_parse_public_key(dnskey.public_key, dnskey.public_key_len,
				     dsa) != VAL_NO_ERROR) {
		val_log(ctx, LOG_DEBUG, "dsasha1_sigverify(): Error in parsing public key.  Returning INDETERMINATE");
		DSA_free(dsa);
		return VAL_INTERNAL_ERROR;
	}
	
	bzero(sha1_hash, SHA_DIGEST_LENGTH);
	SHA1(data, data_len, (unsigned char *) sha1_hash);
	val_log(ctx, LOG_DEBUG, "dsasha1_sigverify(): SHA-1 hash = %s", 
				get_hex_string(sha1_hash, SHA_DIGEST_LENGTH, buf, buflen));

	val_log(ctx, LOG_DEBUG, "dsasha1_sigverify(): verifying DSA signature...");
	
	if (DSA_verify(NID_sha1, (unsigned char *) sha1_hash, SHA_DIGEST_LENGTH,
		       rrsig.signature, rrsig.signature_len, dsa)) {
		val_log(ctx, LOG_DEBUG, "DSA_verify returned SUCCESS");
		DSA_free(dsa);
		return VAL_A_RRSIG_VERIFIED;
	}
	else {
		val_log(ctx, LOG_DEBUG, "DSA_verify returned FAILURE");
		DSA_free(dsa);
		return VAL_A_RRSIG_VERIFY_FAILED;
	}   
}
