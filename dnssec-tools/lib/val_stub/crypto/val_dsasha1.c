/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the implementation for the DSA/SHA-1 algorithm signature
 * verification
 *
 * See RFC 2536
 */

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/objects.h> /* For NID_sha1 */
#include <strings.h>
#include <string.h>
#include <ctype.h>

#include <val_errors.h>
#include "val_dsasha1.h"

/* Returns VALIDATE_SUCCESS on success, other values on failure */
static int dsasha1_parse_public_key (const unsigned char *buf,
				     int buflen,
				     DSA *dsa)
{
    u_int8_t T;
    int index = 0;
    BIGNUM *bn_p, *bn_q, *bn_g, *bn_y;

    if (!dsa) return INDETERMINATE;

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

    return VALIDATE_SUCCESS; /* success */
}

int dsasha1_sigverify (const unsigned char *data,
		       int data_len,
		       const val_dnskey_rdata_t dnskey,
		       const val_rrsig_rdata_t rrsig)
{
    DSA *dsa = NULL;
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    int i;

    printf("dsasha1_sigverify(): parsing the public key...\n");
    if ((dsa = DSA_new()) == NULL) {
	printf("dsasha1_sigverify could not allocate dsa structure.\n");
	return INDETERMINATE;
    };

    if (dsasha1_parse_public_key(dnskey.public_key, dnskey.public_key_len,
				 dsa) != VALIDATE_SUCCESS) {
	printf("dsasha1_sigverify(): Error in parsing public key.  Returning INDETERMINATE\n");
	DSA_free(dsa);
	return INDETERMINATE;
    }

    printf("dsasha1_sigverify(): computing SHA-1 hash...\n");
    bzero(sha1_hash, SHA_DIGEST_LENGTH);
    SHA1(data, data_len, (unsigned char *) sha1_hash);
    printf("hash = 0x");
    for (i=0; i<SHA_DIGEST_LENGTH; i++) {
	printf("%02x", sha1_hash[i]);
    }
    printf("\n");

    printf("dsasha1_sigverify(): verifying DSA signature...\n");

    if (DSA_verify(NID_sha1, (unsigned char *) sha1_hash, SHA_DIGEST_LENGTH,
		   rrsig.signature, rrsig.signature_len, dsa)) {
	printf("DSA_verify returned SUCCESS\n");
	DSA_free(dsa);
	return VALIDATE_SUCCESS;
    }
    else {
	printf("DSA_verify returned FAILURE\n");
	DSA_free(dsa);
	return INDETERMINATE;
    }   
}
