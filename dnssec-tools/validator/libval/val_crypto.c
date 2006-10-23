/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the implementation for the DSA/SHA-1 algorithm signature
 * verification, the implementation for the RSA/MD5 algorithm signature
 * verification and the implementation for the RSA/SHA-1 algorithm signature
 * verification
 *
 * See RFC 2537, RFC 3110, RFC 4034 Appendix B.1, RFC 2536
 */
#include "validator-config.h"

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h> /* For NID_sha1 */
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include <validator.h>
#include "val_log.h"
#include "val_crypto.h"
#include "val_support.h"


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

void dsasha1_sigverify (val_context_t *ctx,
				const unsigned char *data,
		       int data_len,
		       const val_dnskey_rdata_t dnskey,
		       const val_rrsig_rdata_t rrsig,
               val_astatus_t *key_status,
               val_astatus_t *sig_status)
{
	char buf[1028];
	int buflen = 1024;
	DSA *dsa = NULL;
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
	
	val_log(ctx, LOG_DEBUG, "dsasha1_sigverify(): parsing the public key...\n");
	if ((dsa = DSA_new()) == NULL) {
		val_log(ctx, LOG_DEBUG, "dsasha1_sigverify could not allocate dsa structure.\n");
        *key_status = VAL_A_INVALID_KEY;
        return;
	};
	
	if (dsasha1_parse_public_key(dnskey.public_key, dnskey.public_key_len,
				     dsa) != VAL_NO_ERROR) {
		val_log(ctx, LOG_DEBUG, "dsasha1_sigverify(): Error in parsing public key.\n");
		DSA_free(dsa);
        *key_status = VAL_A_INVALID_KEY;
		return;
	}
	
	bzero(sha1_hash, SHA_DIGEST_LENGTH);
	SHA1(data, data_len, (unsigned char *) sha1_hash);
	val_log(ctx, LOG_DEBUG, "dsasha1_sigverify(): SHA-1 hash = %s", 
				get_hex_string(sha1_hash, SHA_DIGEST_LENGTH, buf, buflen));

	val_log(ctx, LOG_DEBUG, "dsasha1_sigverify(): verifying DSA signature...\n");
	
	if (DSA_verify(NID_sha1, (unsigned char *) sha1_hash, SHA_DIGEST_LENGTH,
		       rrsig.signature, rrsig.signature_len, dsa)) {
		val_log(ctx, LOG_DEBUG, "DSA_verify returned SUCCESS\n");
		DSA_free(dsa);
        *sig_status = VAL_A_RRSIG_VERIFIED;
	}
	else {
		val_log(ctx, LOG_DEBUG, "DSA_verify returned FAILURE\n");
		DSA_free(dsa);
        *sig_status = VAL_A_RRSIG_VERIFY_FAILED;
	}   
    return;
}

/* Returns VAL_NO_ERROR on success, other values on failure */
static int rsamd5_parse_public_key (const unsigned char *buf,
				    int buflen,
				    RSA *rsa)
{
	int index = 0;
	const u_char *cp;
	u_int16_t exp_len = 0x0000;
	BIGNUM *bn_exp;
	BIGNUM *bn_mod;
	
	if (!rsa) return VAL_INTERNAL_ERROR;
	
	cp = buf;
	
#if 1
	if ((u_int8_t)(buf[index]) == (u_int8_t) 0) {
		index += 1;
		cp = (buf + index);
		VAL_GET16(exp_len, cp);
		index += 2;
	}
	else {
#endif
		exp_len += (u_int8_t)(buf[index]);
		index += 1;
#if 1
	}
#endif
	
	/* Extract the exponent */
	bn_exp = BN_bin2bn(buf + index, exp_len, NULL);
	
	index += exp_len;
	
	/* Extract the modulus */
	bn_mod = BN_bin2bn(buf + index, buflen - index, NULL);
	
	rsa->e = bn_exp;
	rsa->n = bn_mod;
	
	return VAL_NO_ERROR; /* success */
}

/* See RFC 4034, Appendix B.1 :
 *
 * " For a DNSKEY RR with algorithm 1, the key tag is defined to be the most
 *   significant 16 bits of the least significant 24 bits in the public
 *   key modulus (in other words, the 4th to last and 3rd to last octets
 *   of the public key modulus)."
 */
u_int16_t rsamd5_keytag (const unsigned char *pubkey,
			 int pubkey_len)
{
	RSA *rsa = NULL;
	BIGNUM *modulus;
	u_int16_t keytag = 0x0000;
	unsigned char *modulus_bin;
	int modulus_len;
	
	if ((rsa = RSA_new()) == NULL) {
		return VAL_OUT_OF_MEMORY;
	};
	
	if (rsamd5_parse_public_key(pubkey, pubkey_len,
				    rsa) != VAL_NO_ERROR) {
		RSA_free(rsa);
		return VAL_INTERNAL_ERROR;
	}
	
	modulus = rsa->n;
	modulus_len = BN_num_bytes(modulus);
	modulus_bin = (unsigned char *) MALLOC (modulus_len * sizeof(unsigned char));
	
	BN_bn2bin(modulus, modulus_bin);
	
	keytag = ((0x00ff & modulus_bin[modulus_len - 3]) << 8) |
		(0x00ff & modulus_bin[modulus_len - 2]);

	FREE(modulus_bin);
	RSA_free(rsa);
	return keytag;
}

void rsamd5_sigverify (val_context_t *ctx,
			   const unsigned char *data,
		       int data_len,
		       const val_dnskey_rdata_t dnskey,
		       const val_rrsig_rdata_t rrsig,
               val_astatus_t *sig_status,
               val_astatus_t *key_status)
{
	char buf[1028];
	int buflen = 1024;
	RSA *rsa = NULL;
	unsigned char md5_hash[MD5_DIGEST_LENGTH];
	
	val_log(ctx, LOG_DEBUG, "rsamd5_sigverify(): parsing the public key...\n");
	if ((rsa = RSA_new()) == NULL) {
		val_log(ctx, LOG_DEBUG, "rsamd5_sigverify could not allocate rsa structure.\n");
        *key_status = VAL_A_INVALID_KEY;
		return;
	};
	
	if (rsamd5_parse_public_key(dnskey.public_key, dnskey.public_key_len,
				    rsa) != VAL_NO_ERROR) {
		val_log(ctx, LOG_DEBUG, "rsamd5_sigverify(): Error in parsing public key.\n");
		RSA_free(rsa);
        *key_status = VAL_A_INVALID_KEY;
		return;
	}
	
	bzero(md5_hash, MD5_DIGEST_LENGTH);
	MD5(data, data_len, (unsigned char *) md5_hash);
	val_log(ctx, LOG_DEBUG, "rsamd5_sigverify(): MD5 hash = %s", 
				get_hex_string(md5_hash, MD5_DIGEST_LENGTH, buf, buflen));
	
	val_log(ctx, LOG_DEBUG, "rsamd5_sigverify(): verifying RSA signature...\n");
	
	if (RSA_verify(NID_md5, (unsigned char *) md5_hash, MD5_DIGEST_LENGTH,
		       rrsig.signature, rrsig.signature_len, rsa)) {
		val_log(ctx, LOG_DEBUG, "RSA_verify returned SUCCESS\n");
		RSA_free(rsa);
        *sig_status = VAL_A_RRSIG_VERIFIED;
	}
	else {
		val_log(ctx, LOG_DEBUG, "RSA_verify returned FAILURE\n");
		RSA_free(rsa);
        *sig_status = VAL_A_RRSIG_VERIFY_FAILED;
	}   
    return;
}
/* Returns VAL_NO_ERROR on success, other values on failure */
static int rsasha1_parse_public_key (const unsigned char *buf,
				     int buflen,
				     RSA *rsa)
{
	int index = 0;
	const u_char *cp;
	u_int16_t exp_len = 0x0000;
	BIGNUM *bn_exp;
	BIGNUM *bn_mod;
	
	if (!rsa) return VAL_INTERNAL_ERROR;
	
	cp = buf;
	
	if ((u_int8_t)(buf[index]) == (u_int8_t) 0) {
		index += 1;
		cp = (buf + index);
		VAL_GET16(exp_len, cp);
		index += 2;
	}
	else {
		exp_len += (u_int8_t)(buf[index]);
		index += 1;
	}
	
	/* Extract the exponent */
	bn_exp = BN_bin2bn(buf + index, exp_len, NULL);
	index += exp_len;
	
	/* Extract the modulus */
	bn_mod = BN_bin2bn(buf + index, buflen - index, NULL);
	
	rsa->e = bn_exp;
	rsa->n = bn_mod;
	
	return VAL_NO_ERROR; /* success */
}

void rsasha1_sigverify (val_context_t *ctx,
			   const unsigned char *data,
		       int data_len,
		       const val_dnskey_rdata_t dnskey,
		       const val_rrsig_rdata_t rrsig,
               val_astatus_t *sig_status,
               val_astatus_t *key_status)
{
	char buf[1028];
	int buflen = 1024;
	RSA *rsa = NULL;
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
	
	val_log(ctx, LOG_DEBUG, "rsasha1_sigverify(): parsing the public key...\n");
	if ((rsa = RSA_new()) == NULL) {
		val_log(ctx, LOG_DEBUG, "rsasha1_sigverify could not allocate rsa structure.\n");
        *key_status = VAL_A_INVALID_KEY;
		return;
	};
	
	if (rsasha1_parse_public_key(dnskey.public_key, dnskey.public_key_len,
				     rsa) != VAL_NO_ERROR) {
		val_log(ctx, LOG_DEBUG, "rsasha1_sigverify(): Error in parsing public key.\n");
		RSA_free(rsa);
        *key_status = VAL_A_INVALID_KEY;
		return;
	}
	
	bzero(sha1_hash, SHA_DIGEST_LENGTH);
	SHA1(data, data_len, (unsigned char *) sha1_hash);
	val_log(ctx, LOG_DEBUG, "rsasha1_sigverify(): SHA-1 hash = %s", 
				get_hex_string(sha1_hash, SHA_DIGEST_LENGTH, buf, buflen));

	val_log(ctx, LOG_DEBUG, "rsasha1_sigverify(): verifying RSA signature...\n");
	
	if (RSA_verify(NID_sha1, (unsigned char *) sha1_hash, SHA_DIGEST_LENGTH,
		       rrsig.signature, rrsig.signature_len, rsa)) {
		val_log(ctx, LOG_DEBUG, "RSA_verify returned SUCCESS\n");
		RSA_free(rsa);
        *sig_status = VAL_A_RRSIG_VERIFIED;
	}
	else {
		val_log(ctx, LOG_DEBUG, "RSA_verify returned FAILURE\n");
		RSA_free(rsa);
        *sig_status = VAL_A_RRSIG_VERIFY_FAILED;
	}
    return;
}

int
ds_sha_hash_is_equal(u_int8_t * name_n, 
                     u_int8_t *rrdata, 
                     u_int16_t  rrdatalen,
                     u_int8_t * ds_hash)
{
    u_int8_t        ds_digest[SHA_DIGEST_LENGTH];
    int             namelen;
    SHA_CTX         c;

    if (rrdata == NULL)
        return 0;

    namelen = wire_name_length(name_n);

    memset(ds_digest, SHA_DIGEST_LENGTH, 0);

    SHA1_Init(&c);
    SHA1_Update(&c, name_n, namelen);
    SHA1_Update(&c, rrdata, rrdatalen);
    SHA1_Final(ds_digest, &c);

    if (!memcmp(ds_digest, ds_hash, SHA_DIGEST_LENGTH))
        return 1;

    return 0;
}

#ifdef LIBVAL_NSEC3 
u_int8_t *
nsec3_sha_hash_compute( u_int8_t *qc_name_n, u_int8_t *salt, u_int8_t saltlen,
        u_int16_t iter, u_int8_t **hash, u_int8_t *hashlen)
{
    /*
     * Assume that the caller has already performed all sanity checks 
     */
    SHA_CTX         c;
    int i;

    *hash = (u_int8_t *) MALLOC(SHA_DIGEST_LENGTH * sizeof(u_int8_t));
    if (*hash == NULL)
        return NULL;
    *hashlen = SHA_DIGEST_LENGTH;

    memset(*hash, 0, SHA_DIGEST_LENGTH);

    /*
     * IH(salt, x, 0) = H( x || salt) 
     */
    SHA1_Init(&c);
    SHA1_Update(&c, qc_name_n, wire_name_length(qc_name_n));
    SHA1_Update(&c, salt, saltlen);
    SHA1_Final(*hash, &c);

    /*
     * IH(salt, x, k) = H(IH(salt, x, k-1) || salt) 
     */
    for (i = 0; i < iter; i++) {
        SHA1_Init(&c);
        SHA1_Update(&c, *hash, *hashlen);
        SHA1_Update(&c, salt, saltlen);
        SHA1_Final(*hash, &c);
    }
    return *hash;
}
#endif

char    *
get_base64_string(unsigned char *message, int message_len, char *buf,
                  int bufsize)
{
    BIO            *b64 = BIO_new(BIO_f_base64());
    BIO            *mem = BIO_new_mem_buf(message, message_len);
    mem = BIO_push(b64, mem);

    if (-1 == BIO_write(mem, buf, bufsize))
        strcpy(buf, "");
    BIO_free_all(mem);

    return buf;
}

int 
decode_base64_key(char *keyptr, u_char *public_key, int keysize)
{
    BIO            *b64;
    BIO            *mem;
    int len;

    b64 = BIO_new(BIO_f_base64());
    mem = BIO_new_mem_buf(keyptr, -1);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    mem = BIO_push(b64, mem);
    len = BIO_read(mem, public_key, keysize);
    BIO_free_all(mem);
    return len;
}
