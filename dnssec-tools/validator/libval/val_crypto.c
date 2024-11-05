/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 */

/*
 * DESCRIPTION
 * This is the implementation for the DSA/SHA-1 algorithm signature
 * verification, the implementation for the RSA/MD5 algorithm signature
 * verification and the implementation for the RSA/SHA-1 algorithm signature
 * verification
 *
 * See RFC 2537, RFC 3110, RFC 4034 Appendix B.1, RFC 2536
 */
#include "validator-internal.h"

#include <openssl/bn.h>
#include <openssl/sha.h>
#ifdef HAVE_CRYPTO_SHA2_H /* netbsd */
#include <crypto/sha2.h>
#endif
#include <openssl/dsa.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif /* !defined(OPENSSL_NO_ENGINE) */
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>    /* For NID_sha1 */


#ifdef HAVE_SHA_2
#ifdef HAVE_OPENSSL_ECDSA_H
#include <openssl/ecdsa.h>
#endif
#include <openssl/obj_mac.h>  /* for EC curves */
#endif

#include "val_crypto.h"
#include "val_support.h"

#define VAL_EVP_DGST_SHA1    1
#define VAL_EVP_DGST_SHA256  2
#define VAL_EVP_DGST_SHA384  3
#define VAL_EVP_DGST_SHA512  4

static unsigned int 
gen_evp_hash(const int hashtype, const u_char *data, size_t data_len, 
             u_char *outbuf, size_t outsize)
{
    const EVP_MD *md = NULL;
    unsigned int calcsize = -1;

    if (outbuf && outsize > 0) {
        memset(outbuf, 0, outsize);
    }

    switch (hashtype) {
        case VAL_EVP_DGST_SHA1:
            md = EVP_sha1();
            break;
        case VAL_EVP_DGST_SHA256:
            md = EVP_sha256();
            break;
        case VAL_EVP_DGST_SHA384:
            md = EVP_sha384();
            break;
        case VAL_EVP_DGST_SHA512:
            md = EVP_sha512();
            break;
        default:
            break;
    }

    if (md != NULL) {
        EVP_MD_CTX *md_ctx;
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md_ctx, md, NULL);
        EVP_DigestUpdate(md_ctx, data, data_len);
        EVP_DigestFinal_ex(md_ctx, outbuf, &calcsize);
        EVP_MD_CTX_free(md_ctx);
    }
    return calcsize;
}


/*
 * Returns VAL_NO_ERROR on success, other values on failure 
 */
static int
dsasha1_parse_public_key(const u_char *buf, size_t buflen, DSA * dsa)
{
    u_char        T;
    int             index = 0;
    BIGNUM         *bn_p, *bn_q, *bn_g, *bn_y;

    if (!dsa || buflen == 0) {
        return VAL_BAD_ARGUMENT;
    }

    T = (u_char) (buf[index]);
    index++;
    
    if (index+20 > buflen)
        return VAL_BAD_ARGUMENT;
    bn_q = BN_bin2bn(buf + index, 20, NULL);
    index += 20;

    if (index+64 + (T * 8) > buflen)
        return VAL_BAD_ARGUMENT;
    bn_p = BN_bin2bn(buf + index, 64 + (T * 8), NULL);
    index += (64 + (T * 8));

    if (index+64 + (T * 8) > buflen)
        return VAL_BAD_ARGUMENT;
    bn_g = BN_bin2bn(buf + index, 64 + (T * 8), NULL);
    index += (64 + (T * 8));

    if (index+64 + (T * 8) > buflen)
        return VAL_BAD_ARGUMENT;
    bn_y = BN_bin2bn(buf + index, 64 + (T * 8), NULL);
    index += (64 + (T * 8));

    DSA_set0_pqg(dsa, bn_p, bn_q, bn_g);
    DSA_set0_key(dsa, bn_y, NULL);

    return VAL_NO_ERROR;        /* success */
}

void
dsasha1_sigverify(val_context_t * ctx,
                  const u_char *data,
                  size_t data_len,
                  const val_dnskey_rdata_t * dnskey,
                  const val_rrsig_rdata_t * rrsig,
                  val_astatus_t * key_status, val_astatus_t * sig_status)
{
    char            buf[1028];
    size_t          buflen = 1024;
    DSA            *dsa = NULL;
    u_char   sha1_hash[SHA_DIGEST_LENGTH];
    u_char   sig_asn1[2+2*(3+SHA_DIGEST_LENGTH)];

    val_log(ctx, LOG_DEBUG,
            "dsasha1_sigverify(): parsing the public key...");
    if ((dsa = DSA_new()) == NULL) {
        val_log(ctx, LOG_INFO,
                "dsasha1_sigverify(): could not allocate dsa structure.");
        *key_status = VAL_AC_INVALID_KEY;
        return;
    };

    if (dsasha1_parse_public_key
        (dnskey->public_key, dnskey->public_key_len,
         dsa) != VAL_NO_ERROR) {
        val_log(ctx, LOG_INFO,
                "dsasha1_sigverify(): Error in parsing public key.");
        DSA_free(dsa);
        *key_status = VAL_AC_INVALID_KEY;
        return;
    }

    gen_evp_hash(VAL_EVP_DGST_SHA1, data, data_len, sha1_hash, SHA_DIGEST_LENGTH); 
    val_log(ctx, LOG_DEBUG, "dsasha1_sigverify(): SHA-1 hash = %s",
            get_hex_string(sha1_hash, SHA_DIGEST_LENGTH, buf, buflen));

    val_log(ctx, LOG_DEBUG,
            "dsasha1_sigverify(): verifying DSA signature...");

    /*
     * Fix: courtesy tom.fowler
     * First convert the signature into its DER representation
     *  0x30, 0x2E,       -  ASN1 sequence 
     *   0x02, 0x15,      - ASN integer, length 21 bytes
     *   0x00, <R bytes>  - 1 + 20 bytes per 2536 
     *   0x02, 0x15,      - ASN integer 
     *   0x00, <S bytes>  - 1 + 20 bytes per 2536
     */
    if (rrsig->signature_len < (1 + 2*SHA_DIGEST_LENGTH)) {
        /* dont have enough data */
        val_log(ctx, LOG_INFO,
                "dsasha1_sigverify(): Error parsing DSA rrsig.");
        DSA_free(dsa);
        *sig_status = VAL_AC_INVALID_RRSIG;
        return;
    }
    memcpy(sig_asn1, "\x30\x2E\x02\x15\x00", 5);
    memcpy(sig_asn1+5, rrsig->signature+1, SHA_DIGEST_LENGTH);
    memcpy(sig_asn1+5+SHA_DIGEST_LENGTH, "\x02\x15\x00", 3);
    memcpy(sig_asn1+5+SHA_DIGEST_LENGTH+3,
           rrsig->signature+1+SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH);

    if (DSA_verify
        (NID_sha1, (u_char *) sha1_hash, SHA_DIGEST_LENGTH,
         sig_asn1, sizeof(sig_asn1), dsa)  == 1) {
        val_log(ctx, LOG_INFO, "dsasha1_sigverify(): returned SUCCESS");
        DSA_free(dsa);
        *sig_status = VAL_AC_RRSIG_VERIFIED;
    } else {
        val_log(ctx, LOG_INFO, "dsasha1_sigverify(): returned FAILURE");
        DSA_free(dsa);
        *sig_status = VAL_AC_RRSIG_VERIFY_FAILED;
    }
    return;
}

/*
 * Returns VAL_NO_ERROR on success, other values on failure 
 */
static int
rsamd5_parse_public_key(const u_char *buf, size_t buflen, RSA * rsa)
{
    int             index = 0;
    const u_char   *cp;
    u_int16_t       exp_len = 0x0000;
    BIGNUM         *bn_exp;
    BIGNUM         *bn_mod;

    if (!rsa || buflen == 0)
        return VAL_BAD_ARGUMENT;

    cp = buf;

    if (buf[index] == 0) {

        if (buflen < 3)
            return VAL_BAD_ARGUMENT;

        index += 1;
        cp = (buf + index);
        VAL_GET16(exp_len, cp);
        index += 2;
    } else {
        exp_len += buf[index];
        index += 1;
    }

    if (exp_len > buflen - index) {
        return VAL_BAD_ARGUMENT;
    }
    
    /*
     * Extract the exponent 
     */
    bn_exp = BN_bin2bn(buf + index, exp_len, NULL);

    index += exp_len;

    if (buflen <= index) {
        return VAL_BAD_ARGUMENT;
    }

    /*
     * Extract the modulus 
     */
    bn_mod = BN_bin2bn(buf + index, buflen - index, NULL);

    RSA_set0_key(rsa, bn_mod, bn_exp, NULL);

    return VAL_NO_ERROR;        /* success */
}

/*
 * See RFC 4034, Appendix B.1 :
 *
 * " For a DNSKEY RR with algorithm 1, the key tag is defined to be the most
 *   significant 16 bits of the least significant 24 bits in the public
 *   key modulus (in other words, the 4th to last and 3rd to last octets
 *   of the public key modulus)."
 */
u_int16_t
rsamd5_keytag(const u_char *pubkey, size_t pubkey_len)
{
    RSA            *rsa = NULL;
    BIGNUM         *modulus;
    u_int16_t       keytag = 0x0000;
    u_char  *modulus_bin;
    int             modulus_len;

    if ((rsa = RSA_new()) == NULL) {
        return VAL_OUT_OF_MEMORY;
    };

    if (rsamd5_parse_public_key(pubkey, pubkey_len, rsa) != VAL_NO_ERROR) {
        RSA_free(rsa);
        return VAL_BAD_ARGUMENT;
    }

    RSA_get0_key(rsa, (const BIGNUM **) &modulus, NULL, NULL);
    modulus_len = BN_num_bytes(modulus);
    modulus_bin =
        (u_char *) MALLOC(modulus_len * sizeof(u_char));

    BN_bn2bin(modulus, modulus_bin);

    keytag = ((0x00ff & modulus_bin[modulus_len - 3]) << 8) |
        (0x00ff & modulus_bin[modulus_len - 2]);

    FREE(modulus_bin);
    RSA_free(rsa);
    return keytag;
}

void
rsamd5_sigverify(val_context_t * ctx,
                 const u_char *data,
                 size_t data_len,
                 const val_dnskey_rdata_t * dnskey,
                 const val_rrsig_rdata_t * rrsig,
                 val_astatus_t * key_status, val_astatus_t * sig_status)
{
    char            buf[1028];
    size_t          buflen = 1024;
    RSA            *rsa = NULL;
    u_char   md5_hash[MD5_DIGEST_LENGTH];

    val_log(ctx, LOG_DEBUG,
            "rsamd5_sigverify(): parsing the public key...");
    if ((rsa = RSA_new()) == NULL) {
        val_log(ctx, LOG_INFO,
                "rsamd5_sigverify(): could not allocate rsa structure.");
        *key_status = VAL_AC_INVALID_KEY;
        return;
    };

    if (rsamd5_parse_public_key(dnskey->public_key, dnskey->public_key_len,
                                rsa) != VAL_NO_ERROR) {
        val_log(ctx, LOG_INFO,
                "rsamd5_sigverify(): Error in parsing public key.");
        RSA_free(rsa);
        *key_status = VAL_AC_INVALID_KEY;
        return;
    }

    memset(md5_hash, 0, MD5_DIGEST_LENGTH);
    MD5(data, data_len, (u_char *) md5_hash);
    val_log(ctx, LOG_DEBUG, "rsamd5_sigverify(): MD5 hash = %s",
            get_hex_string(md5_hash, MD5_DIGEST_LENGTH, buf, buflen));

    val_log(ctx, LOG_DEBUG,
            "rsamd5_sigverify(): verifying RSA signature...");

    if (RSA_verify(NID_md5, (u_char *) md5_hash, MD5_DIGEST_LENGTH,
                   rrsig->signature, rrsig->signature_len, rsa) == 1) {
        val_log(ctx, LOG_INFO, "rsamd5_sigverify(): returned SUCCESS");
        RSA_free(rsa);
        *sig_status = VAL_AC_RRSIG_VERIFIED;
    } else {
        val_log(ctx, LOG_INFO, "rsamd5_sigverify(): returned FAILURE");
        RSA_free(rsa);
        *sig_status = VAL_AC_RRSIG_VERIFY_FAILED;
    }
    return;
}

/*
 * Returns VAL_NO_ERROR on success, other values on failure 
 */
static int
rsa_parse_public_key(const u_char *buf, size_t buflen, RSA * rsa)
{
    int             index = 0;
    const u_char   *cp;
    u_int16_t       exp_len = 0x0000;
    BIGNUM         *bn_exp;
    BIGNUM         *bn_mod;

    if (!rsa || buflen == 0)
        return VAL_BAD_ARGUMENT;

    cp = buf;

    if (buf[index] == 0) {
        if (buflen < 3)
            return VAL_BAD_ARGUMENT;
        index += 1;
        cp = (buf + index);
        VAL_GET16(exp_len, cp);
        index += 2;
    } else {
        exp_len += buf[index];
        index += 1;
    }

    if (index + exp_len > buflen) {
        return VAL_BAD_ARGUMENT;
    }
    
    /*
     * Extract the exponent 
     */
    bn_exp = BN_bin2bn(buf + index, exp_len, NULL);
    index += exp_len;

    if (buflen <= index) {
        return VAL_BAD_ARGUMENT;
    }

    /*
     * Extract the modulus 
     */
    bn_mod = BN_bin2bn(buf + index, buflen - index, NULL);

    RSA_set0_key(rsa, bn_mod, bn_exp, NULL);

    return VAL_NO_ERROR;        /* success */
}

void
rsasha_sigverify(val_context_t * ctx,
                  const u_char *data,
                  size_t data_len,
                  const val_dnskey_rdata_t * dnskey,
                  const val_rrsig_rdata_t * rrsig,
                  val_astatus_t * key_status, val_astatus_t * sig_status)
{
    char            buf[1028];
    size_t          buflen = 1024;
    RSA            *rsa = NULL;
    u_char   sha_hash[MAX_DIGEST_LENGTH];
    size_t   hashlen = 0;
    int nid = 0;

    val_log(ctx, LOG_DEBUG,
            "rsasha_sigverify(): parsing the public key...");
    if ((rsa = RSA_new()) == NULL) {
        val_log(ctx, LOG_INFO,
                "rsasha_sigverify(): could not allocate rsa structure.");
        *key_status = VAL_AC_INVALID_KEY;
        return;
    };

    if (rsa_parse_public_key
        (dnskey->public_key, (size_t)dnskey->public_key_len,
         rsa) != VAL_NO_ERROR) {
        val_log(ctx, LOG_INFO,
                "rsasha_sigverify(): Error in parsing public key.");
        RSA_free(rsa);
        *key_status = VAL_AC_INVALID_KEY;
        return;
    }

    memset(sha_hash, 0, sizeof(sha_hash));
    if (rrsig->algorithm == ALG_RSASHA1
#ifdef LIBVAL_NSEC3
        || rrsig->algorithm == ALG_NSEC3_RSASHA1
#endif
       ) {
        hashlen = SHA_DIGEST_LENGTH; 
        gen_evp_hash(VAL_EVP_DGST_SHA1, data, data_len, sha_hash, hashlen); 
        nid = NID_sha1; 
    } else if (rrsig->algorithm == ALG_RSASHA256) {
        hashlen = SHA256_DIGEST_LENGTH; 
        gen_evp_hash(VAL_EVP_DGST_SHA256, data, data_len, sha_hash, hashlen); 
        nid = NID_sha256; 
    } else if (rrsig->algorithm == ALG_RSASHA512) {
        hashlen = SHA512_DIGEST_LENGTH; 
        gen_evp_hash(VAL_EVP_DGST_SHA512, data, data_len, sha_hash, hashlen); 
        nid = NID_sha512; 
    } else {
        val_log(ctx, LOG_INFO,
                "rsasha_sigverify(): Unkown algorithm.");
        RSA_free(rsa);
        *key_status = VAL_AC_INVALID_KEY;
        return;
    } 

    val_log(ctx, LOG_DEBUG, "rsasha_sigverify(): SHA hash = %s",
            get_hex_string(sha_hash, hashlen, buf, buflen));
    val_log(ctx, LOG_DEBUG,
            "rsasha_sigverify(): verifying RSA signature...");

    if (RSA_verify
        (nid, sha_hash, hashlen,
         rrsig->signature, rrsig->signature_len, rsa) == 1) {
        val_log(ctx, LOG_INFO, "rsasha_sigverify(): returned SUCCESS");
        RSA_free(rsa);
        *sig_status = VAL_AC_RRSIG_VERIFIED;
    } else {
        val_log(ctx, LOG_INFO, "rsasha_sigverify(): returned FAILURE");
        RSA_free(rsa);
        *sig_status = VAL_AC_RRSIG_VERIFY_FAILED;
    }
    return;
}

#if defined(HAVE_ECDSA) && defined(HAVE_OPENSSL_ECDSA_H)
void
ecdsa_sigverify(val_context_t * ctx,
                const u_char *data,
                size_t data_len,
                const val_dnskey_rdata_t * dnskey,
                const val_rrsig_rdata_t * rrsig,
                val_astatus_t * key_status, val_astatus_t * sig_status)
{
    char            buf[1028];
    size_t          buflen = 1024;
    u_char   sha_hash[MAX_DIGEST_LENGTH];
    EC_KEY   *eckey = NULL;
    BIGNUM *bn_x = NULL;
    BIGNUM *bn_y = NULL;
    ECDSA_SIG *ecdsa_sig;
    size_t   hashlen = 0;

    ecdsa_sig = ECDSA_SIG_new();
    memset(sha_hash, 0, sizeof(sha_hash));

    val_log(ctx, LOG_DEBUG,
            "ecdsa_sigverify(): parsing the public key...");

    if (rrsig->algorithm == ALG_ECDSAP256SHA256) {
        hashlen = SHA256_DIGEST_LENGTH; 
        gen_evp_hash(VAL_EVP_DGST_SHA256, data, data_len, sha_hash, hashlen); 
        eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); /* P-256 */
    } else if (rrsig->algorithm == ALG_ECDSAP384SHA384) {
        hashlen = SHA384_DIGEST_LENGTH; 
        gen_evp_hash(VAL_EVP_DGST_SHA384, data, data_len, sha_hash, hashlen); 
        eckey = EC_KEY_new_by_curve_name(NID_secp384r1); /* P-384 */
    } 

    if (eckey == NULL) {
        val_log(ctx, LOG_INFO,
                "ecdsa_sigverify(): could not create key for ECDSA group.");
        *key_status = VAL_AC_INVALID_KEY;
        goto err;
    };

    /* 
     * contruct an EC_POINT from the "Q" field in the 
     * dnskey->public_key, dnskey->public_key_len
     */
    if (dnskey->public_key_len != 2*hashlen) {
        val_log(ctx, LOG_INFO,
                "ecdsa_sigverify(): dnskey length does not match expected size.");
        *key_status = VAL_AC_INVALID_KEY;
        goto err;
    }
    bn_x = BN_bin2bn(dnskey->public_key, hashlen, NULL);
    bn_y = BN_bin2bn(&dnskey->public_key[hashlen], hashlen, NULL);
    if (1 != EC_KEY_set_public_key_affine_coordinates(eckey, bn_x, bn_y)) {
        val_log(ctx, LOG_INFO,
                "ecdsa_sigverify(): Error associating ECSA structure with key.");
        *key_status = VAL_AC_INVALID_KEY;
        goto err;
    }


    val_log(ctx, LOG_DEBUG, "ecdsa_sigverify(): SHA hash = %s",
            get_hex_string(sha_hash, hashlen, buf, buflen));
    val_log(ctx, LOG_DEBUG,
            "ecdsa_sigverify(): verifying ECDSA signature...");

    /* 
     * contruct ECDSA signature from the "r" and "s" fileds in 
     * rrsig->signature, rrsig->signature_len
     */
    if (rrsig->signature_len != 2*hashlen) {
        val_log(ctx, LOG_INFO,
                "ecdsa_sigverify(): Signature length does not match expected size.");
        *sig_status = VAL_AC_RRSIG_VERIFY_FAILED;
        goto err;
    }

    ECDSA_SIG_set0(ecdsa_sig, BN_bin2bn(rrsig->signature, hashlen, NULL),
                   BN_bin2bn(&rrsig->signature[hashlen], hashlen, NULL));

    if (ECDSA_do_verify(sha_hash, hashlen, ecdsa_sig, eckey) == 1) {
        val_log(ctx, LOG_INFO, "ecdsa_sigverify(): returned SUCCESS");
        *sig_status = VAL_AC_RRSIG_VERIFIED;
    } else {
        val_log(ctx, LOG_INFO, "ecdsa_sigverify(): returned FAILURE");
        *sig_status = VAL_AC_RRSIG_VERIFY_FAILED;
    }

    /* Free all structures allocated */
err:
    if (ecdsa_sig)
        ECDSA_SIG_free(ecdsa_sig);
    if (bn_x)
        BN_free(bn_x);
    if (bn_y)
        BN_free(bn_y);
    if (eckey)
        EC_KEY_free(eckey);

    return;

}
#endif

int
ds_sha_hash_is_equal(u_char * name_n,
                     u_char * rrdata,
                     size_t rrdatalen, 
                     u_char * ds_hash,
                     size_t ds_hash_len)
{
    u_char        ds_digest[SHA_DIGEST_LENGTH];
    size_t        namelen;
    SHA_CTX         c;
    size_t          l_index;
    u_char        qc_name_n[NS_MAXCDNAME];

    if (rrdata == NULL || ds_hash_len != SHA_DIGEST_LENGTH)
        return 0;

    namelen = wire_name_length(name_n);
    memcpy(qc_name_n, name_n, namelen);
    l_index = 0;
    lower_name(qc_name_n, &l_index);

    memset(ds_digest, 0, SHA_DIGEST_LENGTH);

    SHA1_Init(&c);
    SHA1_Update(&c, qc_name_n, namelen);
    SHA1_Update(&c, rrdata, rrdatalen);
    SHA1_Final(ds_digest, &c);

    if (!memcmp(ds_digest, ds_hash, SHA_DIGEST_LENGTH))
        return 1;

    return 0;
}

#ifdef HAVE_SHA_2
int
ds_sha256_hash_is_equal(u_char * name_n,
                        u_char * rrdata,
                        size_t rrdatalen, 
                        u_char * ds_hash,
                        size_t ds_hash_len)
{
    u_char        ds_digest[SHA256_DIGEST_LENGTH];
    size_t        namelen;
    SHA256_CTX    c;
    size_t          l_index;
    u_char        qc_name_n[NS_MAXCDNAME];

    if (rrdata == NULL || ds_hash_len != SHA256_DIGEST_LENGTH)
        return 0;

    namelen = wire_name_length(name_n);
    memcpy(qc_name_n, name_n, namelen);
    l_index = 0;
    lower_name(qc_name_n, &l_index);

    memset(ds_digest, 0, SHA256_DIGEST_LENGTH);

    SHA256_Init(&c);
    SHA256_Update(&c, qc_name_n, namelen);
    SHA256_Update(&c, rrdata, rrdatalen);
    SHA256_Final(ds_digest, &c);

    if (!memcmp(ds_digest, ds_hash, SHA256_DIGEST_LENGTH))
        return 1;

    return 0;
}

int
ds_sha384_hash_is_equal(u_char * name_n,
                        u_char * rrdata,
                        size_t rrdatalen, 
                        u_char * ds_hash,
                        size_t ds_hash_len)
{
    u_char        ds_digest[SHA384_DIGEST_LENGTH];
    size_t        namelen;
    SHA512_CTX    c;
    size_t          l_index;
    u_char        qc_name_n[NS_MAXCDNAME];

    if (rrdata == NULL || ds_hash_len != SHA384_DIGEST_LENGTH)
        return 0;

    namelen = wire_name_length(name_n);
    memcpy(qc_name_n, name_n, namelen);
    l_index = 0;
    lower_name(qc_name_n, &l_index);

    memset(ds_digest, 0, SHA384_DIGEST_LENGTH);

    SHA384_Init(&c);
    SHA384_Update(&c, qc_name_n, namelen);
    SHA384_Update(&c, rrdata, rrdatalen);
    SHA384_Final(ds_digest, &c);

    if (!memcmp(ds_digest, ds_hash, SHA384_DIGEST_LENGTH))
        return 1;

    return 0;
}
#endif

#ifdef LIBVAL_NSEC3
u_char       *
nsec3_sha_hash_compute(u_char * name_n, u_char * salt,
                       size_t saltlen, size_t iter, u_char ** hash,
                       size_t * hashlen)
{
    /*
     * Assume that the caller has already performed all sanity checks 
     */
    SHA_CTX         c;
    size_t          i;
    size_t          l_index;
    int len = wire_name_length(name_n);
    u_char qc_name_n[NS_MAXCDNAME];

    memcpy(qc_name_n, name_n, len);
    l_index = 0;
    lower_name(qc_name_n, &l_index);

    *hash = (u_char *) MALLOC(SHA_DIGEST_LENGTH * sizeof(u_char));
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

char           *
get_base64_string(u_char *message, size_t message_len, char *buf,
                  size_t bufsize)
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
decode_base64_key(char *keyptr, u_char * public_key, size_t keysize)
{
    BIO            *b64;
    BIO            *mem;
    BIO            *bio;
    int             len;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    mem = BIO_new_mem_buf(keyptr, -1);
    bio = BIO_push(b64, mem);
    len = BIO_read(bio, public_key, keysize);
    BIO_free(mem);
    BIO_free(b64);
    return len;
}
