/*
 * Copyright 2005-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 */

#ifndef VAL_CRYPTO_H
#define VAL_CRYPTO_H


void            dsasha1_sigverify(val_context_t * ctx,
                                  const u_char *data,
                                  size_t data_len,
                                  const val_dnskey_rdata_t * dnskey,
                                  const val_rrsig_rdata_t * rrsig,
                                  val_astatus_t * key_status,
                                  val_astatus_t * sig_status);

void            rsamd5_sigverify(val_context_t * ctx,
                                 const u_char *data,
                                 size_t data_len,
                                 const val_dnskey_rdata_t * dnskey,
                                 const val_rrsig_rdata_t * rrsig,
                                 val_astatus_t * key_status,
                                 val_astatus_t * sig_status);

u_int16_t       rsamd5_keytag(const u_char *pubkey, size_t pubkey_len);

void            rsasha_sigverify(val_context_t * ctx,
                                  const u_char *data,
                                  size_t data_len,
                                  const val_dnskey_rdata_t * dnskey,
                                  const val_rrsig_rdata_t * rrsig,
                                  val_astatus_t * key_status,
                                  val_astatus_t * sig_status);

int             ds_sha_hash_is_equal(u_char * name_n,
                                     u_char * rrdata,
                                     size_t rrdatalen,
                                     u_char * ds_hash,
                                     size_t ds_hash_len);

#ifdef HAVE_SHA_256
int             ds_sha256_hash_is_equal(u_char * name_n,
                                        u_char * rrdata,
                                        size_t rrdatalen,
                                        u_char * ds_hash,
                                        size_t ds_hash_len);
#endif

#ifdef LIBVAL_NSEC3
u_char       *nsec3_sha_hash_compute(u_char * qc_name_n,
                                       u_char * salt, size_t saltlen,
                                       size_t iter, u_char ** hash,
                                       size_t * hashlen);
#endif

char           *get_base64_string(u_char *message, size_t message_len,
                                  char *buf, size_t bufsize);

int             decode_base64_key(char *keyptr, u_char * public_key,
                                  size_t keysize);

#endif
