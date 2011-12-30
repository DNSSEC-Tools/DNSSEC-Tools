/*
 * Copyright 2005-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the header file for the verifier.
 */

#ifndef VAL_VERIFY_H
#define VAL_VERIFY_H

/*
 * Result status codes returned by the validator functions.
 */

typedef int     val_result_t;

/*
 * Check if DS hash matches the DNSKEY  
 */
int             ds_hash_is_equal(val_context_t *ctx,
                    u_char ds_hashtype, u_char * ds_hash,
                    size_t ds_hash_len, u_char * name_n,
                    struct val_rr_rec *dnskey, val_astatus_t * ds_status);

/*
 * Compare if DNSKEY matches DS 
 */
#define DNSKEY_MATCHES_DS(ctx, dnskey, ds, name_n, dnskey_rr_rec, ds_status) \
    ((dnskey)->key_tag == (ds)->d_keytag &&\
     (ds)->d_algo == (dnskey)->algorithm &&\
     ds_hash_is_equal(ctx,\
                      (ds)->d_type,\
                      (ds)->d_hash, (size_t)((ds)->d_hash_len),\
                      name_n,\
                      dnskey_rr_rec, ds_status))

/*
 * Compare if two public keys are identical 
 */
#define DNSKEY_MATCHES_DNSKEY(key1, key2) \
    ((key1) && (key2) && \
     (key1)->flags == (key2)->flags &&\
     (key1)->protocol == (key2)->protocol &&\
     (key1)->algorithm == (key2)->algorithm &&\
     (key1)->key_tag == (key2)->key_tag &&\
     (key1)->public_key_len == (key2)->public_key_len &&\
     !memcmp((key1)->public_key, (key2)->public_key, (key1)->public_key_len))

/*
 * The Verifier Function.
 */
void            verify_next_assertion(val_context_t * ctx,
                                      struct val_digested_auth_chain *as,
                                      struct val_digested_auth_chain *the_trust,
                                      u_int flags);

#endif
