/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
/*
 * DESCRIPTION:
 * Contains functions that interface to the signature verification routines.
 */
#include "validator-internal.h"

#include "val_support.h"
#include "val_cache.h"
#include "val_verify.h"
#include "val_crypto.h"
#include "val_policy.h"
#include "val_parse.h"


#define ZONE_KEY_FLAG 0x0100    /* Zone Key Flag, RFC 4034 */
#define BUFLEN 8192

/*
 * Check if any clock skew policy matches
 */
static void
get_clock_skew(val_context_t *ctx,
               u_char *name_n,
               int *skew,
               u_int32_t *ttl_x)
{
    policy_entry_t *cs_pol, *cs_cur;
    u_char       *p;
    size_t       name_len;

    if (ctx == NULL || name_n == NULL || skew == NULL || ttl_x == NULL) {
        val_log(ctx, LOG_DEBUG, "get_clock_skew(): Cannot check for clock skew policy, bad args"); 
        return; 
    }
    
    RETRIEVE_POLICY(ctx, P_CLOCK_SKEW, cs_pol);
    if (cs_pol) {

        name_len = wire_name_length(name_n);

        for (cs_cur = cs_pol;
             cs_cur && (wire_name_length(cs_cur->zone_n) > name_len);
             cs_cur = cs_cur->next);
        /*
         * for all zones which are shorter or as long, do a strstr 
         */
        /*
         * Because of the ordering, the longest match is found first 
         */
        for (; cs_cur; cs_cur = cs_cur->next) {
            int             root_zone = 0;
            if (!namecmp(cs_cur->zone_n, (const u_char *) ""))
                root_zone = 1;
            else {
                /*
                 * Find the last occurrence of cs_cur->zone_n in name_n 
                 */
                p = name_n;
                while (p && (*p != '\0')) {
                    if (!namecmp(p, cs_cur->zone_n))
                        break;
                    p = p + *p + 1;
                }
            }
            if (root_zone || (!namecmp(p, cs_cur->zone_n))) {
                val_log(ctx, LOG_DEBUG, "get_clock_skew(): Found clock skew policy"); 
                if (cs_cur->pol) {
                    *skew = ((struct clock_skew_policy *)(cs_cur->pol))->clock_skew;
                    if (cs_cur->exp_ttl > 0)
                        *ttl_x = cs_cur->exp_ttl;
                    return;
                }
            }
        }
    }
    val_log(ctx, LOG_DEBUG, "get_clock_skew(): No clock skew policy found"); 
    *skew = 0;
}

/*
 * Verify a signature, given the data and the dnskey 
 */
static int 
val_sigverify(val_context_t * ctx,
              int is_a_wildcard,
              const u_char *data,
              size_t data_len,
              const val_dnskey_rdata_t * dnskey,
              const val_rrsig_rdata_t * rrsig,
              val_astatus_t * dnskey_status, val_astatus_t * sig_status,
              int clock_skew)
{
    struct timeval  tv;
    struct timeval  tv_sig;

    /** Inputs to this function have already been NULL-checked **/

    /*
     * Check if the dnskey is a zone key 
     */
    if ((dnskey->flags & ZONE_KEY_FLAG) == 0) {
        val_log(ctx, LOG_INFO, "val_sigverify(): DNSKEY with tag=%d is not a zone key", dnskey->key_tag);
        *dnskey_status = VAL_AC_INVALID_KEY;
        return 0;
    }

    /*
     * Check dnskey protocol value 
     */
    if (dnskey->protocol != 3) {
        val_log(ctx, LOG_INFO,
                "val_sigverify(): Invalid protocol field in DNSKEY with tag=%d: %d",
                dnskey->protocol, dnskey->key_tag);
        *dnskey_status = VAL_AC_UNKNOWN_DNSKEY_PROTOCOL;
        return 0;
    }

    /*
     * Match dnskey and rrsig algorithms 
     */
    if (dnskey->algorithm != rrsig->algorithm) {
        val_log(ctx, LOG_INFO,
                "val_sigverify(): Algorithm mismatch between DNSKEY (%d) and RRSIG (%d) records.",
                dnskey->algorithm, rrsig->algorithm);
        *sig_status = VAL_AC_RRSIG_ALGORITHM_MISMATCH;
        return 0;
    }


    if (clock_skew >= 0) {
        
        /*
         * Check signature inception and expiration times 
         */
        gettimeofday(&tv, NULL);
        if (tv.tv_sec < rrsig->sig_incp) {
            if (tv.tv_sec < rrsig->sig_incp - clock_skew) {
                char            currTime[1028];
                char            incpTime[1028];

                memset(&tv_sig, 0, sizeof(tv_sig));
                tv_sig.tv_sec = rrsig->sig_incp;

                GET_TIME_BUF((const time_t *)(&tv.tv_sec), currTime);
                GET_TIME_BUF((const time_t *)(&tv_sig.tv_sec), incpTime);

                val_log(ctx, LOG_INFO,
                        "val_sigverify(): Signature not yet valid. Current time (%s) is less than signature inception time (%s).",
                        currTime, incpTime);
                *sig_status = VAL_AC_RRSIG_NOTYETACTIVE;
                return 0;
            } else {
                val_log(ctx, LOG_DEBUG,
                        "val_sigverify(): Signature not yet valid, but within acceptable skew.");
            }
    
        }
    
        if (tv.tv_sec > rrsig->sig_expr) {
            if (tv.tv_sec > rrsig->sig_expr + clock_skew) {
                char            currTime[1028];
                char            exprTime[1028];

                memset(&tv_sig, 0, sizeof(tv_sig));
                tv_sig.tv_sec = rrsig->sig_expr;

                memset(currTime, 0, sizeof(currTime));
                memset(exprTime, 0, sizeof(exprTime));
                GET_TIME_BUF((const time_t *)(&tv.tv_sec), currTime);
                GET_TIME_BUF((const time_t *)(&tv_sig.tv_sec), exprTime);

                val_log(ctx, LOG_INFO,
                        "val_sigverify(): Signature expired. Current time (%s) is greater than signature expiration time (%s).",
                        currTime, exprTime);
                *sig_status = VAL_AC_RRSIG_EXPIRED;
                return 0;
            } else {
                val_log(ctx, LOG_DEBUG,
                        "val_sigverify(): Signature expired, but within acceptable skew.");
            }
        }
    } else {
        val_log(ctx, LOG_DEBUG,
                "val_sigverify(): Not checking inception and expiration times on signatures.");
    }

    switch (rrsig->algorithm) {

    case ALG_RSAMD5:
        rsamd5_sigverify(ctx, data, data_len, dnskey, rrsig, 
                         dnskey_status, sig_status);
        break;

#ifdef LIBVAL_NSEC3
    case ALG_NSEC3_DSASHA1:
#endif
    case ALG_DSASHA1:
        dsasha1_sigverify(ctx, data, data_len, dnskey, rrsig,
                          dnskey_status, sig_status);
        break;

#ifdef LIBVAL_NSEC3
    case ALG_NSEC3_RSASHA1:
#endif
    case ALG_RSASHA1:
#ifdef HAVE_SHA_2
    case ALG_RSASHA256:
    case ALG_RSASHA512:
#endif
        rsasha_sigverify(ctx, data, data_len, dnskey, rrsig,
                          dnskey_status, sig_status);
        break;

#if defined(HAVE_SHA_2) && defined(HAVE_OPENSSL_ECDSA_H)
    case ALG_ECDSAP256SHA256:
    case ALG_ECDSAP384SHA384:
        ecdsa_sigverify(ctx, data, data_len, dnskey, rrsig,
                        dnskey_status, sig_status);
        break;
#endif

    default:
        val_log(ctx, LOG_INFO, "val_sigverify(): Unsupported algorithm %d.",
                rrsig->algorithm);
        *sig_status = VAL_AC_ALGORITHM_NOT_SUPPORTED;
        *dnskey_status = VAL_AC_ALGORITHM_NOT_SUPPORTED;
        break;
    }

    if (*sig_status == VAL_AC_RRSIG_VERIFIED) {
        if (is_a_wildcard) {
            val_log(ctx, LOG_DEBUG, "val_sigverify(): Verified RRSIG is for a wildcard");
            if (clock_skew > 0)
                *sig_status = VAL_AC_WCARD_VERIFIED_SKEW;
            else
                *sig_status = VAL_AC_WCARD_VERIFIED;
        } else {
            if (clock_skew > 0)
                *sig_status = VAL_AC_RRSIG_VERIFIED_SKEW;
        }
        return 1;
    }

    return 0;
}

/*
 * Calculate the size of the field over which the verification
 * is done.  This is the sum of
 * the number of bytes through the signer name in the SIG RDATA
 * the length of the signer name (uncompressed)
 * the sum of the fully uncompressed lengths of the RRs in the set
 * *field_length is the field length
 * *signer_length is the length of the signer's name (used externally)
 */
static int
predict_sigbuflength(struct rrset_rec *rr_set,
                     size_t * field_length, size_t *signer_length)
{
    struct rrset_rr  *rr;
    int             owner_length;

    /** Input has already been NULL-checked **/
    owner_length = wire_name_length(rr_set->rrs_name_n);

    *signer_length =
        wire_name_length(&rr_set->rrs_sig->rr_rdata[SIGNBY]);

    if (*signer_length == 0)
        return VAL_BAD_ARGUMENT;

    *field_length = SIGNBY + (*signer_length);

    for (rr = rr_set->rrs_data; rr; rr = rr->rr_next)
        *field_length += owner_length + ENVELOPE + rr->rr_rdata_length;

    return VAL_NO_ERROR;
}

/*
 * Create the buffer over which the signature is to be verified
 */
static int
make_sigfield(u_char ** field,
              size_t * field_length,
              struct rrset_rec *rr_set,
              struct rrset_rr *rr_sig, int is_a_wildcard)
{
    struct rrset_rr  *curr_rr;
    size_t          index;
    size_t          signer_length;
    size_t          owner_length;
    u_int16_t       type_n;
    u_int16_t       class_n;
    u_int32_t       ttl_n;
    u_int16_t       rdata_length_n;
    u_char          lowered_owner_n[NS_MAXCDNAME];
    size_t          l_index;
    int             retval;

    if ((field == NULL) || (field_length == NULL) || (rr_set == NULL) ||
        (rr_sig == NULL) || (rr_set->rrs_name_n == NULL) ||
        (rr_set->rrs_sig == NULL) || 
        (rr_set->rrs_sig->rr_rdata == NULL))
        return VAL_BAD_ARGUMENT;

    if ((retval = predict_sigbuflength(rr_set, field_length, &signer_length)) !=
        VAL_NO_ERROR)
        return retval;

    *field = (u_char *) MALLOC(*field_length * sizeof(u_char));

    if (*field == NULL)
        return VAL_OUT_OF_MEMORY;

    /*
     * Make sure we are using the correct TTL 
     */

    memcpy(&ttl_n, &rr_sig->rr_rdata[TTL], sizeof(u_int32_t));
    rr_set->rrs_ttl_h = ntohl(ttl_n);

    /*
     * While we're at it, we'll gather other common info, specifically
     * network ordered numbers (type, class) and name length.
     */

    owner_length = wire_name_length(rr_set->rrs_name_n);

    if (owner_length == 0)
        goto err;

    memcpy(lowered_owner_n, rr_set->rrs_name_n, owner_length);
    l_index = 0;
    lower_name(lowered_owner_n, &l_index);

    type_n = htons(rr_set->rrs_type_h);
    class_n = htons(rr_set->rrs_class_h);

    /*
     * Copy in the SIG RDATA (up to the signature 
     */

    index = 0;
    if ((index + SIGNBY + signer_length) > *field_length)
        goto err;
    memcpy(&(*field)[index], rr_sig->rr_rdata, SIGNBY + signer_length);
    l_index = 0;
    lower_name(&(*field)[index+SIGNBY], &l_index);
    index += SIGNBY + signer_length;

    /*
     * For each record of data, copy in the envelope & the lower cased rdata 
     */

    for (curr_rr = rr_set->rrs_data; curr_rr;
         curr_rr = curr_rr->rr_next) {
        if (curr_rr->rr_rdata == NULL)
            goto err;

        /*
         * Copy in the envelope information 
         */

        if (is_a_wildcard) {
            /*
             * Construct the original name 
             */
            u_char wcard_n[NS_MAXCDNAME];
            u_char *np = lowered_owner_n;
            int    i;
            size_t outer_len;

            for (i = 0; i < is_a_wildcard; i++)
                np += np[0] + 1;
            outer_len = wire_name_length(np);

            wcard_n[0] = (u_char) 1;
            wcard_n[1] = '*';
            if ((outer_len + 2) > sizeof(wcard_n))
                goto err;
            memcpy(&wcard_n[2], np, outer_len);
            if ((index + outer_len + 2) > *field_length)
                goto err;
            memcpy(&(*field)[index], wcard_n, outer_len + 2);
            index += outer_len + 2;
        } else {
            if ((index + owner_length) > *field_length)
                goto err;
            memcpy(&(*field)[index], lowered_owner_n, owner_length);
            index += owner_length;
        }

        if ((index + sizeof(u_int16_t) + sizeof(u_int16_t) +
             sizeof(u_int32_t))
            > *field_length)
            goto err;
        memcpy(&(*field)[index], &type_n, sizeof(u_int16_t));
        index += sizeof(u_int16_t);
        memcpy(&(*field)[index], &class_n, sizeof(u_int16_t));
        index += sizeof(u_int16_t);
        memcpy(&(*field)[index], &ttl_n, sizeof(u_int32_t));
        index += sizeof(u_int32_t);

        /*
         * Now the RR-specific info, the length and the data 
         */

        rdata_length_n = htons(curr_rr->rr_rdata_length);
        if ((index + sizeof(u_int16_t) + curr_rr->rr_rdata_length)
            > *field_length)
            goto err;
        memcpy(&(*field)[index], &rdata_length_n, sizeof(u_int16_t));
        index += sizeof(u_int16_t);
        memcpy(&(*field)[index], curr_rr->rr_rdata,
               curr_rr->rr_rdata_length);
        index += curr_rr->rr_rdata_length;
    }

    *field_length = index;
    return VAL_NO_ERROR;

  err:
    FREE(*field);
    *field = NULL;
    *field_length = 0;
    return VAL_BAD_ARGUMENT;
}

/*
 * identify the owner name (zone name) and key footprint from
 * the rrsig
 */
static int
identify_key_from_sig(struct rrset_rr *sig, u_char ** name_n,
                      u_int16_t * footprint_n)
{
    if ((sig == NULL) || (sig->rr_rdata == NULL) || (name_n == NULL) ||
        (footprint_n == NULL) || (sig->rr_rdata_length < SIGNBY)) {
        if (name_n != NULL)
            *name_n = NULL;
        if (footprint_n != NULL)
            memset(footprint_n, 0, sizeof(u_int16_t));
        return VAL_BAD_ARGUMENT;
    }

    *name_n = &sig->rr_rdata[SIGNBY];
    memcpy(footprint_n, &sig->rr_rdata[SIGNBY - sizeof(u_int16_t)],
           sizeof(u_int16_t));
    return VAL_NO_ERROR;
}

/*
 * helper function for a set of verify-related operations
 */
static int
do_verify(val_context_t * ctx,
          u_char *zone_n,
          val_astatus_t * dnskey_status,
          val_astatus_t * sig_status,
          struct rrset_rec *the_set,
          struct rrset_rr *the_sig,
          val_dnskey_rdata_t * the_key, int is_a_wildcard,
          u_int32_t flags)
{
    /*
     * Use the crypto routines to verify the signature
     */

    u_char       *ver_field;
    size_t          ver_length;
    int             ret_val;
    val_rrsig_rdata_t rrsig_rdata;
    int clock_skew = 0;
    u_int32_t ttl_x = 0;
    int retval = 0;

    /*
     * Wildcard expansions for DNSKEYs and DSs are not permitted
     */
    if (is_a_wildcard &&
        ((the_set->rrs_type_h == ns_t_ds) ||
         (the_set->rrs_type_h == ns_t_dnskey))) {
        val_log(ctx, LOG_INFO, "do_verify(): Invalid DNSKEY or DS record - cannot be wildcard expanded");
        *dnskey_status = VAL_AC_INVALID_KEY;
        return 0;
    }

    if ((ret_val = make_sigfield(&ver_field, &ver_length, the_set, the_sig,
                                 is_a_wildcard)) != VAL_NO_ERROR ||
        ver_field == NULL || 
        ver_length == 0) {

        val_log(ctx, LOG_INFO, 
                "do_verify(): Could not construct signature field for verification: %s", 
                p_val_err(ret_val));
        *sig_status = VAL_AC_INVALID_RRSIG;
        return 0;
    }

    /*
     * Find the signature - no memory is malloc'ed for this operation  
     */

    if (VAL_NO_ERROR != val_parse_rrsig_rdata(the_sig->rr_rdata, 
                                   the_sig->rr_rdata_length,
                                   &rrsig_rdata)) {
        if (ver_field)
            FREE(ver_field);
        val_log(ctx, LOG_INFO, 
                "do_verify(): Could not parse signature field");
        *sig_status = VAL_AC_INVALID_RRSIG;
        return 0;
    }

    rrsig_rdata.next = NULL;

    if (flags & VAL_QUERY_IGNORE_SKEW) {
        clock_skew = -1;
        val_log(ctx, LOG_DEBUG, "do_verify(): Ignoring clock skew"); 
    } else {
        get_clock_skew(ctx, zone_n, &clock_skew, &ttl_x);
        /* the state is valid for only as long as the policy validity period */
        SET_MIN_TTL(the_set->rrs_ttl_x, ttl_x);
    }

    /*
     * Perform the verification 
     */
    retval = val_sigverify(ctx, is_a_wildcard, ver_field, ver_length, the_key,
                  &rrsig_rdata, dnskey_status, sig_status, clock_skew);

    if (rrsig_rdata.signature != NULL) {
        FREE(rrsig_rdata.signature);
        rrsig_rdata.signature = NULL;
    }

    FREE(ver_field);
    return retval;
}

/*
 * wrapper around the DS comparison function
 */
int
ds_hash_is_equal(val_context_t *ctx,
                 u_char ds_hashtype, u_char * ds_hash,
                 size_t ds_hash_len, u_char * name_n,
                 struct rrset_rr *dnskey, val_astatus_t * ds_status)
{
    if ((dnskey == NULL) || (ds_hash == NULL) || (name_n == NULL)) {
        val_log(ctx, LOG_INFO, "ds_hash_is_equal(): Cannot compare DS data - invalid content");
        return 0;
    }

    /*
     * Only SHA-1 is understood 
     */
    if (ds_hashtype == ALG_DS_HASH_SHA1) {
        return ds_sha_hash_is_equal(name_n, dnskey->rr_rdata,
                                    (size_t)dnskey->rr_rdata_length, 
                                    ds_hash, ds_hash_len);

    } 

#ifdef HAVE_SHA_2
    else if (ds_hashtype == ALG_DS_HASH_SHA256) {
        return ds_sha256_hash_is_equal(name_n, dnskey->rr_rdata,
                                       (size_t)dnskey->rr_rdata_length, 
                                       ds_hash, ds_hash_len);
    } 
    else if (ds_hashtype == ALG_DS_HASH_SHA384) {
        return ds_sha384_hash_is_equal(name_n, dnskey->rr_rdata,
                                       (size_t)dnskey->rr_rdata_length, 
                                       ds_hash, ds_hash_len);
    } 
#endif

    /* else */

    *ds_status = VAL_AC_ALGORITHM_NOT_SUPPORTED;
    val_log(ctx, LOG_INFO, "ds_hash_is_equal(): Unsupported DS hash algorithm");
    return 0;
}

static int
check_label_count(struct rrset_rec *the_set,
                  struct rrset_rr *the_sig, int *is_a_wildcard)
{
    size_t        owner_labels;
    size_t        sig_labels;

    if ((the_set == NULL) || (the_sig == NULL) || (is_a_wildcard == NULL))
        return 0;

    owner_labels = wire_name_labels(the_set->rrs_name_n);
    sig_labels = the_sig->rr_rdata[RRSIGLABEL] + 1;

    if (sig_labels > owner_labels)
        return 0;

    *is_a_wildcard = (owner_labels - sig_labels);

    return 1;
}

/*
 * State returned in as->val_ac_status is one of:
 * VAL_AC_VERIFIED : at least one sig passed
 * VAL_AC_NOT_VERIFIED : no sig passed
 * VAL_AC_WCARD_VERIFIED : if sigs were wildcard verified 
 * the exact error
 */
#define SET_STATUS(savedstatus, rr, newstatus) \
	do { \
		rr->rr_status = newstatus; \
        if (\
            savedstatus == VAL_AC_TRUST_NOCHK &&\
            newstatus == VAL_AC_DNSKEY_NOMATCH) {\
                savedstatus = VAL_AC_NOT_VERIFIED; \
        }\
        else if (\
            savedstatus == VAL_AC_TRUST_NOCHK ||\
            savedstatus == VAL_AC_TRUST ||\
            savedstatus == VAL_AC_VERIFIED ||\
            savedstatus == VAL_AC_WCARD_VERIFIED ||\
            newstatus == VAL_AC_UNSET)\
                ; /* do nothing */\
        /* Any success is good */\
        else if (\
            newstatus == VAL_AC_RRSIG_VERIFIED ||\
            newstatus == VAL_AC_RRSIG_VERIFIED_SKEW) \
                savedstatus = VAL_AC_VERIFIED;\
        else if (\
            newstatus == VAL_AC_WCARD_VERIFIED ||\
            newstatus == VAL_AC_WCARD_VERIFIED_SKEW)\
                savedstatus = VAL_AC_WCARD_VERIFIED;\
        /* we don't already have success and what we receive is bad */ \
        else {\
                savedstatus = VAL_AC_NOT_VERIFIED; \
        }\
	} while (0)

void
verify_next_assertion(val_context_t * ctx,
                      struct val_digested_auth_chain *as,
                      struct val_digested_auth_chain *the_trust,
                      u_int32_t flags)
{
    struct rrset_rec *the_set;
    struct rrset_rr  *the_sig;
    u_char       *signby_name_n;
    u_int16_t       signby_footprint_n;
    val_dnskey_rdata_t dnskey;
    int             is_a_wildcard;
    struct rrset_rr  *nextrr;
    struct rrset_rr  *keyrr;
    u_int16_t       tag_h;
    char            name_p[NS_MAXDNAME];
    int success = 0;

    if ((as == NULL) || (as->val_ac_rrset.ac_data == NULL) || (the_trust == NULL)) {
        val_log(ctx, LOG_INFO, "verify_next_assertion(): Cannot verify assertion - no data");
        return;
    }

    the_set = as->val_ac_rrset.ac_data;
    dnskey.public_key = NULL;


    if (-1 == ns_name_ntop(the_set->rrs_name_n, name_p, sizeof(name_p)))
        snprintf(name_p, sizeof(name_p), "unknown/error");

    if (the_set->rrs_sig == NULL) {
        val_log(ctx, LOG_INFO, "verify_next_assertion(): RRSIG is missing");
        as->val_ac_status = VAL_AC_RRSIG_MISSING;
        return;
    }

    if (the_set->rrs_type_h != ns_t_dnskey) {
        /*
         * trust path contains the key 
         */
        if (the_trust->val_ac_rrset.ac_data == NULL) {
            val_log(ctx, LOG_INFO, "verify_next_assertion(): Key is empty");
            as->val_ac_status = VAL_AC_DNSKEY_MISSING;
            return;
        }
        keyrr = the_trust->val_ac_rrset.ac_data->rrs_data;
    } else {
        /*
         * data itself contains the key 
         */
        if (the_set->rrs_data == NULL) {
            val_log(ctx, LOG_INFO, "verify_next_assertion(): Key is empty");
            as->val_ac_status = VAL_AC_DNSKEY_MISSING;
            return;
        }
        keyrr = the_set->rrs_data;
    }

    for (the_sig = the_set->rrs_sig;
         the_sig; the_sig = the_sig->rr_next) {

        /*
         * do wildcard processing 
         */
        if (!check_label_count(the_set, the_sig, &is_a_wildcard)) {
            SET_STATUS(as->val_ac_status, the_sig,
                       VAL_AC_WRONG_LABEL_COUNT);
            val_log(ctx, LOG_INFO, "verify_next_assertion(): Incorrect RRSIG label count");
            continue;
        }

        /*
         * for each sig, identify key, 
         */
        if (VAL_NO_ERROR != identify_key_from_sig(the_sig, &signby_name_n,
                              &signby_footprint_n)) {
            SET_STATUS(as->val_ac_status, the_sig,
                       VAL_AC_INVALID_RRSIG);
            val_log(ctx, LOG_INFO, "verify_next_assertion(): Cannot extract key footprint from RRSIG");
            continue;
        }

        tag_h = ntohs(signby_footprint_n);
        for (nextrr = keyrr; nextrr; nextrr = nextrr->rr_next) {
            int             is_verified = 0;
            if (VAL_NO_ERROR != val_parse_dnskey_rdata(nextrr->rr_rdata,
                                             nextrr->rr_rdata_length,
                                             &dnskey)) {
                val_log(ctx, LOG_INFO, "verify_next_assertion(): Cannot parse DNSKEY data");
                nextrr->rr_status = VAL_AC_INVALID_KEY;
                continue;
            }

            dnskey.next = NULL;
            if (dnskey.key_tag != tag_h) {
                if (dnskey.public_key != NULL) {
                    FREE(dnskey.public_key);
                    dnskey.public_key = NULL;
                }
                continue;
            }

            val_log(ctx, LOG_DEBUG, "verify_next_assertion(): Found potential matching DNSKEY for RRSIG");

            /*
             * check the signature 
             */
            is_verified = do_verify(ctx, signby_name_n,
                      &nextrr->rr_status,
                      &the_sig->rr_status,
                      the_set, the_sig, &dnskey, is_a_wildcard, flags);

            /*
             * There might be multiple keys with the same key tag; set this as
             * the signing key only if we dont have other status for this key
             */
            SET_STATUS(as->val_ac_status, the_sig, the_sig->rr_status);
            if (nextrr->rr_status == VAL_AC_UNSET) {
                nextrr->rr_status = VAL_AC_SIGNING_KEY;
            }

            if (is_verified) {

                val_log(ctx, LOG_INFO, "verify_next_assertion(): Verified a RRSIG for %s (%s) using a DNSKEY (%d)",
                        name_p, p_type(the_set->rrs_type_h),
                        dnskey.key_tag);

                if ( as->val_ac_status == VAL_AC_TRUST ||
                    nextrr->rr_status == VAL_AC_TRUST_POINT) {
                    /* we've verified a trust anchor */
                    as->val_ac_status = VAL_AC_TRUST; 
                    val_log(ctx, LOG_INFO, "verify_next_assertion(): verification traces back to trust anchor");
                    if (dnskey.public_key != NULL) {
                        FREE(dnskey.public_key);
                        dnskey.public_key = NULL;
                    }
                    success = 1;
                    break;

                } else if ( the_set->rrs_type_h == ns_t_dnskey && as != the_trust) {
                    /* Check if we're trying to verify some key in the authentication chain */
                    /* Check if we have reached our trust key */
                    /*
                     * If this record contains a DNSKEY, check if the DS record contains this key 
                     * DNSKEYs cannot be wildcard expanded, so VAL_AC_WCARD_VERIFIED does not
                     * count as a good sig
                     * Create the link even if the DNSKEY algorithm is unknown since this 
                     * may be the provably insecure case
                     */
                    /*
                     * follow the trust path 
                     */
                    struct rrset_rr  *dsrec =
                        the_trust->val_ac_rrset.ac_data->rrs_data;
                    while (dsrec) {
                        val_ds_rdata_t  ds;
                        int retval;
                        ds.d_hash = NULL;
                        retval = val_parse_ds_rdata(dsrec->rr_rdata,
                                       dsrec->rr_rdata_length, &ds);
                        if(retval == VAL_NOT_IMPLEMENTED) {
                            val_log(ctx, LOG_INFO, "verify_next_assertion(): DS hash not supported");
                            dsrec->rr_status = VAL_AC_ALGORITHM_NOT_SUPPORTED;
                        } else if (retval != VAL_NO_ERROR) {
                            val_log(ctx, LOG_INFO, "verify_next_assertion(): DS parse error");
                            dsrec->rr_status = VAL_AC_INVALID_DS;
                        } else if (DNSKEY_MATCHES_DS(ctx, &dnskey, &ds, 
                                    the_set->rrs_name_n, nextrr, 
                                    &dsrec->rr_status)) {
                            val_log(ctx, LOG_DEBUG, 
                                    "verify_next_assertion(): DNSKEY tag (%d) matches DS tag (%d)",
                                    (&dnskey)->key_tag,                                         
                                    (&ds)->d_keytag);
                            /*
                             * the first match is enough 
                             */
                            nextrr->rr_status = VAL_AC_VERIFIED_LINK;
                            dsrec->rr_status = VAL_AC_VERIFIED_LINK;
                            FREE(ds.d_hash);
                            ds.d_hash = NULL;
                            if (dnskey.public_key) {
                                FREE(dnskey.public_key);
                                dnskey.public_key = NULL;
                            }
                            val_log(ctx, LOG_INFO, "verify_next_assertion(): Key links upward");
                            success = 1;
                            break;
                        } else {
                            /*
                             * Didn't find a valid entry in the DS record set 
                             * Not necessarily a problem, since there is no requirement that a DS be present
                             * If none match, then we set the status accordingly. See below.
                             */
                            nextrr->rr_status = VAL_AC_DS_NOMATCH;
                        } 

                        if (ds.d_hash != NULL) {
                            FREE(ds.d_hash);
                            ds.d_hash = NULL;
                        }
                        dsrec = dsrec->rr_next;
                    }
                }
            } 

            if (dnskey.public_key != NULL) {
                FREE(dnskey.public_key);
            }
            dnskey.public_key = NULL;
        }

        if (the_sig->rr_status == VAL_AC_UNSET) {
            val_log(ctx, LOG_INFO, "verify_next_assertion(): Could not link this RRSIG to a DNSKEY");
            SET_STATUS(as->val_ac_status, the_sig, VAL_AC_DNSKEY_NOMATCH);
        }

        /* Continue checking only if we want to verify all signatures */
        if (success && !(flags & VAL_QUERY_CHECK_ALL_RRSIGS)) {
            break;
        }
    }
        
    /* 
     * If we reach here and we're a keyset, we either didn't verify the keyset or
     * didn't verify the link from the key to the DS 
     */ 
    if (!success && the_set->rrs_type_h == ns_t_dnskey){
        as->val_ac_status = VAL_AC_NO_LINK;
    }
}
