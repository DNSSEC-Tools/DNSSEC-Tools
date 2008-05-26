/*
 * Copyright 2005-2008 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
/*
 * DESCRIPTION:
 * Contains functions that interface to the signature verification routines.
 */
#include "validator-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <strings.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>

#include <validator/resolver.h>
#include <validator/validator.h>
#include <validator/validator-internal.h>
#include "val_support.h"
#include "val_cache.h"
#include "val_verify.h"
#include "val_crypto.h"
#include "val_policy.h"


#define ZONE_KEY_FLAG 0x0100    /* Zone Key Flag, RFC 4034 */
#define BUFLEN 8192

/*
 * Check if any clock skew policy matches
 */
static void
get_clock_skew(val_context_t *ctx,
               u_int8_t *name_n,
               int *skew,
               u_int32_t *ttl_x)
{
    policy_entry_t *cs_pol, *cs_cur;
    u_int8_t       *p;
    int             name_len;

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
            if (!namecmp(cs_cur->zone_n, (const u_int8_t *) ""))
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
static void
val_sigverify(val_context_t * ctx,
              int is_a_wildcard,
              const unsigned char *data,
              int data_len,
              const val_dnskey_rdata_t * dnskey,
              const val_rrsig_rdata_t * rrsig,
              val_astatus_t * dnskey_status, val_astatus_t * sig_status,
              int clock_skew)
{
    struct timeval  tv;
    struct timezone tz;

    /** Inputs to this function have already been NULL-checked **/

    /*
     * Check if the dnskey is a zone key 
     */
    if ((dnskey->flags & ZONE_KEY_FLAG) == 0) {
        val_log(ctx, LOG_INFO, "val_sigverify(): DNSKEY with tag=%d is not a zone key", dnskey->key_tag);
        *dnskey_status = VAL_AC_INVALID_KEY;
        return;
    }

    /*
     * Check dnskey protocol value 
     */
    if (dnskey->protocol != 3) {
        val_log(ctx, LOG_INFO,
                "val_sigverify(): Invalid protocol field in DNSKEY with tag=%d: %d",
                dnskey->protocol, dnskey->key_tag);
        *dnskey_status = VAL_AC_UNKNOWN_DNSKEY_PROTOCOL;
        return;
    }

    /*
     * Match dnskey and rrsig algorithms 
     */
    if (dnskey->algorithm != rrsig->algorithm) {
        val_log(ctx, LOG_INFO,
                "val_sigverify(): Algorithm mismatch between DNSKEY (%d) and RRSIG (%d) records.",
                dnskey->algorithm, rrsig->algorithm);
        *sig_status = VAL_AC_RRSIG_ALGORITHM_MISMATCH;
        return;
    }


    if (clock_skew >= 0) {
        
        /*
         * Check signature inception and expiration times 
         */
        gettimeofday(&tv, &tz);
        if (tv.tv_sec < rrsig->sig_incp) {
            if (tv.tv_sec < rrsig->sig_incp - clock_skew) {
                char            currTime[1028];
                char            incpTime[1028];
                int             len;
                bzero(currTime, 1028);
                bzero(incpTime, 1028);
    #ifndef sun
                ctime_r((const time_t *) (&(tv.tv_sec)), currTime);
    #else
                ctime_r((const time_t *) (&(tv.tv_sec)), currTime,
                        sizeof(currTime));
    #endif
                len = strlen(currTime);
                if (len > 0)
                    currTime[len - 1] = 0;
    #ifndef sun
                ctime_r((const time_t *) (&(rrsig->sig_incp)), incpTime);
    #else
                ctime_r((const time_t *) (&(tv.tv_sec)), incpTime,
                        sizeof(incpTime));
    #endif
                len = strlen(incpTime);
                if (len > 0)
                    incpTime[len - 1] = 0;
                val_log(ctx, LOG_INFO,
                        "val_sigverify(): Signature not yet valid. Current time (%s) is less than signature inception time (%s).",
                        currTime, incpTime);
                *sig_status = VAL_AC_RRSIG_NOTYETACTIVE;
                return;
            } else {
                val_log(ctx, LOG_DEBUG,
                        "val_sigverify(): Signature not yet valid, but within acceptable skew.");
            }
    
        }
    
        if (tv.tv_sec > rrsig->sig_expr) {
            if (tv.tv_sec > rrsig->sig_expr + clock_skew) {
                char            currTime[1028];
                char            exprTime[1028];
                int             len;
                bzero(currTime, 1028);
                bzero(exprTime, 1028);
    #ifndef sun
                ctime_r((const time_t *) (&(tv.tv_sec)), currTime);
    #else
                ctime_r((const time_t *) (&(tv.tv_sec)), currTime,
                        sizeof(currTime));
    #endif
                len = strlen(currTime);
                if (len > 0)
                    currTime[len - 1] = 0;
    #ifndef sun
                ctime_r((const time_t *) (&(rrsig->sig_expr)), exprTime);
    #else
                ctime_r((const time_t *) (&(tv.tv_sec)), exprTime,
                        sizeof(exprTime));
    #endif
                len = strlen(exprTime);
                if (len > 0)
                    exprTime[len - 1] = 0;
                val_log(ctx, LOG_INFO,
                        "val_sigverify(): Signature expired. Current time (%s) is greater than signature expiration time (%s).",
                        currTime, exprTime);
                *sig_status = VAL_AC_RRSIG_EXPIRED;
                return;
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
        rsamd5_sigverify(ctx, data, data_len, dnskey, rrsig, dnskey_status,
                         sig_status);
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
        rsasha1_sigverify(ctx, data, data_len, dnskey, rrsig,
                          dnskey_status, sig_status);
        break;

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
    }
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
                     size_t * field_length, int *signer_length)
{
    struct val_rr_rec  *rr;
    int             owner_length;

    /** Input has already been NULL-checked **/
    owner_length = wire_name_length(rr_set->rrs.val_rrset_name_n);

    *signer_length =
        wire_name_length(&rr_set->rrs.val_rrset_sig->rr_rdata[SIGNBY]);

    if (*signer_length == 0)
        return VAL_BAD_ARGUMENT;

    *field_length = SIGNBY + (*signer_length);

    for (rr = rr_set->rrs.val_rrset_data; rr; rr = rr->rr_next)
        *field_length += owner_length + ENVELOPE + rr->rr_rdata_length_h;

    return VAL_NO_ERROR;
}

/*
 * Create the buffer over which the signature is to be verified
 */
static int
make_sigfield(u_int8_t ** field,
              size_t * field_length,
              struct rrset_rec *rr_set,
              struct val_rr_rec *rr_sig, int is_a_wildcard)
{
    struct val_rr_rec  *curr_rr;
    int             index;
    int             signer_length;
    int             owner_length;
    u_int16_t       type_n;
    u_int16_t       class_n;
    u_int32_t       ttl_n;
    u_int16_t       rdata_length_n;
    u_int8_t        lowered_owner_n[NS_MAXCDNAME];
    size_t          l_index;
    int             retval;

    if ((field == NULL) || (field_length == NULL) || (rr_set == NULL) ||
        (rr_sig == NULL) || (rr_set->rrs.val_rrset_name_n == NULL) ||
        (rr_set->rrs.val_rrset_sig == NULL) || 
        (rr_set->rrs.val_rrset_sig->rr_rdata == NULL))
        return VAL_BAD_ARGUMENT;

    if ((retval = predict_sigbuflength(rr_set, field_length, &signer_length)) !=
        VAL_NO_ERROR)
        return retval;

    *field = (u_int8_t *) MALLOC(*field_length);

    if (*field == NULL)
        return VAL_OUT_OF_MEMORY;

    /*
     * Make sure we are using the correct TTL 
     */

    memcpy(&ttl_n, &rr_sig->rr_rdata[TTL], sizeof(u_int32_t));
    rr_set->rrs.val_rrset_ttl_h = ntohl(ttl_n);

    /*
     * While we're at it, we'll gather other common info, specifically
     * network ordered numbers (type, class) and name length.
     */

    owner_length = wire_name_length(rr_set->rrs.val_rrset_name_n);

    if (owner_length == 0)
        goto err;

    memcpy(lowered_owner_n, rr_set->rrs.val_rrset_name_n, owner_length);
    l_index = 0;
    lower_name(lowered_owner_n, &l_index);

    type_n = htons(rr_set->rrs.val_rrset_type_h);
    class_n = htons(rr_set->rrs.val_rrset_class_h);

    /*
     * Copy in the SIG RDATA (up to the signature 
     */

    index = 0;
    if ((index + SIGNBY + signer_length) > *field_length)
        goto err;
    memcpy(&(*field)[index], rr_sig->rr_rdata, SIGNBY + signer_length);
    index += SIGNBY + signer_length;

    /*
     * For each record of data, copy in the envelope & the lower cased rdata 
     */

    for (curr_rr = rr_set->rrs.val_rrset_data; curr_rr;
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
            u_char          wcard_n[NS_MAXCDNAME];
            u_int8_t       *np = lowered_owner_n;
            int             i;
            int             outer_len;

            for (i = 0; i < is_a_wildcard; i++)
                np += np[0] + 1;
            outer_len = wire_name_length(np);

            wcard_n[0] = (u_int8_t) 1;
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

        rdata_length_n = htons(curr_rr->rr_rdata_length_h);
        if ((index + sizeof(u_int16_t) + curr_rr->rr_rdata_length_h)
            > *field_length)
            goto err;
        memcpy(&(*field)[index], &rdata_length_n, sizeof(u_int16_t));
        index += sizeof(u_int16_t);
        memcpy(&(*field)[index], curr_rr->rr_rdata,
               curr_rr->rr_rdata_length_h);
        index += curr_rr->rr_rdata_length_h;
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
identify_key_from_sig(struct val_rr_rec *sig, u_int8_t ** name_n,
                      u_int16_t * footprint_n)
{
    if ((sig == NULL) || (sig->rr_rdata == NULL) || (name_n == NULL) ||
        (footprint_n == NULL) || (sig->rr_rdata_length_h < SIGNBY)) {
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
static void
do_verify(val_context_t * ctx,
          u_int8_t *zone_n,
          val_astatus_t * dnskey_status,
          val_astatus_t * sig_status,
          struct rrset_rec *the_set,
          struct val_rr_rec *the_sig,
          val_dnskey_rdata_t * the_key, int is_a_wildcard)
{
    /*
     * Use the crypto routines to verify the signature
     */

    u_int8_t       *ver_field;
    size_t          ver_length;
    int             ret_val;
    val_rrsig_rdata_t rrsig_rdata;
    int clock_skew = 0;
    u_int32_t ttl_x = 0;

    /*
     * Wildcard expansions for DNSKEYs and DSs are not permitted
     */
    if (is_a_wildcard &&
        ((the_set->rrs.val_rrset_type_h == ns_t_ds) ||
         (the_set->rrs.val_rrset_type_h == ns_t_dnskey))) {
        val_log(ctx, LOG_INFO, "do_verify(): Invalid DNSKEY or DS record - cannot be wildcard expanded");
        *dnskey_status = VAL_AC_INVALID_KEY;
        return;
    }

    if ((ret_val = make_sigfield(&ver_field, &ver_length, the_set, the_sig,
                                 is_a_wildcard)) != VAL_NO_ERROR ||
        ver_field == NULL || 
        ver_length == 0) {

        val_log(ctx, LOG_INFO, 
                "do_verify(): Could not construct signature field for verification: %s", 
                p_val_err(ret_val));
        *sig_status = VAL_AC_INVALID_RRSIG;
        return;
    }

    /*
     * Find the signature - no memory is malloc'ed for this operation  
     */

    if (-1 == val_parse_rrsig_rdata(the_sig->rr_rdata, 
                                     the_sig->rr_rdata_length_h,
                                     &rrsig_rdata)) {
        if (ver_field)
            FREE(ver_field);
        val_log(ctx, LOG_INFO, 
                "do_verify(): Could not parse signature field");
        *sig_status = VAL_AC_INVALID_RRSIG;
        return;
    }

    rrsig_rdata.next = NULL;

    get_clock_skew(ctx, zone_n, &clock_skew, &ttl_x);
    /* the state is valid for only as long as the policy validity period */
    SET_MIN_TTL(the_set->rrs.val_rrset_ttl_x, ttl_x);

    /*
     * Perform the verification 
     */
    val_sigverify(ctx, is_a_wildcard, ver_field, ver_length, the_key,
                  &rrsig_rdata, dnskey_status, sig_status, clock_skew);

    if (rrsig_rdata.signature != NULL) {
        FREE(rrsig_rdata.signature);
        rrsig_rdata.signature = NULL;
    }

    FREE(ver_field);
    return;
}

/*
 * wrapper around the DS comparison function
 */
int
ds_hash_is_equal(val_context_t *ctx,
                 u_int8_t ds_hashtype, u_int8_t * ds_hash,
                 u_int32_t ds_hash_len, u_int8_t * name_n,
                 struct val_rr_rec *dnskey, val_astatus_t * ds_status)
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
                                    dnskey->rr_rdata_length_h, 
                                    ds_hash, ds_hash_len);

    } 

#ifdef HAVE_SHA_256
    else if (ds_hashtype == ALG_DS_HASH_SHA256) {
        return ds_sha256_hash_is_equal(name_n, dnskey->rr_rdata,
                                       dnskey->rr_rdata_length_h, 
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
                  struct val_rr_rec *the_sig, int *is_a_wildcard)
{
    u_int8_t        owner_labels;;
    u_int8_t        sig_labels;

    if ((the_set == NULL) || (the_sig == NULL) || (is_a_wildcard == NULL))
        return 0;

    owner_labels = wire_name_labels(the_set->rrs.val_rrset_name_n);
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
        if (savedstatus == VAL_AC_TRUST_NOCHK ||\
            savedstatus == VAL_AC_TRUST)\
            ; /* do nothing */\
        /* Any success is good */\
        else if (newstatus == VAL_AC_RRSIG_VERIFIED ||\
            newstatus == VAL_AC_RRSIG_VERIFIED_SKEW) \
            savedstatus = VAL_AC_VERIFIED;\
        else if (newstatus == VAL_AC_WCARD_VERIFIED ||\
                 newstatus == VAL_AC_WCARD_VERIFIED_SKEW)\
            savedstatus = VAL_AC_WCARD_VERIFIED;\
        /* we don't already have success and what we receive is bad */ \
        else if ((savedstatus != VAL_AC_VERIFIED) && \
                 (savedstatus != VAL_AC_WCARD_VERIFIED) &&\
                 (newstatus != VAL_AC_UNSET) &&\
                 /* success values for DNSKEYS are not relevant */\
                 (newstatus != VAL_AC_SIGNING_KEY) && \
                 (newstatus != VAL_AC_TRUST_POINT) && \
                 (newstatus != VAL_AC_UNKNOWN_ALGORITHM_LINK) && \
                 (newstatus != VAL_AC_VERIFIED_LINK)){\
            savedstatus = VAL_AC_NOT_VERIFIED; \
        }\
        /* else leave savedstatus untouched */\
	} while (0)

void
verify_next_assertion(val_context_t * ctx,
                      struct val_digested_auth_chain *as,
                      struct val_digested_auth_chain *the_trust)
{
    struct rrset_rec *the_set;
    struct val_rr_rec  *the_sig;
    u_int8_t       *signby_name_n;
    u_int16_t       signby_footprint_n;
    val_dnskey_rdata_t dnskey;
    int             is_a_wildcard;
    struct val_rr_rec  *nextrr;
    struct val_rr_rec  *keyrr;
    u_int16_t       tag_h;

    if ((as == NULL) || (as->_as.ac_data == NULL) || (the_trust == NULL)) {
        val_log(ctx, LOG_INFO, "verify_next_assertion(): Cannot verify assertion - no data");
        return;
    }

    the_set = as->_as.ac_data;
    dnskey.public_key = NULL;

    if (the_set->rrs.val_rrset_sig == NULL) {
        val_log(ctx, LOG_INFO, "verify_next_assertion(): RRSIG is missing");
        as->val_ac_status = VAL_AC_RRSIG_MISSING;
        return;
    }

    if (the_set->rrs.val_rrset_type_h != ns_t_dnskey) {
        /*
         * trust path contains the key 
         */
        if (the_trust->_as.ac_data == NULL) {
            val_log(ctx, LOG_INFO, "verify_next_assertion(): Key is empty");
            as->val_ac_status = VAL_AC_DNSKEY_MISSING;
            return;
        }
        keyrr = the_trust->_as.ac_data->rrs.val_rrset_data;
    } else {
        /*
         * data itself contains the key 
         */
        if (the_set->rrs.val_rrset_data == NULL) {
            val_log(ctx, LOG_INFO, "verify_next_assertion(): Key is empty");
            as->val_ac_status = VAL_AC_DNSKEY_MISSING;
            return;
        }
        keyrr = the_set->rrs.val_rrset_data;
    }

    for (the_sig = the_set->rrs.val_rrset_sig;
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
            if (-1 == val_parse_dnskey_rdata(nextrr->rr_rdata,
                                             nextrr->rr_rdata_length_h,
                                             &dnskey)) {
                val_log(ctx, LOG_INFO, "verify_next_assertion(): Cannot parse DNSKEY data");
                SET_STATUS(as->val_ac_status, nextrr, VAL_AC_INVALID_KEY);
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

            val_log(ctx, LOG_DEBUG, "verify_next_assertion(): Found matching DNSKEY for RRSIG");

            /*
             * check the signature 
             */
            do_verify(ctx, signby_name_n,
                      &nextrr->rr_status,
                      &the_sig->rr_status,
                      the_set, the_sig, &dnskey, is_a_wildcard);


            if (the_sig->rr_status == VAL_AC_RRSIG_VERIFIED ||
                the_sig->rr_status == VAL_AC_RRSIG_VERIFIED_SKEW ||
                the_sig->rr_status == VAL_AC_WCARD_VERIFIED ||
                the_sig->rr_status == VAL_AC_WCARD_VERIFIED_SKEW) {

                SET_STATUS(as->val_ac_status, the_sig, the_sig->rr_status);
                SET_STATUS(as->val_ac_status, nextrr, nextrr->rr_status);
                if (nextrr->rr_status == VAL_AC_UNSET) {
                    nextrr->rr_status = VAL_AC_SIGNING_KEY;
                }
                break;
            }

            /*
             * There might be multiple keys with the same key tag; set this as
             * the signing key only if we dont have other status for this key
             */
            SET_STATUS(as->val_ac_status, the_sig, the_sig->rr_status);
            SET_STATUS(as->val_ac_status, nextrr, nextrr->rr_status);
            if (nextrr->rr_status == VAL_AC_UNSET) {
                nextrr->rr_status = VAL_AC_SIGNING_KEY;
            }

            if (dnskey.public_key != NULL) {
                FREE(dnskey.public_key);
            }
            dnskey.public_key = NULL;
        }

        if (nextrr == NULL) {
            val_log(ctx, LOG_INFO, "verify_next_assertion(): No DNSKEY matched for this RRSIG");
            SET_STATUS(as->val_ac_status, the_sig, VAL_AC_DNSKEY_NOMATCH);

        } else if (as->val_ac_status == VAL_AC_TRUST_NOCHK || 
                    as->val_ac_status == VAL_AC_TRUST) {

            if (nextrr->rr_status == VAL_AC_TRUST_POINT && 
                    (the_sig->rr_status == VAL_AC_RRSIG_VERIFIED ||
                     the_sig->rr_status == VAL_AC_RRSIG_VERIFIED_SKEW)) {
                    as->val_ac_status = VAL_AC_TRUST; 
                    val_log(ctx, LOG_INFO, "verify_next_assertion(): verification traces back to trust anchor");
            }
            
        } else if (the_set->rrs.val_rrset_type_h == ns_t_dnskey && 
                     (the_sig->rr_status == VAL_AC_RRSIG_VERIFIED ||
                     the_sig->rr_status == VAL_AC_RRSIG_VERIFIED_SKEW ||
                     the_sig->rr_status == VAL_AC_ALGORITHM_NOT_SUPPORTED)) {

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
            struct val_rr_rec  *dsrec =
                the_trust->_as.ac_data->rrs.val_rrset_data;
            while (dsrec) {
                val_ds_rdata_t  ds;
                if (-1 == val_parse_ds_rdata(dsrec->rr_rdata,
                                   dsrec->rr_rdata_length_h, &ds)) {
                    val_log(ctx, LOG_INFO, "verify_next_assertion(): Unknown DS algorithm");
                    SET_STATUS(as->val_ac_status, dsrec, VAL_AC_UNKNOWN_ALGORITHM_LINK);
                } else {

                    if (DNSKEY_MATCHES_DS(ctx, &dnskey, &ds, 
                            the_set->rrs.val_rrset_name_n, nextrr, 
                            &dsrec->rr_status)) {

                        if (the_sig->rr_status == VAL_AC_RRSIG_VERIFIED ||
                            the_sig->rr_status == VAL_AC_RRSIG_VERIFIED_SKEW)
                            SET_STATUS(as->val_ac_status, nextrr,
                                       VAL_AC_VERIFIED_LINK);
                        else
                            SET_STATUS(as->val_ac_status, nextrr,
                                       VAL_AC_UNKNOWN_ALGORITHM_LINK);

                        FREE(ds.d_hash);
                        if (dnskey.public_key) {
                            FREE(dnskey.public_key);
                        }
                        /*
                        * the first match is enough 
                        */
                        val_log(ctx, LOG_INFO, "verify_next_assertion(): Key links upward");
                        return;
                    }

                    FREE(ds.d_hash);
                    ds.d_hash = NULL;
                }

                dsrec = dsrec->rr_next;
            }

            /*
             * Didn't find a valid entry in the DS record set 
             * Not necessarily a problem, since there is no requirement that a DS be present
             * If none match, then we set the status accordingly. See below.
             */
            nextrr->rr_status = VAL_AC_DS_NOMATCH;
        }

        if (dnskey.public_key != NULL) {
            FREE(dnskey.public_key);
            dnskey.public_key = NULL;
        }
    }

    if (as->val_ac_status == VAL_AC_TRUST_NOCHK) {
        /* we were not able to verify our trust anchor */
        as->val_ac_status = VAL_AC_NO_TRUST_ANCHOR;
    }
}
