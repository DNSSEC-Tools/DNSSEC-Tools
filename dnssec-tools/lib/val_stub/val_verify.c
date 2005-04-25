/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the implementation file for the verifier.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <arpa/nameser.h>

#include <resolver.h>
#include <res_errors.h>
#include <support.h>
#include <res_query.h>

#include "val_support.h"
#include "val_zone.h"
#include "res_squery.h"
#include "val_cache.h"
#include "val_errors.h"
#include "val_x_query.h"
#include "validator.h"
#include "val_log.h"

#include "val_print.h"
#include "val_parse.h"
#include "crypto/val_rsamd5.h"
#include "crypto/val_rsasha1.h"
#include "crypto/val_dsasha1.h"

#include "val_verify.h"
#include "val_cache.h"


#define ZONE_KEY_FLAG 0x0100 /* Zone Key Flag, RFC 4034 */
#define BUFLEN 8192

/* Verify a signature, given the data and the dnskey */
/* Pass in a context, to give acceptable time skew */
static int val_sigverify (const char *data,
			  int data_len,
			  const val_dnskey_rdata_t dnskey,
			  const val_rrsig_rdata_t rrsig)
{
    /* Check if the dnskey is a zone key */
    if ((dnskey.flags & ZONE_KEY_FLAG) == 0) {
	val_log("DNSKEY not a zone signing key\n");
	return NOT_A_ZONE_KEY;
    }
    
    /* Check dnskey protocol value */
    if (dnskey.protocol != 3) {
	val_log("Invalid protocol field in DNSKEY record: %d\n",
	       dnskey.protocol);
	return UNKNOWN_DNSKEY_PROTO;
    }

    /* Match dnskey and rrsig algorithms */
    if (dnskey.algorithm != rrsig.algorithm) {
	val_log("Algorithm mismatch between DNSKEY (%d) and RRSIG (%d) records.\n",
	       dnskey.algorithm, rrsig.algorithm);
	return INTERNAL_ERROR;
    }

    /* Check signature inception and expiration times */
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    if (tv.tv_sec < rrsig.sig_incp) {
	char currTime[1028];
	char incpTime[1028];
	bzero(currTime, 1028);
	bzero(incpTime, 1028);
	ctime_r((const time_t *)(&(tv.tv_sec)), currTime);
	ctime_r((const time_t *)(&(rrsig.sig_incp)), incpTime);
	val_log("Signature not yet valid. Current time (%s) is less than signature inception time (%s).\n",
	       currTime, incpTime);
	return RRSIG_NOTYETACTIVE;
    }

    if (tv.tv_sec > rrsig.sig_expr) {
	char currTime[1028];
	char exprTime[1028];
	bzero(currTime, 1028);
	bzero(exprTime, 1028);
	ctime_r((const time_t *)(&(tv.tv_sec)), currTime);
	ctime_r((const time_t *)(&(rrsig.sig_expr)), exprTime);
	val_log("Signature expired. Current time (%s) is greater than signature expiration time (%s).\n",
	       currTime, exprTime);
	return RRSIG_EXPIRED;
    }

    switch(rrsig.algorithm) {
	
    case 1: return  rsamd5_sigverify(data, data_len, dnskey, rrsig); break;
    case 3: return dsasha1_sigverify(data, data_len, dnskey, rrsig); break;
    case 5: return rsasha1_sigverify(data, data_len, dnskey, rrsig); break;
    case 2:
    case 4:
	val_log("Unsupported algorithm %d.\n", dnskey.algorithm);
	return ALGO_NOT_SUPPORTED;
	break;

    default:
	do {
	    val_log("Unknown algorithm %d.\n", dnskey.algorithm);
	    return UNKNOWN_ALGO;
	} while (0);
    }

}

/* returns the number of bytes that were put into rrBuf */
/* Concatenate the rrset into a buffer */
/* Assume canonical ordering of RRs in the rrset */
static int val_concat_rrset ( struct rrset_rec *rrset,
			      const unsigned int orig_ttl,
			      unsigned char *rrBuf,
			      int orig_rrBuf_len) {

    int rrBuf_len = 0;
    struct rr_rec *rr = NULL;
    unsigned char *cp;
    
    /* Assume that elements of the rrs_data list are in canonical form */
    /* sort the rrs_rdata by bubble-sort */
    int sorted = 0;
    while (!sorted) {
	struct rr_rec *first_rr = NULL, *prev_rr = NULL, *curr_rr1 = NULL, *curr_rr2 = NULL, *next_rr = NULL;
	sorted = 1;
	curr_rr1 = rrset->rrs_data;
	first_rr = curr_rr1;

	if (curr_rr1) curr_rr2 = curr_rr1->rr_next;
	while (curr_rr2 != NULL) {

	    int cmp_len = (curr_rr1->rr_rdata_length_h < curr_rr2->rr_rdata_length_h) ?
		curr_rr1->rr_rdata_length_h : curr_rr2->rr_rdata_length_h;
	    
	    next_rr = curr_rr2->rr_next;
	    int cmp_res = memcmp (curr_rr1->rr_rdata, curr_rr2->rr_rdata, cmp_len);
	    if ((cmp_res > 0) || ((cmp_res == 0) && (curr_rr2->rr_rdata_length_h > curr_rr1->rr_rdata_length_h))) {
		/* switch rrs */
		struct rr_rec *tmp_rr = NULL;
		sorted = 0;
		curr_rr1->rr_next = next_rr;
		curr_rr2->rr_next = curr_rr1;
		if (prev_rr) {
		    prev_rr->rr_next = curr_rr2;
		}
		else {
		    first_rr = curr_rr2;
		}
		tmp_rr = curr_rr2;
		curr_rr2 = curr_rr1;
		curr_rr1 = tmp_rr;
	    }

	    prev_rr = curr_rr1;
	    curr_rr1 = curr_rr2;
	    curr_rr2 = curr_rr2->rr_next;
	}
	rrset->rrs_data = first_rr;
    }
    
    rr = rrset->rrs_data;
    while (rr) {
	memcpy(rrBuf + rrBuf_len, rrset->rrs_name_n, strlen(rrset->rrs_name_n) + 1);
	rrBuf_len += strlen(rrset->rrs_name_n) + 1;

	cp = rrBuf + rrBuf_len;
	NS_PUT16(rrset->rrs_type_h, cp);
	rrBuf_len += 2;

	NS_PUT16(rrset->rrs_class_h, cp);
	rrBuf_len += 2;

	/* Put the original ttl */
	NS_PUT32(orig_ttl, cp);
	rrBuf_len += 4;

	NS_PUT16(rr->rr_rdata_length_h, cp);
	rrBuf_len += 2;

	memcpy(rrBuf +rrBuf_len, rr->rr_rdata, rr->rr_rdata_length_h);
	rrBuf_len += rr->rr_rdata_length_h;

	rr = rr->rr_next;
    }
    return rrBuf_len;
}

/* tells whether the response contain any rrsigs */
static int have_rrsigs (struct domain_info *response)
{
    struct rrset_rec *rrset;

    if (!response) {
	return 0;
    }

    rrset = response->di_rrset;
    while (rrset) {
	struct rr_rec *rrs_sig = rrset->rrs_sig;
	while (rrs_sig) {
	    val_rrsig_rdata_t rrsig_rdata;
	    bzero(&rrsig_rdata, sizeof(rrsig_rdata));
	    val_parse_rrsig_rdata(rrs_sig->rr_rdata, rrs_sig->rr_rdata_length_h,
				  &rrsig_rdata);
	    if ((rrsig_rdata.type_covered == rrset->rrs_type_h) ||
	        (rrsig_rdata.type_covered == ns_t_nsec)) {
		return 1;
	    }
	    rrs_sig = rrs_sig->rr_next;
	}
	rrset = rrset->rrs_next;
    }

    return 0;
}


val_result_t val_verify (struct val_context *context, struct domain_info *response)
{
    val_dnskey_rdata_t *dnskey_rdata, *dp;
    struct rrset_rec *dnskeys;
    struct rrset_rec *rrset;
    u_int8_t sig_data[BUFLEN*2];
    val_result_t status = INDETERMINATE;
    char requested_name[MAXDNAME];

    if (!response) {
	val_log("val_verify(): no response to verify\n");
	return INTERNAL_ERROR;
    }

    //dnskeys = context->learned_keys;
	dnskeys = get_cached_keys();

    if (!dnskeys) {
	if (have_rrsigs(response)) {
	    val_log("val_verify(): no dnskeys found.\n");
	    return DNSKEY_MISSING;
	}
	else {
	    val_log("val_verify(): no dnskeys or rrsigs found.  probably not a signed zone.\n");
	    return INDETERMINATE;
	}
    }

    // Parse the dnskeys
    dnskey_rdata = NULL;
    val_log("val_verify(): parsing DNSKEYs\n");

    while (dnskeys) {
	if (dnskeys->rrs_type_h == ns_t_dnskey) {
	    struct rr_rec *rrs_data = dnskeys->rrs_data;
	    while (rrs_data) {
		val_dnskey_rdata_t *new_dnskey_rdata = (val_dnskey_rdata_t *) malloc (sizeof(val_dnskey_rdata_t));
		val_parse_dnskey_rdata (rrs_data->rr_rdata,
					rrs_data->rr_rdata_length_h,
					new_dnskey_rdata);
		
		new_dnskey_rdata->next = dnskey_rdata;
		dnskey_rdata = new_dnskey_rdata;
		val_print_dnskey_rdata("", dnskey_rdata);
		val_log("\n");
		
		rrs_data = rrs_data->rr_next;
	    }
	}
	dnskeys = dnskeys->rrs_next;
    }

    if (dnskey_rdata == NULL) {
	// No DNSKEYs were found
	if (have_rrsigs(response)) {
	    status = DNSKEY_MISSING;
	}
	else {
	    status = INDETERMINATE;
	}
	goto cleanup;
    }

    bzero(requested_name, MAXDNAME);
    ns_name_pton(response->di_requested_name_h, requested_name, MAXDNAME);

    // Check for each rrset
    rrset = response->di_rrset;
    while(rrset) {
	int sigresult = INTERNAL_ERROR;
	int found_rrsig  = 0;
	int found_dnskey = 0;
	int verified = 0;
	struct rr_rec *rrs_sig = rrset->rrs_sig;
	char rrs_name[MAXDNAME];
	bzero(rrs_name, MAXDNAME);
	ns_name_ntop(rrset->rrs_name_n, rrs_name, MAXDNAME);

	// Check for each signature
	while (rrs_sig && (!verified)) {
	    val_rrsig_rdata_t rrsig_rdata;
	    int sig_data_len;

	    val_log("val_verify(): parsing rrsig for %s\n", rrs_name);

	    bzero(&rrsig_rdata, sizeof(rrsig_rdata));
	    val_parse_rrsig_rdata(rrs_sig->rr_rdata, rrs_sig->rr_rdata_length_h,
				  &rrsig_rdata);
	    val_print_rrsig_rdata (" ", &rrsig_rdata);
	    val_log("\n");

	    if (rrsig_rdata.type_covered != rrset->rrs_type_h) {
		val_log("Different type covered by rrsig");
		rrs_sig = rrs_sig->rr_next;
		continue;
	    }

	    found_rrsig = 1;

	    // Compose the signature data
	    val_log("val_verify(): composing signature data\n");
	    bzero(sig_data, BUFLEN*2);

	    /* Copy rrsig rdata, except signature */
	    /* RFC 4034 section 3.1.7 says that the signer's name field in the rrsig_rdata
	     * is not compressed */
	    memcpy(sig_data, rrs_sig->rr_rdata, rrs_sig->rr_rdata_length_h - rrsig_rdata.signature_len);
	    sig_data_len = rrs_sig->rr_rdata_length_h - rrsig_rdata.signature_len;
	    
	    /* Copy RRs in the rrset in canonical order */
	    // Compose the canonical form of the rrset data
	    val_log("val_verify(): concatenating rrset\n");
	    {
		unsigned char canon_rrset[BUFLEN];
		int canon_rrset_length = 0;
		bzero(canon_rrset, BUFLEN);

		canon_rrset_length = val_concat_rrset(rrset, rrsig_rdata.orig_ttl, canon_rrset, BUFLEN);
		memcpy(sig_data + sig_data_len, canon_rrset, canon_rrset_length);
		sig_data_len += canon_rrset_length;
	    }

	    // For each dnskey verify if the signature matches
	    dp = dnskey_rdata;
	    while (dp && (!verified)) {
		val_log("val_verify(): Trying DNSKEY with keytag = %d\n", dp->key_tag);
		if (dp->key_tag != rrsig_rdata.key_tag) {
		    dp = dp->next;
		    val_log("val_verify(): keytag does not match. Trying next DNSKEY\n");
		    continue;
		}

		found_dnskey = 1;

		/* verify signature */
		val_log("val_verify(): verifying signature\n");
		if ((sigresult = val_sigverify(sig_data, sig_data_len,
					       *dp, rrsig_rdata)) == RRSIG_VERIFIED) {
		    verified = 1;
		    dp = dp->next;
		    continue;
		}
		else {
		    val_log("val_verify(): verification failed. Trying next DNSKEY\n");
		}

		dp = dp->next;
	    }

	    if (rrsig_rdata.signature) free(rrsig_rdata.signature);
	    rrs_sig = rrs_sig->rr_next;
	}
	
	if (!found_rrsig) {
	    val_log("val_verify(): RRSIG not found for %s\n", rrs_name);
	    rrset->rrs_status = RRSIG_MISSING;
	}
	else if (!found_dnskey) {
	        val_log("val_verify(): DNSKEY not found.\n");
		rrset->rrs_status = DNSKEY_MISSING;
	}
	else {
	    // Check if the rrset matches the query
	    if (((response->di_requested_type_h == ns_t_any) ||
	         ((response->di_requested_type_h == ns_t_a) && (rrset->rrs_type_h == ns_t_cname)) ||
                 (response->di_requested_type_h == rrset->rrs_type_h)) &&
		(response->di_requested_class_h == rrset->rrs_class_h) &&
		(strcasecmp(requested_name, rrset->rrs_name_n) == 0)
		) {
	        val_log("val_verify(): RRSET matches query.\n");
		if (sigresult == RRSIG_VERIFIED) {
		    status = VALIDATE_SUCCESS;
		}
		else if (status != VALIDATE_SUCCESS) {
		    status = sigresult;
		}
	    }
	    else {
	        val_log("val_verify(): RRSET does not match query.\n");
	    }
	    val_log("val_verify(): status = %s.\n", p_val_error(status));
	    
	    rrset->rrs_status = sigresult;
	}
	
	rrset = rrset->rrs_next;
    }

 cleanup:
    // Free dnskey rdata structs
    dp = dnskey_rdata;
    while (dp) {
	val_dnskey_rdata_t *sdp;
	sdp = dp->next;
	if (dp->public_key) free (dp->public_key);
	free(dp);
	dp = sdp;
    }
    
    return status;
}


int predict_sigbuflength (  struct rrset_rec *rr_set,
                            size_t *field_length,
                            int *signer_length)
{
    /*
        Calculate the size of the field over which the verification
        is done.  This is the sum of
            the number of bytes through the signer name in the SIG RDATA
            the length of the signer name (uncompressed)
            the sum of the fully uncompressed lengths of the RRs in the set
        *field_length is the field length
        *signer_length is the length of the signer's name (used externally)
    */
    struct rr_rec   *rr;
    int             owner_length;
                                                                                                                          
    owner_length = wire_name_length (rr_set->rrs_name_n);
                                                                                                                          
    *signer_length = wire_name_length (&rr_set->rrs_sig->rr_rdata[SIGNBY]);
                                                                                                                          
    if (*signer_length == 0) return SR_INTERNAL_ERROR;
                                                                                                                          
    *field_length = SIGNBY + (*signer_length);
                                                                                                                          
    for (rr = rr_set->rrs_data; rr; rr = rr->rr_next)
        *field_length += owner_length + ENVELOPE + rr->rr_rdata_length_h;
                                                                                                                          
    return SR_UNSET;
}

int make_sigfield (  u_int8_t            **field,
                        int                 *field_length,
                        struct rrset_rec    *rr_set,
                        struct rr_rec       *rr_sig,
                        int                 is_a_wildcard)
{
    struct rr_rec       *curr_rr;
    int                 index;
    int                 signer_length;
    int                 owner_length;
    u_int16_t           type_n;
    u_int16_t           class_n;
    u_int32_t           ttl_n;
    u_int16_t           rdata_length_n;
    u_int8_t            lowered_owner_n[MAXDNAME];
    size_t              l_index;
                                                                                                                          
    if (predict_sigbuflength (rr_set, field_length, &signer_length)!=SR_UNSET)
        return SR_INTERNAL_ERROR;
                                                                                                                          
    *field = (u_int8_t*) MALLOC (*field_length);
                                                                                                                          
    if (*field == NULL) return SR_MEMORY_ERROR;
                                                                                                                          
    /* Make sure we are using the correct TTL */
                                                                                                                          
    memcpy (&ttl_n, &rr_sig->rr_rdata[TTL],sizeof(u_int32_t));
    rr_set->rrs_ttl_h = ntohl (ttl_n);
                                                                                                                          
    /*
        While we're at it, we'll gather other common info, specifically
        network ordered numbers (type, class) and name length.
    */
                                                                                                                          
    owner_length = wire_name_length (rr_set->rrs_name_n);
                                                                                                                          
    if (owner_length == 0) return SR_INTERNAL_ERROR;
                                                                                                                          
    memcpy (lowered_owner_n, rr_set->rrs_name_n, owner_length);
    l_index = 0;
    lower_name (lowered_owner_n, &l_index);
                                                                                                                          
    type_n = htons(rr_set->rrs_type_h);
    class_n = htons(rr_set->rrs_class_h);
                                                                                                                          
    /* Copy in the SIG RDATA (up to the signature */
                                                                                                                          
    index = 0;
    memcpy (&(*field)[index], rr_sig->rr_rdata, SIGNBY+signer_length);
    index += SIGNBY+signer_length;
                                                                                                                          
    /* For each record of data, copy in the envelope & the lower cased rdata */
                                                                                                                          
    for (curr_rr = rr_set->rrs_data; curr_rr; curr_rr = curr_rr->rr_next)
    {
        /* Copy in the envelope information */
                                                                                                                          
        if (is_a_wildcard)
        {
            u_int8_t    wildcard_label[2];
            size_t      wildcard_label_length = 2;
            wildcard_label[0] = (u_int8_t) 1;
            wildcard_label[1] = (u_int8_t) '*';
                                                                                                                          
            memcpy (&(*field)[index],wildcard_label,wildcard_label_length);
            index += wildcard_label_length;
        }
        else
        {
            memcpy (&(*field)[index], lowered_owner_n, owner_length);
            index += owner_length;
        }
        memcpy (&(*field)[index], &type_n, sizeof(u_int16_t));
        index += sizeof(u_int16_t);
        memcpy (&(*field)[index], &class_n, sizeof(u_int16_t));
        index += sizeof(u_int16_t);
        memcpy (&(*field)[index], &ttl_n, sizeof(u_int32_t));
        index += sizeof(u_int32_t);
                                                                                                                          
        /* Now the RR-specific info, the length and the data */
                                                                                                                          
        rdata_length_n = htons (curr_rr->rr_rdata_length_h);
        memcpy (&(*field)[index], &rdata_length_n, sizeof(u_int16_t));
        index += sizeof(u_int16_t);
        memcpy (&(*field)[index],curr_rr->rr_rdata,curr_rr->rr_rdata_length_h);
        index += curr_rr->rr_rdata_length_h;
    }
                                                                                                                          
    return SR_UNSET;
}

int find_signature (u_int8_t **field, struct rr_rec *rr_sig)
{
    int     sig_index;
                                                                                                                          
    sig_index = SIGNBY + wire_name_length (&rr_sig->rr_rdata[SIGNBY]);
                                                                                                                          
    *field = &rr_sig->rr_rdata[sig_index];
                                                                                                                          
    return rr_sig->rr_rdata_length_h - sig_index;
}

void identify_key_from_sig (struct rr_rec *sig,u_int8_t **name_n,u_int16_t *footprint_n)
{
    *name_n = &sig->rr_rdata[SIGNBY];
    memcpy (footprint_n, &sig->rr_rdata[SIGNBY-sizeof(u_int16_t)],
                sizeof(u_int16_t));
}

int  find_key_for_tag (struct rr_rec *keyrr, u_int16_t *tag, val_dnskey_rdata_t *new_dnskey_rdata)
{
	struct rr_rec *nextrr;
	u_int16_t fp;

	for (nextrr = keyrr; nextrr; nextrr=nextrr->rr_next)
	{
		if (new_dnskey_rdata == NULL) 
			return OUT_OF_MEMORY;

		val_parse_dnskey_rdata (nextrr->rr_rdata,
                    nextrr->rr_rdata_length_h,
                    new_dnskey_rdata);
		new_dnskey_rdata->next = NULL;        
                                                                                                           
    	memcpy (&fp, &new_dnskey_rdata->key_tag, sizeof(u_int16_t));
		if (*tag == htons(fp))
			return NO_ERROR;

		free(new_dnskey_rdata->public_key);
	}
	
	return DNSKEY_MISSING;
}


#define WHERE_LABELS_IS 3
int check_label_count (
                            struct rrset_rec    *the_set,
                            struct rr_rec       *the_sig,
                            int                 *is_a_wildcard)
{
    u_int8_t owner_labels = wire_name_labels (the_set->rrs_name_n);
    u_int8_t sig_labels = the_sig->rr_rdata[WHERE_LABELS_IS] + 1;
                                                                                                                          
    if (sig_labels > owner_labels) return SR_PROCESS_ERROR;
                                                                                                                          
    *is_a_wildcard = (sig_labels < owner_labels);
                                                                                                                          
    return SR_UNSET;
}

int do_verify (   int                 *sig_status,
                  struct rrset_rec    *the_set,
                  struct rr_rec       *the_sig,
                  val_dnskey_rdata_t  *the_key,
                  int                 is_a_wildcard)
{
    /*
        Use the crypto routines to verify the signature
        Put the result into rrs_status
    */
                                                                                                                          
    u_int8_t            *ver_field;
    size_t              ver_length;
 //   u_int8_t            *sig_field;
 //   size_t              sig_length;
    int                 ret_val;
	val_rrsig_rdata_t rrsig_rdata;

    if (the_set==NULL||the_key==NULL) return SR_INTERNAL_ERROR;
                                                                                                                          
    if ((ret_val=make_sigfield (&ver_field, &ver_length, the_set, the_sig,
                                        is_a_wildcard)) != SR_UNSET)
        return ret_val;
                                                                                                                          
    /* Find the signature - no memory is malloc'ed for this operation  */
                                                                                                                          
//  sig_length = find_signature (&sig_field, the_sig);
//	val_parse_rrsig_rdata(sig_field, sig_length, &rrsig_rdata);
	val_parse_rrsig_rdata(the_sig->rr_rdata, the_sig->rr_rdata_length_h,
                  &rrsig_rdata);    
	rrsig_rdata.next = NULL;
                                                                                                                      
    /* Perform the verification */
	*sig_status = val_sigverify(ver_field, ver_length, *the_key, rrsig_rdata);
  
/*
val_log ("\nVerifying this field:\n");
print_hex_field (ver_field,ver_length,21,"VER: ");
val_log ("\nThis is the supposed signature:\n");
print_hex_field (sig_field,sig_length,21,"SIG: ");
val_log ("Result of verification is %s\n", ret_val==0?"GOOD":"BAD");
*/
    FREE (ver_field);
    return SR_UNSET;
}


#ifndef DIGEST_SHA_1
#define DIGEST_SHA_1 1
#endif
int hash_is_equal (u_int8_t ds_hashtype, u_int8_t *ds_hash, u_int8_t *public_key, u_int32_t public_key_len)
{
	/* Only SHA-1 is understood */
    if(ds_hashtype != htons(DIGEST_SHA_1))
        return 0;

	// XXX check hashes
	return 1;	
}


void verify_next_assertion(struct assertion_chain *as)
{
	struct rrset_rec *the_set;
	struct rr_rec   *the_sig;
	u_int8_t        *signby_name_n;
	u_int16_t       signby_footprint_n;
	val_dnskey_rdata_t dnskey;
	int             is_a_wildcard;
	struct assertion_chain *the_trust;
	int verified = 0;

	the_set = as->ac_data;
	the_trust = as->ac_trust;
	for (the_sig = the_set->rrs_sig;the_sig;the_sig = the_sig->rr_next) {

		/* for each sig, identify key, */ 
		identify_key_from_sig (the_sig, &signby_name_n, &signby_footprint_n);

		if(the_set->rrs_type_h != ns_t_dnskey) {
			/* trust path contains the key */
			if(NO_ERROR != 
				find_key_for_tag (the_trust->ac_data->rrs_data, 
					&signby_footprint_n, &dnskey)) {
				the_sig->status = SIG_KEY_NOT_AVAILABLE;
				free(dnskey.public_key);
				continue;
			}
		}
		else {
			/* data itself contains the key */
			if(NO_ERROR != find_key_for_tag (the_set->rrs_data, &signby_footprint_n, &dnskey)) {
				the_sig->status = SIG_KEY_NOT_AVAILABLE;
				free(dnskey.public_key);
				continue;
			}
		}	

		/* do wildcard processing */
		if(check_label_count (the_set, the_sig, &is_a_wildcard) != SR_UNSET) {
			the_sig->status = SIG_BAD_LABEL_COUNT;
			free(dnskey.public_key);
			continue;
		}

		/* and check the signature */
		if(SR_UNSET != do_verify(&the_sig->status, the_set, the_sig, &dnskey, is_a_wildcard)) {
			the_sig->status = SIG_PROCESS_ERR;
			free(dnskey.public_key);
			continue;
		}

		/* If this record contains a DNSKEY, check if the DS record contains this key */
		if(the_sig->status == RRSIG_VERIFIED) {
			if (the_set->rrs_type_h == ns_t_dnskey) {
				/* follow the trust path */
				struct rr_rec *dsrec = the_trust->ac_data->rrs_data;		
				uint16_t keytag = htons(dnskey.key_tag);
				while(dsrec)	
				{	
					val_ds_rdata_t ds;
					val_parse_ds_rdata(dsrec->rr_rdata, dsrec->rr_rdata_length_h, &ds);
					if((ds.d_keytag == keytag) 
						&& (ds.d_algo == dnskey.algorithm)) 
						if (hash_is_equal(ds.d_type, 
								ds.d_hash, dnskey.public_key,
								dnskey.public_key_len))
							break;
					dsrec = dsrec->rr_next;
				}
				if(!dsrec)
					the_sig->status = SIG_DS_NOMATCH;
				else
					verified = 1;
			}
			else
				verified = 1;
		}
		free(dnskey.public_key);
	}

	as->ac_state = (verified == 1)? A_VERIFIED : A_VERIFY_FAILED;
}
