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

#include <resolver.h>
#include <validator.h>
#include "val_support.h"
#include "val_cache.h"
#include "val_verify.h"
#include "crypto/val_rsamd5.h"
#include "crypto/val_rsasha1.h"
#include "crypto/val_dsasha1.h"


#define ZONE_KEY_FLAG 0x0100 /* Zone Key Flag, RFC 4034 */
#define BUFLEN 8192

/* Verify a signature, given the data and the dnskey */
/* Pass in a context, to give acceptable time skew */
static int val_sigverify (
				val_context_t *ctx,
				const char *data,
			  int data_len,
			  const val_dnskey_rdata_t dnskey,
			  const val_rrsig_rdata_t rrsig)
{
    /* Check if the dnskey is a zone key */
    if ((dnskey.flags & ZONE_KEY_FLAG) == 0) {
	val_log(ctx, LOG_DEBUG, "DNSKEY not a zone signing key");
	return NOT_A_ZONE_KEY;
    }
    
    /* Check dnskey protocol value */
    if (dnskey.protocol != 3) {
	val_log(ctx, LOG_DEBUG, "Invalid protocol field in DNSKEY record: %d",
	       dnskey.protocol);
	return UNKNOWN_DNSKEY_PROTO;
    }

    /* Match dnskey and rrsig algorithms */
    if (dnskey.algorithm != rrsig.algorithm) {
	val_log(ctx, LOG_DEBUG, "Algorithm mismatch between DNSKEY (%d) and RRSIG (%d) records.",
	       dnskey.algorithm, rrsig.algorithm);
	return RRSIG_ALGO_MISMATCH;
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
	val_log(ctx, LOG_DEBUG, "Signature not yet valid. Current time (%s) is less than signature inception time (%s).",
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
	val_log(ctx, LOG_DEBUG, "Signature expired. Current time (%s) is greater than signature expiration time (%s).",
	       currTime, exprTime);
	return RRSIG_EXPIRED;
    }

    switch(rrsig.algorithm) {
	
    case 1: return  rsamd5_sigverify(ctx, data, data_len, dnskey, rrsig); break;
    case 3: return dsasha1_sigverify(ctx, data, data_len, dnskey, rrsig); break;
    case 5: return rsasha1_sigverify(ctx, data, data_len, dnskey, rrsig); break;
    case 2:
    case 4:
	val_log(ctx, LOG_DEBUG, "Unsupported algorithm %d.\n", dnskey.algorithm);
	return ALGO_NOT_SUPPORTED;
	break;

    default:
	do {
	    val_log(ctx, LOG_DEBUG, "Unknown algorithm %d.", dnskey.algorithm);
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
			if(rrsig_rdata.signature != NULL)
				FREE(rrsig_rdata.signature);
		return 1;
	    }
		if(rrsig_rdata.signature != NULL)
			FREE(rrsig_rdata.signature);
	    rrs_sig = rrs_sig->rr_next;
	}
	rrset = rrset->rrs_next;
    }

    return 0;
}


static int predict_sigbuflength (  struct rrset_rec *rr_set,
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
                                                                                                                          
    if (*signer_length == 0) return INTERNAL_ERROR;
                                                                                                                          
    *field_length = SIGNBY + (*signer_length);
                                                                                                                          
    for (rr = rr_set->rrs_data; rr; rr = rr->rr_next)
        *field_length += owner_length + ENVELOPE + rr->rr_rdata_length_h;
                                                                                                                          
    return NO_ERROR;
}

static int make_sigfield (  u_int8_t            **field,
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
                                                                                                                          
    if (predict_sigbuflength (rr_set, field_length, &signer_length)!=NO_ERROR)
        return INTERNAL_ERROR;
                                                                                                                          
    *field = (u_int8_t*) MALLOC (*field_length);
                                                                                                                          
    if (*field == NULL) return OUT_OF_MEMORY;
                                                                                                                          
    /* Make sure we are using the correct TTL */
                                                                                                                          
    memcpy (&ttl_n, &rr_sig->rr_rdata[TTL],sizeof(u_int32_t));
    rr_set->rrs_ttl_h = ntohl (ttl_n);
                                                                                                                          
    /*
        While we're at it, we'll gather other common info, specifically
        network ordered numbers (type, class) and name length.
    */
                                                                                                                          
    owner_length = wire_name_length (rr_set->rrs_name_n);
                                                                                                                          
    if (owner_length == 0) return INTERNAL_ERROR;
                                                                                                                          
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
			/* Construct the original name */
			u_char wcard_n[MAXCDNAME];
			u_int8_t *np = lowered_owner_n;
			int i;

			for (i = 0; i < is_a_wildcard; i++) 
				np += np[0] + 1;
			int outer_len =  wire_name_length(np);

			wcard_n[0] = (u_int8_t) 1;
			wcard_n[1] = '*';
			memcpy(&wcard_n[2], np, outer_len);
			memcpy (&(*field)[index], wcard_n, outer_len+2);
			index += outer_len+2;
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
            
	*field_length = index;                                                                                                              
    return NO_ERROR;
}

static int find_signature (u_int8_t **field, struct rr_rec *rr_sig)
{
    int     sig_index;
                                                                                                                          
    sig_index = SIGNBY + wire_name_length (&rr_sig->rr_rdata[SIGNBY]);
                                                                                                                          
    *field = &rr_sig->rr_rdata[sig_index];
                                                                                                                          
    return rr_sig->rr_rdata_length_h - sig_index;
}

static void identify_key_from_sig (struct rr_rec *sig,u_int8_t **name_n,u_int16_t *footprint_n)
{
    *name_n = &sig->rr_rdata[SIGNBY];
    memcpy (footprint_n, &sig->rr_rdata[SIGNBY-sizeof(u_int16_t)],
                sizeof(u_int16_t));
}

static int  find_key_for_tag (struct rr_rec *keyrr, u_int16_t *tag_n, val_dnskey_rdata_t *new_dnskey_rdata)
{
	struct rr_rec *nextrr;
	u_int16_t tag_h = ntohs(*tag_n);

	for (nextrr = keyrr; nextrr; nextrr=nextrr->rr_next)
	{
		if (new_dnskey_rdata == NULL) 
			return OUT_OF_MEMORY;

		val_parse_dnskey_rdata (nextrr->rr_rdata,
                    nextrr->rr_rdata_length_h,
                    new_dnskey_rdata);
		new_dnskey_rdata->next = NULL;        
                                                                                                           
		if (new_dnskey_rdata->key_tag == tag_h)
			return NO_ERROR;
	}
	
	return DNSKEY_NOMATCH;
}



static int do_verify (   
					val_context_t *ctx,
					int                 *sig_status,
                  struct rrset_rec    *the_set,
                  struct rr_rec       *the_sig,
                  val_dnskey_rdata_t  *the_key,
                  int                 is_a_wildcard)
{
    /*
        Use the crypto routines to verify the signature
    */
                                                                                                                          
    u_int8_t            *ver_field;
    size_t              ver_length;
 //   u_int8_t            *sig_field;
 //   size_t              sig_length;
    int                 ret_val;
	val_rrsig_rdata_t rrsig_rdata;

    if (the_set==NULL||the_key==NULL) return INTERNAL_ERROR;
                                                                                                                          
    if ((ret_val=make_sigfield (&ver_field, &ver_length, the_set, the_sig,
                                        is_a_wildcard)) != NO_ERROR)
        return ret_val;
                                                                                                                          
    /* Find the signature - no memory is malloc'ed for this operation  */
                                                                                                                          
//  sig_length = find_signature (&sig_field, the_sig);
//	val_parse_rrsig_rdata(sig_field, sig_length, &rrsig_rdata);
	val_parse_rrsig_rdata(the_sig->rr_rdata, the_sig->rr_rdata_length_h,
                  &rrsig_rdata);    
	rrsig_rdata.next = NULL;
                                                                                                                      
    /* Perform the verification */
	*sig_status = val_sigverify(ctx, ver_field, ver_length, *the_key, rrsig_rdata);
  
	if(rrsig_rdata.signature != NULL)
		FREE(rrsig_rdata.signature);

    FREE (ver_field);
    return NO_ERROR;
}


#ifndef DIGEST_SHA_1
#define DIGEST_SHA_1 1
#endif
static int hash_is_equal (u_int8_t ds_hashtype, u_int8_t *ds_hash, u_int8_t *public_key, u_int32_t public_key_len)
{
	/* Only SHA-1 is understood */
    if(ds_hashtype != DIGEST_SHA_1)
        return 0;

	// XXX check hashes
	return 1;	
}

/*
 * State returned in as->val_ac_status is one of:
 * VERIFIED : at least one sig passed
 * A_NOT_VERIFIED : multiple errors
 * the exact error
 */

#define SET_STATUS(savedstatus, sig, newstatus) \
	do { \
		sig->status = newstatus; \
		if ((savedstatus != VERIFIED) && (savedstatus != newstatus))  \
			savedstatus = NOT_VERIFIED; \
		else	\
			savedstatus = newstatus; \
	} while (0)

// XXX Still have to check for the following error conditions
// XXX WRONG_RRSIG_OWNER
// XXX RRSIG_ALGO_MISMATCH
// XXX KEYTAG_MISMATCH
void verify_next_assertion(val_context_t *ctx, struct val_assertion_chain *as)
{
	struct rrset_rec *the_set;
	struct rr_rec   *the_sig;
	u_int8_t        *signby_name_n;
	u_int16_t       signby_footprint_n;
	val_dnskey_rdata_t dnskey;
	int             is_a_wildcard;
	struct val_assertion_chain *the_trust;
	int retval;

	as->val_ac_status = VERIFIED;

	the_set = as->_as->ac_data;
	the_trust = as->val_ac_trust;
	for (the_sig = the_set->rrs_sig;the_sig;the_sig = the_sig->rr_next) {

		/* for each sig, identify key, */ 
		identify_key_from_sig (the_sig, &signby_name_n, &signby_footprint_n);

		if(the_set->rrs_type_h != ns_t_dnskey) {
			/* trust path contains the key */
			if(NO_ERROR != (retval = 
				find_key_for_tag (the_trust->_as->ac_data->rrs_data, 
					&signby_footprint_n, &dnskey))) {
				SET_STATUS(as->val_ac_status, the_sig, DNSKEY_NOMATCH);
				if (dnskey.public_key != NULL)
					FREE(dnskey.public_key);
				continue;
			}
		}
		else {
			/* data itself contains the key */
			if(NO_ERROR != (retval = find_key_for_tag (the_set->rrs_data, &signby_footprint_n, &dnskey))) {
				SET_STATUS(as->val_ac_status, the_sig, DNSKEY_NOMATCH);
				if (dnskey.public_key != NULL)
					FREE(dnskey.public_key);
				continue;
			}
		}	

		/* do wildcard processing */
		if(check_label_count (the_set, the_sig, &is_a_wildcard) != NO_ERROR) {
			SET_STATUS(as->val_ac_status, the_sig, WRONG_LABEL_COUNT);
			FREE(dnskey.public_key);
			continue;
		}

		/* and check the signature */
		if(NO_ERROR != (retval = do_verify(ctx, &the_sig->status, the_set, the_sig, &dnskey, is_a_wildcard))) {
			SET_STATUS(as->val_ac_status, the_sig, retval);
			FREE(dnskey.public_key);
			continue;
		}

		FREE(dnskey.public_key);

		/* If this record contains a DNSKEY, check if the DS record contains this key */
		if(the_sig->status == RRSIG_VERIFIED) {
			if (the_set->rrs_type_h == ns_t_dnskey) {
				/* follow the trust path */
				struct rr_rec *dsrec = the_trust->_as->ac_data->rrs_data;		
				while(dsrec)	
				{	
					val_ds_rdata_t ds;
					val_parse_ds_rdata(dsrec->rr_rdata, dsrec->rr_rdata_length_h, &ds);
					u_int16_t ds_keytag_n = htons(ds.d_keytag);
					if(NO_ERROR != (retval = find_key_for_tag (the_set->rrs_data, &ds_keytag_n, &dnskey))) {
						dsrec = dsrec->rr_next;
						continue;
					}

					if((ds.d_keytag == dnskey.key_tag) 
						&& (ds.d_algo == dnskey.algorithm) 
						 && (hash_is_equal(ds.d_type, 
								ds.d_hash, dnskey.public_key,
								dnskey.public_key_len))) {
							FREE(dnskey.public_key);
							break;
					}

					dsrec = dsrec->rr_next;
				}

				if(!dsrec)
					SET_STATUS(as->val_ac_status, the_sig, SECURITY_LAME);
			}
		}
		else
			SET_STATUS(as->val_ac_status, the_sig, the_sig->status);

	}
}
