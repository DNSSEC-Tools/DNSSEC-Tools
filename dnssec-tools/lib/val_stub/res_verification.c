#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "res_key_monitor.h"
#include "dns_support.h"
#include "iip_support.h"
#include "res_verification.h"
#include "res_zone_info.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef NULL
#define NULL (void*)0
#endif

#define SIGNBY				18
#define ENVELOPE			10
#define TTL					 4

#define SR_V_SIG_UNSET		1
#define SR_V_SIG_ABSENT		1
#define SR_V_SIG_IMMATERIAL	2
#define SR_V_SIG_FAILED		3
#define SR_V_SIG_VALIDATED	4

int res_v_predict_length (	struct rrset_rec *rr_set,
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
	struct rr_rec	*rr;
	int				owner_length;

	owner_length = wire_name_length (rr_set->rrs_name_n);

	*signer_length = wire_name_length (&rr_set->rrs_sig->rr_rdata[SIGNBY]);

	if (*signer_length == 0) return SR_V_INTERNAL_ERROR;

	*field_length = SIGNBY + (*signer_length);

	for (rr = rr_set->rrs_data; rr; rr = rr->rr_next)
		*field_length += owner_length + ENVELOPE + rr->rr_rdata_length_h;

	return SR_V_UNSET;
}

void res_v_lower_name (u_int8_t rdata[], int *index)
{

	/* Convert the upper case characters in a domain name to lower case */

	int length = wire_name_length(&rdata[(*index)]);

	while ((*index) < length)
	{
		rdata[(*index)] = tolower(rdata[(*index)]);
		(*index)++;
	}
}

void res_v_lower (u_int16_t type_h, u_int8_t *rdata, int len)
{
	/* Convert the case of any domain name to lower in the RDATA section */

	int	index = 0;

	switch (type_h)
	{
		/* These RR's have no domain name in them */

		case ns_t_nsap:	case ns_t_eid:		case ns_t_nimloc:	case ns_t_key: case 48:
		case ns_t_aaaa:	case ns_t_loc:		case ns_t_atma:		case ns_t_a:
		case ns_t_wks:	case ns_t_hinfo:	case ns_t_txt:		case ns_t_x25:
		case ns_t_isdn:	default:

			return;

		/* These RR's have two domain names at the start */

		case ns_t_soa:	case ns_t_minfo:	case ns_t_rp:

			res_v_lower_name (rdata, &index);
			/* fall through */


		/* These have one name (and are joined by the code above) */

		case ns_t_ns:	case ns_t_cname:	case ns_t_mb:		case ns_t_mg:
		case ns_t_mr:	case ns_t_ptr:		case ns_t_nxt:

			res_v_lower_name (rdata, &index);

			return;

		/* These RR's end in one or two domain names */

		case ns_t_srv:

			index = 4; /* SRV has three preceeding 16 bit quantities */

		case ns_t_rt: case ns_t_mx: case ns_t_afsdb: case ns_t_px:

			index += 2; /* Pass the 16 bit quatity prior to the name */

			res_v_lower_name (rdata, &index);

			/* Get the second tail name (only in PX records) */
			if (type_h == ns_t_px) res_v_lower_name (rdata, &index);

			return;

		/* The last case is RR's with names in the middle. */
		/*
			Note: this code is never used as SIG's are the only record in
			this case.  SIG's are not signed, so they never are run through
			this code.  This is left here in case other RR's are defined in
			this unfortunate (for them) manner.
		*/
		case 46:
		case ns_t_sig:

			index = SIGNBY;

			res_v_lower_name (rdata, &index);

			return;
	}
}

struct rr_rec *res_v_copy (u_int16_t type_h, struct rr_rec *r)
{
	/*
		Make a copy of an RR, lowering the case of any contained
		domain name in the RR section.
	*/
	struct rr_rec *the_copy;

	the_copy = (struct rr_rec *) MALLOC (sizeof(struct rr_rec));

	if (the_copy==NULL) return NULL;

	the_copy->rr_rdata_length_h = r->rr_rdata_length_h;
	the_copy->rr_rdata = (u_int8_t *) MALLOC (the_copy->rr_rdata_length_h);

	if (the_copy->rr_rdata==NULL) return NULL;

	memcpy (the_copy->rr_rdata, r->rr_rdata, r->rr_rdata_length_h);

	res_v_lower (type_h, the_copy->rr_rdata, the_copy->rr_rdata_length_h);

	the_copy->rr_next = NULL;
	return the_copy;
}

#define INSERTED	1
#define DUPLICATE	-1
int res_v_insert (struct rrset_rec *cs, struct rr_rec *cr)
{
	/*
		Insert a copied RR into the set being prepared for signing.  This
		is an implementation of an insertoin sort.
	*/
	int				ret_val;
	int				length;
	struct rr_rec	*temp_rr;

	if (cs->rrs_data == NULL)
	{
		cs->rrs_data = cr;
		return INSERTED;
	}
	else
	{
		length =cs->rrs_data->rr_rdata_length_h<cr->rr_rdata_length_h?
				cs->rrs_data->rr_rdata_length_h:cr->rr_rdata_length_h;

		ret_val = memcmp (cs->rrs_data->rr_rdata, cr->rr_rdata, length);

		if (ret_val==0&&cs->rrs_data->rr_rdata_length_h==cr->rr_rdata_length_h)
		{
			/* cr is a copy of an existing record, forget it... */
			FREE (cr->rr_rdata);
			FREE (cr);
			return DUPLICATE;
		}
		else if (ret_val > 0 || (ret_val==0 && length==cr->rr_rdata_length_h))
		{
			cr->rr_next = cs->rrs_data;
			cs->rrs_data = cr;
			return INSERTED;
		}
		else
		{
			temp_rr = cs->rrs_data;

			if (temp_rr->rr_next == NULL)
			{
				temp_rr->rr_next = cr;
				cr->rr_next = NULL;
				return INSERTED;
			}

			while (temp_rr->rr_next)
			{
				length = temp_rr->rr_next->rr_rdata_length_h <
												cr->rr_rdata_length_h ?
						 temp_rr->rr_next->rr_rdata_length_h :
												cr->rr_rdata_length_h;
				
				ret_val = memcmp (temp_rr->rr_next->rr_rdata, cr->rr_rdata,
									length);
				if (ret_val==0 &&
					temp_rr->rr_next->rr_rdata_length_h==cr->rr_rdata_length_h)
				{
					/* cr is a copy of an existing record, forget it... */
					FREE (cr->rr_rdata);
					FREE (cr);
					return DUPLICATE;
				}
				else if (ret_val>0||(ret_val==0&&length==cr->rr_rdata_length_h))
				{
					/* We've found a home for the record */
					cr->rr_next = temp_rr->rr_next;
					temp_rr->rr_next = cr;
					return INSERTED;
				}
				temp_rr = temp_rr->rr_next;
			}

			/* If we've gone this far, add the record to the end of the list */

			temp_rr->rr_next = cr;
			cr->rr_next = NULL;
			return INSERTED;
		}
	}
}	

struct rrset_rec *res_v_prepare_for_field (struct rrset_rec *rr_set,
											size_t	*length)
{
	struct rrset_rec	*copy_set;
	struct rr_rec		*orig_rr;
	struct rr_rec		*copy_rr;
	size_t				o_length;
	int					rdata_len;

	copy_set = (struct rrset_rec *) MALLOC (sizeof(struct rrset_rec));

	if (copy_set == NULL) return NULL;

	o_length = wire_name_length (copy_set->rrs_name_n);
	memcpy (copy_set, rr_set, sizeof(struct rrset_rec));

	copy_set->rrs_data = NULL;
	copy_set->rrs_next = NULL;
	copy_set->rrs_sig = NULL;
	copy_set->rrs_name_n = NULL;

	/*
		Do an insertion sort of the records in rr_set.  As records are
		copied, convert the domain names to lower case.
	*/

	for (orig_rr = rr_set->rrs_data; orig_rr; orig_rr = orig_rr->rr_next)
	{
		/* Copy it into the right form for verification */
		copy_rr = res_v_copy (rr_set->rrs_type_h, orig_rr);

		if (copy_rr==NULL) return NULL;

		rdata_len = copy_rr->rr_rdata_length_h;

		/* Now, find a place for it */

		if (res_v_insert (copy_set, copy_rr) == DUPLICATE)
			*length -= (o_length + ENVELOPE + rdata_len);
	}
	return copy_set;
}

int res_v_make_field (	u_int8_t			**field,
						int					*field_length,
						struct rrset_rec	*rr_set,
						struct rr_rec		*rr_sig,
						int					is_a_wildcard)
{
	struct rr_rec		*curr_rr;
	int					index;
	int					signer_length;
	int					owner_length;
	u_int16_t			type_n;
	u_int16_t			class_n;
	u_int32_t			ttl_n;
	u_int16_t			rdata_length_n;
	struct rrset_rec	*copy_set;
	u_int8_t			lowered_owner_n[MAXDNAME];
	size_t				l_index;

	if (res_v_predict_length (rr_set, field_length, &signer_length)!=SR_V_UNSET)
		return SR_V_INTERNAL_ERROR;

	*field = (u_int8_t*) MALLOC (*field_length);

	if (*field == NULL) return SR_V_MEMORY_ERROR;

	/* Make sure we are using the correct TTL */

	memcpy (&ttl_n, &rr_sig->rr_rdata[TTL],sizeof(u_int32_t));
	rr_set->rrs_ttl_h = ntohl (ttl_n);

	/*
		While we're at it, we'll gather other common info, specifically
		network ordered numbers (type, class) and name length.
	*/

	owner_length = wire_name_length (rr_set->rrs_name_n);

	if (owner_length == 0) return SR_V_INTERNAL_ERROR;

	memcpy (lowered_owner_n, rr_set->rrs_name_n, owner_length);
	l_index = 0;
	res_v_lower_name (lowered_owner_n, &l_index);

	type_n = htons(rr_set->rrs_type_h);
	class_n = htons(rr_set->rrs_class_h);

	/* Copy in the SIG RDATA (up to the signature */

	index = 0;
	memcpy (&(*field)[index], rr_sig->rr_rdata, SIGNBY+signer_length);
	index += SIGNBY+signer_length;

	/* Convert to lower case & sort the records */

	if ((copy_set = res_v_prepare_for_field (rr_set, field_length))==NULL)
	{
		FREE (*field);
		*field = NULL;
		return SR_V_MEMORY_ERROR;
	}

	/* For each record of data, copy in the envelope & the lower cased rdata */

	for (curr_rr = copy_set->rrs_data; curr_rr; curr_rr = curr_rr->rr_next)
	{
		/* Copy in the envelope information */

		if (is_a_wildcard)
		{
			u_int8_t	wildcard_label[2];
			size_t		wildcard_label_length = 2;
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

	res_sq_free_rrset_recs (&copy_set);

	return SR_V_UNSET;
}

int res_v_find_signature (u_int8_t **field, struct rr_rec *rr_sig)
{
	int		sig_index;

	sig_index = SIGNBY + wire_name_length (&rr_sig->rr_rdata[SIGNBY]);

	*field = &rr_sig->rr_rdata[sig_index];

	return rr_sig->rr_rdata_length_h - sig_index;
}

void res_v_identify_key (struct rr_rec *sig,u_int8_t **name_n,u_int16_t *footprint_n)
{
	*name_n = &sig->rr_rdata[SIGNBY];
	memcpy (footprint_n, &sig->rr_rdata[SIGNBY-sizeof(u_int16_t)],
				sizeof(u_int16_t));
}

void  res_v_identify_tag (char *name_n, struct rr_rec *keyrr, u_int16_t *footprint_n)
{
	u_int8_t *key = keyrr->rr_rdata;
	u_int16_t keysize = keyrr->rr_rdata_length_h;

	DST_KEY *dkey = dst_dnskey_to_public_key(keysize, key, name_n);
	memcpy (footprint_n, &dkey->dk_id, sizeof(u_int16_t));
}


int res_v_do_verify (	int					*it_passes,
						struct rrset_rec	*the_set,
						struct rr_rec		*the_sig,
						DST_KEY				*the_key,
						int					is_a_wildcard)
{
	/*
		Use the crypto routines to verify the signature
		Put the result into rrs_status
	*/

	u_int8_t			*ver_field;
	size_t				ver_length;
	u_int8_t			*sig_field;
	size_t				sig_length;
	int					ret_val;

	if (the_set==NULL||the_key==NULL) return SR_V_INTERNAL_ERROR;

	if ((ret_val=res_v_make_field (&ver_field, &ver_length, the_set, the_sig,
										is_a_wildcard)) != SR_V_UNSET)
		return ret_val;

	/* Find the signature - no memory is malloc'ed for this operation  */

	sig_length = res_v_find_signature (&sig_field, the_sig);

	/* Perform the verification */
 
	ret_val = dst_verify_data (SIG_MODE_ALL, ver_field, ver_length,
										the_key, sig_field, sig_length);

//	ret_val = dst_verify_data (SIG_MODE_ALL, the_key, NULL, ver_field, ver_length,
//										sig_field, sig_length);


	(*it_passes) = (ret_val==0);
/*
printf ("\nVerifying this field:\n");
print_hex_field (ver_field,ver_length,21,"VER: ");
printf ("\nThis is the supposed signature:\n");
print_hex_field (sig_field,sig_length,21,"SIG: ");
printf ("Result of verification is %s\n", ret_val==0?"GOOD":"BAD");
*/
	FREE (ver_field);
	return SR_V_UNSET;
}

#define WHERE_LABELS_IS	3
int res_v_check_label_count (
							struct rrset_rec	*the_set,
							struct rr_rec		*the_sig,
							int					*is_a_wildcard)
{
	u_int8_t owner_labels = wire_name_labels (the_set->rrs_name_n);
	u_int8_t sig_labels = the_sig->rr_rdata[WHERE_LABELS_IS] + 1;

	if (sig_labels > owner_labels) return SR_V_PROCESS_ERROR;

	*is_a_wildcard = (sig_labels < owner_labels);

	return SR_V_UNSET;
}

int res_v_set_ans_kind (	struct qname_chain	*q_names_n,
							const u_int16_t		q_type_h,
							const u_int16_t		q_class_h,
							struct rrset_rec	*the_set)
{
	/* Answer is a Referral if... */

		/* Referals won't make it this far, therr handled in digest_response */

	/* Answer is a NACK_NXT if... */

	if (the_set->rrs_type_h == ns_t_nxt)
	{
		if (namecmp(the_set->rrs_name_n, q_names_n->qc_name_n)==0 &&
							(q_type_h == ns_t_any || q_type_h == ns_t_nxt))
			/* We asked for it */
			the_set->rrs_ans_kind = SR_ANS_STRAIGHT;
		else
			the_set->rrs_ans_kind = SR_ANS_NACK_NXT;

		return SR_V_UNSET;
	}

	/* Answer is a NACK_SOA if... */

	if (the_set->rrs_type_h == ns_t_soa)
	{
		if (namecmp(the_set->rrs_name_n, q_names_n->qc_name_n)==0 &&
							(q_type_h == ns_t_any || q_type_h == ns_t_soa))
			/* We asked for it */
			the_set->rrs_ans_kind = SR_ANS_STRAIGHT;
		else
			the_set->rrs_ans_kind = SR_ANS_NACK_SOA;

		return SR_V_UNSET;
	}

	/* Answer is a CNAME if... */

	if (the_set->rrs_type_h == ns_t_cname)
	{
		if (namecmp(the_set->rrs_name_n, q_names_n->qc_name_n)==0 &&
							(q_type_h == ns_t_any || q_type_h == ns_t_cname))
			/* We asked for it */
			the_set->rrs_ans_kind = SR_ANS_STRAIGHT;
		else
			the_set->rrs_ans_kind = SR_ANS_CNAME;

		return SR_V_UNSET;
	}

	/* Answer is an ANSWER if... */
	if (namecmp(the_set->rrs_name_n, q_names_n->qc_name_n)==0 &&
					(q_type_h==ns_t_any || q_type_h==the_set->rrs_type_h))
	{
		/* We asked for it */
		the_set->rrs_ans_kind = SR_ANS_STRAIGHT;
		return SR_V_UNSET;
	}

	the_set->rrs_ans_kind = SR_ANS_UNSET;

	return SR_V_PROCESS_ERROR;
}
#define	TOP_OF_QNAMES	0
#define	MID_OF_QNAMES	1
#define	NOT_IN_QNAMES	2

int res_v_name_in_q_names (
							struct qname_chain	*q_names_n,
							struct rrset_rec	*the_set)
{
	struct qname_chain *temp_qc;

	if (q_names_n==NULL) return NOT_IN_QNAMES;

	if (namecmp(the_set->rrs_name_n, q_names_n->qc_name_n)==0)
		return TOP_OF_QNAMES;

	temp_qc = q_names_n->qc_next;

	while (temp_qc)
	{
		if (namecmp(the_set->rrs_name_n, temp_qc->qc_name_n)==0)
			return MID_OF_QNAMES;
		temp_qc = temp_qc->qc_next;
	}

	return NOT_IN_QNAMES;
}

int res_v_fails_to_answer_query(
							struct qname_chain	*q_names_n,
							const u_int16_t		q_type_h,
							const u_int16_t		q_class_h,
							struct rrset_rec	*the_set)
{
	int name_present = res_v_name_in_q_names (q_names_n, the_set);
	int	type_match = the_set->rrs_type_h==q_type_h || q_type_h==ns_t_any;
	int class_match = the_set->rrs_class_h==q_class_h || q_class_h==ns_c_any;
	int data_present = the_set->rrs_data != NULL;

	if (the_set->rrs_status != SR_DATA_UNCHECKED) return FALSE;
	if (!data_present) return FALSE;

	if (
		!class_match ||
		(!type_match && the_set->rrs_ans_kind == SR_ANS_STRAIGHT) ||
		(type_match && the_set->rrs_ans_kind != SR_ANS_STRAIGHT) ||
		(name_present!=TOP_OF_QNAMES && type_match &&
						the_set->rrs_ans_kind == SR_ANS_STRAIGHT) ||
		(name_present!=MID_OF_QNAMES && !type_match &&
						the_set->rrs_ans_kind == SR_ANS_CNAME) ||
		(name_present==MID_OF_QNAMES && !type_match &&
			(the_set->rrs_ans_kind == SR_ANS_NACK_NXT ||
				the_set->rrs_ans_kind == SR_ANS_NACK_NXT))
		)
		{
			the_set->rrs_status = SR_WRONG;
			return TRUE;
		}

	return FALSE;
}

int res_v_NXT_is_wrong_answer (
							struct qname_chain	*q_names_n,
							const u_int16_t		q_type_h,
							const u_int16_t		q_class_h,
							struct rrset_rec	*the_set)
{
	struct rrset_rec	query_set;
	struct known_domain *kd;
	int					src_auth;
	int					nxt_bit_field;

	if (the_set->rrs_ans_kind != SR_ANS_NACK_NXT) return FALSE;

	/*	
		Signer name doesn't matter here, incorrectly signed ones will caught
		later (in "the matrix").
	*/

	if (namecmp(the_set->rrs_name_n, q_names_n->qc_name_n)==0)
	{
		/* NXT owner = query name & q_type not in list */
		nxt_bit_field = wire_name_length (the_set->rrs_data->rr_rdata);

		if (ISSET((&(the_set->rrs_data->rr_rdata[nxt_bit_field])), q_type_h))
		{
			the_set->rrs_status = SR_WRONG;
			return TRUE;
		}
		else
			return FALSE;
	}
	else
	{
		/*	query name is between NXT owner and next name or
			query name is after NXT owner and next name is the zone */

		if (namecmp(the_set->rrs_name_n, q_names_n->qc_name_n) > 0)
		{
			the_set->rrs_status = SR_WRONG;
			return TRUE;
		}

		if (namecmp(q_names_n->qc_name_n, the_set->rrs_name_n) < 0)
			return FALSE;

		/* Now, need to check the zone */

		memset (&query_set, 0, sizeof (struct rrset_rec));
		query_set.rrs_name_n = q_names_n->qc_name_n;
		query_set.rrs_type_h = q_type_h;
		query_set.rrs_class_h = q_class_h;

		/* What zone is the zone of what I'm seeking? */
		if (res_zi_determine_domain (&kd, &query_set, &src_auth)!=SR_ZI_UNSET)
			return FALSE;

		if (kd && namecmp(the_set->rrs_name_n, kd->kd_name_n))
		{
			the_set->rrs_status = SR_WRONG;
			return TRUE;
		}
		return FALSE;
	}
}

int res_v_SOA_is_wrong_answer (
							struct qname_chain	*q_names_n,
							const u_int16_t		q_type_h,
							const u_int16_t		q_class_h,
							struct rrset_rec	*the_set)
{
	struct rrset_rec	query_set;
	struct known_domain *kd;
	int					src_auth;

	if (the_set->rrs_ans_kind != SR_ANS_NACK_SOA) return FALSE;

	memset (&query_set, 0, sizeof (struct rrset_rec));
	query_set.rrs_name_n = q_names_n->qc_name_n;
	query_set.rrs_type_h = q_type_h;
	query_set.rrs_class_h = q_class_h;

	/* What zone is the zone of what I'm seeking? */
	if (res_zi_determine_domain (&kd, &query_set, &src_auth)!=SR_ZI_UNSET)
		return FALSE;

	/* kd returns the domain, not necessarily a zone */
	while (kd && !SR_ZI_IS_DOMAIN_A_ZONE(kd)) kd = kd->kd_parent_domain;

	/* Is the SOA owned by the zone of the target? */
	if (kd && namecmp (the_set->rrs_name_n, kd->kd_name_n))
	{
		the_set->rrs_status = SR_WRONG;
		return TRUE;
	}

	return FALSE;
}

int res_v_no_local_keys_configured (struct rrset_rec *the_set)
{
	if (res_zi_key_count()==0)
	{
		the_set->rrs_status = SR_NO_LOCAL_KEYS;
		return TRUE;
	}

	return FALSE;
}

int res_v_looking_for_sigs (struct rrset_rec *the_set, const u_int16_t q_type_h)
{
	if (q_type_h==46)
	//if (q_type_h==ns_t_sig)
	{
		the_set->rrs_status = SR_BARE_SIG;
		return TRUE;
	}
	return FALSE;
}

int res_v_missing_data (struct rrset_rec *the_set)
{
	if (the_set->rrs_data==NULL)
	{
		the_set->rrs_status = SR_SIG_ONLY;
		return TRUE;
	}
	return FALSE;
}

#include <time.h>

int res_v_sig_times_bad (struct rr_rec *a_sig)
{
	time_t		current_time = time (0);
	u_int32_t	time_n;
	time_t		time_signed;
	time_t		time_expired;
	int			time_index;

	time_index = TTL+sizeof(u_int32_t);

	memcpy (&time_n, &a_sig->rr_rdata[time_index], sizeof(u_int32_t));
	time_expired = (time_t) ntohl (time_n);

	time_index += sizeof(u_int32_t);
	memcpy (&time_n, &a_sig->rr_rdata[time_index], sizeof(u_int32_t));
	time_signed = (time_t) ntohl (time_n);

	if(time_signed <= current_time && current_time <= time_expired)
		return FALSE;

	if (time_expired < time_signed &&
			(time_expired <= current_time || current_time <= time_signed))
		return FALSE;

	return TRUE;
}

void res_v_remove_signature (struct rrset_rec *the_set,
							struct rr_rec **the_sig,
							struct rr_rec *the_trailer)
{
	if (the_trailer == NULL)
	{
		the_set->rrs_sig = (*the_sig)->rr_next;
		(*the_sig)->rr_next = NULL;
		res_sq_free_rr_recs (the_sig);
		*the_sig = the_set->rrs_sig;
	}
	else
	{
		the_trailer->rr_next = (*the_sig)->rr_next;
		(*the_sig)->rr_next = NULL;
		res_sq_free_rr_recs (the_sig);
		*the_sig = the_trailer->rr_next;
	}
}

struct known_domain *res_v_determine_zone (u_int8_t *name_n)
{
	struct rrset_rec	ficticious;
	struct known_domain	*kd;

	memset (&ficticious, 0, sizeof (struct rrset_rec));

	ficticious.rrs_name_n = name_n;
	ficticious.rrs_type_h = ns_t_any;

	if((kd = res_zi_determine_root (&ficticious))== NULL) return NULL;

	while (kd && !SR_ZI_IS_DOMAIN_A_ZONE(kd)) kd = kd->kd_parent_domain;

	return kd;
}

struct known_domain *res_v_parent_zone_of (struct known_domain *kd)
{
	struct known_domain	*kd_parent = kd->kd_parent_domain;

	while (kd_parent && !SR_ZI_IS_DOMAIN_A_ZONE(kd_parent))
		kd_parent = kd_parent->kd_parent_domain;

	return kd_parent;
}

int res_v_name_matches (u_int8_t *name1_n, u_int8_t *name2_n)
{
	/* This assumes that the names are not attached to key sets */
	u_int8_t			*wildcard = NULL;
	u_int8_t			*non_wildcard = NULL;
	struct known_domain	*wc_kd;
	struct known_domain *nwc_kd;
	int					wc_index = 2;
	int					nwc_index;
	int					wc_length;
	int					nwc_length;

	if (name1_n == NULL || name2_n == NULL) return FALSE;

	if (namecmp(name1_n, name2_n)==0) return TRUE;

	if (name1_n[0] == 0x01 && name1_n[1] == '*')
	{
		wildcard = name1_n;
		non_wildcard = name2_n;
	}
	else if (name2_n[0] == 0x01 && name2_n[1] == '*')
	{
		wildcard = name2_n;
		non_wildcard = name1_n;
	}

	if (wildcard == NULL) return FALSE;

	wc_length = wire_name_length (&wildcard[wc_index]);
	nwc_length = wire_name_length (non_wildcard);
	nwc_index = nwc_length - wc_length;

	if (namecmp (&wildcard[wc_index], &non_wildcard[nwc_index])!=0)
		return FALSE;

	wc_kd = res_v_determine_zone (wildcard);
	nwc_kd = res_v_determine_zone (non_wildcard);

	return wc_kd == nwc_kd;
}

int res_v_can_sign (struct rrset_rec	*the_set,
					u_int8_t			*signby_name_n, 
					int					key_ability)
{
	// SURESH -- change this logic
	return TRUE;

#define DATA_CAT_KEY_PS	0
#define DATA_CAT_KEY_Z	1
#define DATA_CAT_NXT_U	2
#define DATA_CAT_NXT_L	0
#define DATA_CAT_NS_SOA	0
#define DATA_CAT_OTHER	3

#define SIG_CAT_SIGN_ONLY	0
#define SIG_CAT_SAME_ZONE	1
#define SIG_CAT_PARENT		2
#define SIG_CAT_CHILD		3 /* Not implemented here */
#define SIG_CAT_CANT_SIGN	4

	/*
		These are the following legal signing combinations:
			DATA_CAT	SIG_CAT
				3			0
				0			1
				1			2
				2			2
				1			3
	*/

	int		data_cat;
	int		sig_cat;

	/* Determing the data category */

	if (the_set->rrs_type_h == 48)
	//if (the_set->rrs_type_h == ns_t_key)
	{
		/* See if there is a zone key in the mix */
		struct rr_rec	*rr = the_set->rrs_data;
		int				zone_key = FALSE;

		while (rr && zone_key==FALSE)
		{
			zone_key = (rr->rr_rdata[0] & 0x01 && !(rr->rr_rdata[0] & 0xC0));
			rr = rr->rr_next;
		}

		data_cat = zone_key ? DATA_CAT_KEY_Z : DATA_CAT_KEY_PS;
	}
	else if (the_set->rrs_type_h == ns_t_nxt)
	{
		int	bit_field_index = wire_name_length (the_set->rrs_data->rr_rdata);

		/*
			NOTE: The definition of upper/lower NXT conflicts w/res_zone_info's.
			The two are different.  That's just the way the ball bounces.

			Hey, I just changed my mind as the code developed...
		*/
		if  (
			ISSET((&(the_set->rrs_data->rr_rdata)[bit_field_index]), ns_t_ns)
			&&
			!ISSET((&(the_set->rrs_data->rr_rdata)[bit_field_index]), ns_t_soa)
			)
			data_cat = DATA_CAT_NXT_U;
		else
			data_cat = DATA_CAT_NXT_L;
	}
	else if (the_set->rrs_type_h == ns_t_soa || the_set->rrs_type_h == ns_t_ns)
		data_cat = DATA_CAT_NS_SOA;
	else
		data_cat = DATA_CAT_OTHER;


	/* Now, time to determine the signer category. */

	if (key_ability == SR_KM_KEY_IS_SIGNING)
	{
		if (the_set->rrs_type_h == 48 &&
		//if (the_set->rrs_type_h == ns_t_key &&
				res_v_name_matches (the_set->rrs_name_n, signby_name_n))
			sig_cat = SIG_CAT_SIGN_ONLY;
		else
			sig_cat	= SIG_CAT_CANT_SIGN;
	}
	else if (key_ability == SR_KM_KEY_IS_ZONE)
	{
		struct known_domain *key_zone;

		if (the_set->rrs_type_h == 48)
		//if (the_set->rrs_type_h == ns_t_key)
		{
			u_int8_t			*key_name_n;

			key_name_n = the_set->rrs_name_n;

			if (key_name_n[0] != '\0')
			{
				(u_int32_t) key_name_n += (key_name_n[0]+1);

				key_zone = res_v_determine_zone (key_name_n);

				if (namecmp (key_zone->kd_name_n, signby_name_n)==0)
					sig_cat = SIG_CAT_PARENT;
				else
					return FALSE;
			}
			else /* No one can sign the root zone's keys */
				return FALSE;
		}
		else
		{
			struct known_domain *owner_zone;
			struct known_domain *signer_zone;

			owner_zone = res_v_determine_zone (the_set->rrs_name_n);
			signer_zone = res_v_determine_zone (signby_name_n);

			if (owner_zone==NULL || signer_zone==NULL)
				return FALSE;

			if (owner_zone == signer_zone)
			{
				if (data_cat == DATA_CAT_NXT_U &&
					namecmp (owner_zone->kd_name_n,the_set->rrs_name_n) !=0)
					sig_cat = SIG_CAT_PARENT;
				else
					sig_cat = SIG_CAT_SAME_ZONE;
			}
			else if (res_v_parent_zone_of (owner_zone)==signer_zone)
				sig_cat = SIG_CAT_PARENT;
			else
				return FALSE;
		}
	}
	else
		return FALSE;

	if ((data_cat == 3 && sig_cat == 0) ||
			(data_cat == 3 && sig_cat == 1) ||
			(data_cat == 0 && sig_cat == 1) ||
			(data_cat == 1 && sig_cat == 2) ||
			(data_cat == 2 && sig_cat == 2) ||
			(data_cat == 1 && sig_cat == 3))
		return TRUE;
	else
		return FALSE;
}

int res_v_set_signature_status (struct rrset_rec *the_set, int *sig_status)
{
	struct rr_rec	*the_sig;
	struct rr_rec	*the_trailer;
	int				failure_noted = FALSE;
	int				success_noted = FALSE;
	u_int8_t		*signby_name_n;
	u_int16_t		signby_footprint_n;
	DST_KEY			*the_key;
	u_int32_t		key_ability;
	int				is_a_wildcard;
	int				passes;
	int				ret_val;

	the_trailer=NULL;
	the_sig=the_set->rrs_sig;
	while (the_sig)
	{
		if (res_v_sig_times_bad (the_sig))
		{
			res_v_remove_signature (the_set, &the_sig, the_trailer);
			continue;
		}

		res_v_identify_key (the_sig, &signby_name_n, &signby_footprint_n);

		if(the_set->rrs_type_h == 48) {
			if(!strcmp(the_set->rrs_name_n, signby_name_n)) {
			u_int16_t fp;
			res_v_identify_tag(the_set->rrs_name_n, the_set->rrs_data, &fp);
			if(signby_footprint_n == htons(fp))
			{
				// we're trying to verify the key using 
				// the sigature created using the same key
				// That would be an infinite loop
				the_sig = the_sig->rr_next;
				continue;
			}
			}
		} 

{
char    debug_name[1024];
char    debug_type[64];
int     dbg_scss;
memset (debug_name,0,1024);
ns_name_ntop(the_set->rrs_name_n,debug_name,1024);
strcpy(debug_type,local_sym_ntop(__p_type_syms,the_set->rrs_type_h,&dbg_scss));
printf ("NEED KEY for verification of %s/%s\n", debug_name, debug_type);
}
		if ((ret_val=res_km_retrieve_key(&the_key, &key_ability,
								signby_name_n,signby_footprint_n))!=SR_KM_UNSET)
		{
			/* General meyhem ensues */
			if (ret_val == SR_KM_MEMORY_ERROR)
				return SR_V_MEMORY_ERROR;
	
			return SR_V_INTERNAL_ERROR;
		}

		if (key_ability == SR_KM_KEY_IS_NOT_AVAILABLE ||
								key_ability == SR_KM_KEY_IS_UNUSABLE)
		{
			the_sig = the_sig->rr_next;
printf ("RESULT OF VERIFICATION IS %s\n", "Unable key");
			continue;
		}

		if (res_v_can_sign (the_set, signby_name_n, key_ability)==FALSE)
		{
			the_sig = the_sig->rr_next;
printf ("RESULT OF VERIFICATION IS %s\n", "Cannot sign");
			continue;
		}

		/* Time for the validation step... */

		if (res_v_check_label_count (the_set, the_sig, &is_a_wildcard)
				!= SR_V_UNSET)
		{
			res_v_remove_signature (the_set, &the_sig, the_trailer);
printf ("RESULT OF VERIFICATION IS %s\n", "Bad label count");
			continue;
		}

		if ((ret_val=res_v_do_verify (&passes, the_set, the_sig,
										the_key, is_a_wildcard)) != SR_V_UNSET)
		{
			/* Other problems ensue */
			if (ret_val == SR_KM_MEMORY_ERROR)
				return SR_V_MEMORY_ERROR;
	
			return SR_V_INTERNAL_ERROR;
		}

		if (passes)
		{
			success_noted = TRUE;
			the_sig = the_sig->rr_next;
printf ("RESULT OF VERIFICATION IS %s\n", "GOOD");
			break;
		}
		else
		{
printf ("RESULT OF VERIFICATION IS %s\n", "BAD");
			res_v_remove_signature (the_set, &the_sig, the_trailer);
			failure_noted = TRUE;
			continue;
		}

		/* This is unreachable territory */
	}

	if (success_noted)
		*sig_status = SR_V_SIG_VALIDATED;
	else if (failure_noted)
		*sig_status = SR_V_SIG_FAILED;
	else if (the_set->rrs_sig != NULL)
		*sig_status = SR_V_SIG_IMMATERIAL;
	else
		*sig_status = SR_V_SIG_ABSENT;
	
	return SR_V_UNSET;
}

void res_v_check_sanity_of_CNAMEs (struct rrset_rec *answers)
{
	struct rrset_rec	*a_set;
	int					nxt_count = 0;
	struct rrset_rec	*nxts[2];
	u_int8_t			*nxt_bit_field;
	int					nxt_next_name_length;

	/* Check to make sure all CNAMEs are "correct" */
	a_set = answers;
	while (a_set && a_set->rrs_ans_kind == SR_ANS_CNAME)
	{
		if (a_set->rrs_status == SR_VERIFY_FAILED ||
			a_set->rrs_status == SR_SIG_EXPECTED)
		{
			/* We have a break in the chain */
			res_sq_free_rrset_recs (&a_set->rrs_next);
		}
		a_set = a_set->rrs_next;
	}

	/* Remove all data from bad answers */
	a_set = answers;
	while (a_set)
	{
		if (a_set->rrs_status == SR_VERIFY_FAILED ||
			a_set->rrs_status == SR_SIG_EXPECTED)
		{
			/* We have a break in the chain */
			res_sq_free_rr_recs (&a_set->rrs_data);
			res_sq_free_rr_recs (&a_set->rrs_sig);
		}
		a_set = a_set->rrs_next;
	}

	/* Check to make sure all NXT's needed are received */
	a_set = answers;
	while (a_set)
	{
		if (a_set->rrs_type_h == ns_t_nxt &&
			a_set->rrs_ans_kind == SR_ANS_STRAIGHT &&
			a_set->rrs_data &&
			a_set->rrs_data->rr_rdata)
		{
			if (nxt_count == 2)
			{
				nxts[0]->rrs_status = SR_EXTRANEOUS_NXT;
				nxts[1]->rrs_status = SR_EXTRANEOUS_NXT;
				a_set->rrs_status = SR_EXTRANEOUS_NXT;
			}
			else if (nxt_count > 2)
				a_set->rrs_status = SR_EXTRANEOUS_NXT;
			else
				nxts[nxt_count] = a_set;

			nxt_count++;
		}
		a_set = a_set->rrs_next;
	}

	if (nxt_count == 1)
	{
		nxt_next_name_length = wire_name_length(nxts[0]->rrs_data->rr_rdata);
		nxt_bit_field = &(nxts[0]->rrs_data->rr_rdata[nxt_next_name_length]);
		if (ISSET(nxt_bit_field,ns_t_ns))
			nxts[0]->rrs_status = SR_MISSING_OTHER_NXT;
	}
}

void res_v_adjust_status_value (struct rrset_rec *the_set)
{
	if (the_set->rrs_status == SR_VERIFIED ||
			the_set->rrs_status == SR_TSIG_PROTECTED ||
			the_set->rrs_status == SR_UNVERIFIED ||
			the_set->rrs_status == SR_NO_LOCAL_KEYS ||
			the_set->rrs_status == SR_WRONG ||
			the_set->rrs_status == SR_VERIFY_FAILED ||
			the_set->rrs_status == SR_SIG_EXPECTED ||
			the_set->rrs_status == SR_UNSIGNED_SURE ||
			the_set->rrs_status == SR_UNSIGNED_UNSURE)
		the_set->rrs_status += the_set->rrs_ans_kind;
}

void res_v_adjust_status_values (struct rrset_rec *answers)
{
	struct rrset_rec	*the_set;
	for (the_set = answers; the_set; the_set = the_set->rrs_next)
		res_v_adjust_status_value (the_set);
}

int res_v_verify_answers (	u_int32_t			dont_check,
							struct qname_chain	*q_names_n,
							const u_int16_t		q_type_h,
							const u_int16_t		q_class_h,
							struct rrset_rec	*answers)
{
	struct rrset_rec	*the_set;
	int					ret_val;
	int					sig_status;
	int					sec_expected;

	for (the_set = answers; the_set; the_set = the_set->rrs_next)
	{
		if (the_set->rrs_status==SR_EMPTY_NXDOMAIN) continue;

		if (the_set->rrs_status==SR_DATA_UNCHECKED ||
				the_set->rrs_status==SR_TSIG_PROTECTED)
		{
			if (res_v_set_ans_kind (q_names_n, q_type_h, q_class_h, the_set)
									== SR_V_PROCESS_ERROR)
			{
				the_set->rrs_status = SR_UNSET;
				return SR_V_UNSET;
			}
		}
		else
			continue;

		if (the_set->rrs_status==SR_TSIG_PROTECTED) continue;

		if (dont_check) { the_set->rrs_status = SR_UNVERIFIED; continue; }

		/* Does this set relate to the question asked? */
		if (res_v_fails_to_answer_query(q_names_n,q_type_h,q_class_h,the_set))
			continue;

		/* Is this response an (wrong) nack - NXT or SOA? */
		if (res_v_NXT_is_wrong_answer (q_names_n,q_type_h,q_class_h,the_set))
			continue;

		if (res_v_SOA_is_wrong_answer (q_names_n,q_type_h,q_class_h,the_set))
			continue;

		if (res_v_no_local_keys_configured (the_set)) continue;

		if (res_v_looking_for_sigs (the_set, q_type_h))
			continue;
		else if (res_v_missing_data (the_set))
			continue;

		/*
			Now, we've arrived to the point where a set may be one of:
				1) Supposed to be signed
				2) Supposed to be unsigned
				3) I can't tell - either experimental or an unsec delegation
			The signatures (collectively) of a sig are one of:
				1) Absent (none available)
				2) Immaterial (no DNSSEC signing key generated ones)
				3) Validated (A DNSSEC signing key validate them)
				4) Failed (All DNSSEC signing key(s) failed to validate)

		The 3x4 matrix becomes:

            Expectation=> SIGNED            MAYBE           UNSIGNED
            Status
              \/
            Validated     Verified          Verified        --------
            Failed        Failed            Failed          --------
            Immaterial    Missing Signature Unsigned Unsure Unsigned Sure
            Absent        Missing Signature Unsigned Unsure Unsigned Sure

        The "----" cases are impossible - a set is determined to be unsigned
        if there is no key available for it, in that case, no signature
        can be tested - so a result of valid or failed cannot be reached.

		*/

		if ((ret_val=res_zi_set_security_expectation (the_set, &sec_expected))
			!= SR_ZI_UNSET)
		{ /* Figure out what is needed */ }

		if (sec_expected==SR_ZI_SET_ISNT_SIGNED)
		{ the_set->rrs_status = SR_UNSIGNED_SURE; continue; }

		if ((ret_val=res_v_set_signature_status (the_set, &sig_status))
			!= SR_ZI_UNSET)
		{ /* Figure out what is needed */ }

		if (sec_expected==SR_ZI_SET_IS_SIGNED &&
			(sig_status==SR_V_SIG_ABSENT || sig_status==SR_V_SIG_IMMATERIAL))
		{ the_set->rrs_status = SR_SIG_EXPECTED; continue; }
		else if (sig_status==SR_V_SIG_FAILED)
		{ the_set->rrs_status = SR_VERIFY_FAILED; continue; }
		else if (sig_status==SR_V_SIG_VALIDATED)
		{ the_set->rrs_status = SR_VERIFIED; continue; }
		else
		{ the_set->rrs_status = SR_UNSIGNED_UNSURE; continue; }
	}

	/* What about the sanity of wildcards and NXTs? */

	/* Make sure all of the CNAMEs were validated */
	res_v_check_sanity_of_CNAMEs (answers);

	/* Adjust the status values to reflect the kind of data too */
	res_v_adjust_status_values (answers);

	return SR_V_UNSET;
}

void res_v_free_qname_chain (struct qname_chain **qnames)
{
	if (qnames==NULL || (*qnames)==NULL) return;

	if ((*qnames)->qc_next)
		res_v_free_qname_chain (&((*qnames)->qc_next));

	FREE (*qnames);
	(*qnames) = NULL;
}

int res_v_add_to_qname_chain (	struct qname_chain	**qnames,
								const u_int8_t		*name_n)
{
	struct qname_chain *temp;

	temp = (struct qname_chain *) MALLOC (sizeof (struct qname_chain));

	if (temp==NULL) return SR_V_MEMORY_ERROR;

	memcpy (temp->qc_name_n, name_n, wire_name_length(name_n));

	temp->qc_next = *qnames;
	*qnames = temp;

	return SR_V_UNSET;
}

int res_v_verify_key_set (struct rrset_rec	*the_set)
{
	int					ret_val;
	int					sig_status;

	if (res_v_no_local_keys_configured (the_set))
	{
		the_set->rrs_status = SR_NO_LOCAL_KEYS_ANSWER;
		return SR_V_UNSET;
	}

	if ((ret_val=res_v_set_signature_status (the_set, &sig_status))
			!= SR_V_UNSET)
		return ret_val;

	if ((sig_status==SR_V_SIG_ABSENT || sig_status==SR_V_SIG_IMMATERIAL))
		the_set->rrs_status = SR_SIG_EXPECTED_ANSWER;
	else if (sig_status==SR_V_SIG_FAILED)
		the_set->rrs_status = SR_VERIFY_FAILED_ANSWER;
	else if (sig_status==SR_V_SIG_VALIDATED)
		the_set->rrs_status = SR_VERIFIED_ANSWER;

	return SR_V_UNSET;
}

int res_v_verify_an_answer (struct rrset_rec *a_set, struct known_domain *kd)
{
	int					ret_val;
	int					sig_status;

	a_set->rrs_ans_kind = SR_ANS_STRAIGHT;

	if (res_v_no_local_keys_configured (a_set))
	{
		res_v_adjust_status_values (a_set);
		return SR_V_UNSET;
	}

	if (kd->kd_security==SR_ZI_SET_ISNT_SIGNED)
	{
		a_set->rrs_status = SR_UNSIGNED_SURE;
		res_v_adjust_status_values (a_set);
		return SR_V_UNSET;
	}

	if ((ret_val=res_v_set_signature_status(a_set,&sig_status)) != SR_V_UNSET)
	{
		return ret_val;
	}

	if (kd->kd_security==SR_ZI_SET_IS_SIGNED &&
			(sig_status==SR_V_SIG_ABSENT || sig_status==SR_V_SIG_IMMATERIAL))
		a_set->rrs_status = SR_SIG_EXPECTED;
	else if (sig_status==SR_V_SIG_FAILED)
		a_set->rrs_status = SR_VERIFY_FAILED;
	else if (sig_status==SR_V_SIG_VALIDATED)
		a_set->rrs_status = SR_VERIFIED;
	else
		a_set->rrs_status = SR_UNSIGNED_UNSURE;

	/* Adjust the status values to reflect the kind of data too */
	res_v_adjust_status_value (a_set);

	return SR_V_UNSET;
}

struct key_chain *res_v_select_key(	struct key_chain	*the_keys,
									u_int16_t			s_foot_n)
{
	/*
		I've decided not to match based on name because -
			if the keys are filled given a name, it won't matter
			if the keys are given already in the chain, there's no
				guarantee that the naming scheme is DNS.

		But every key has a footprint native to it.
	*/
	struct key_chain	*next_one;

	if (the_keys==NULL) return NULL;

	next_one = the_keys->kc_next;

	while (next_one)
		if (next_one->kc_key->dk_id == ntohs(s_foot_n))
			return next_one;
		else
			next_one = next_one->kc_next;

	return next_one;
}

int res_v_verify_with_chain (int				*result,
							struct rrset_rec	*set,
							u_int8_t			*the_name_n,
							int					name_specified,
							struct key_chain	*the_keys,
							int					delete_keys)
{
	struct rr_rec		*sig;
	struct rr_rec		*trailer;
	u_int8_t			*s_name_n;
	u_int16_t			s_foot_n;
	int					is_wcard;
	int					ret_val;
	struct key_chain	*key;
{
struct key_chain	*k = the_keys;
while (k)
{
printf ("Key: %s, footprint: %5d\n",k->kc_key->dk_key_name,k->kc_key->dk_id);
k = k->kc_next;
}
res_sq_print_answer_list(set, "-", FALSE);
}
	*result = FALSE;

	trailer=NULL;
	sig=set->rrs_sig;
	while (sig && (*result)==FALSE)
	{
		/* Always remove a time-bad signature */

		if (res_v_sig_times_bad (sig))
		{
			res_v_remove_signature (set, &sig, trailer);
			continue;
		}

		/* Select the key from the chain for this signature */

		res_v_identify_key (sig, &s_name_n, &s_foot_n);

		if (name_specified && namecmp(the_name_n,s_name_n)==0)
		{
			sig = sig->rr_next;
			continue;
		}

		key=res_v_select_key(the_keys,s_foot_n);

		while (key && (*result)==FALSE)
		{
			while (key && key->kc_key->dk_id != ntohs(s_foot_n))
				key=res_v_select_key(key,s_foot_n);

			if (key==NULL) break;

			if (res_v_check_label_count(set,sig,&is_wcard)!=SR_V_UNSET)
			{
				res_v_remove_signature (set, &sig, trailer);
				key = NULL; /* Force trying of next signature */
			}

			if((ret_val=res_v_do_verify(result, set,sig, key->kc_key, is_wcard))
																!= SR_V_UNSET)
			{
				if (ret_val == SR_KM_MEMORY_ERROR) return SR_V_MEMORY_ERROR;
				return SR_V_INTERNAL_ERROR;
			}

			if (*result == FALSE) key=res_v_select_key(key,s_foot_n);
		}

		if (*result==FALSE) sig = sig->rr_next;
	}

	if (delete_keys)
	{
		res_sq_free_key_chain (&the_keys);
		res_km_cleanup();
		res_zi_cleanup();
	}

	return SR_V_UNSET;
}

int res_v_does_key_verify (	int					*result,
							struct rrset_rec	*set, 
							char				*name_h,
							u_int8_t			*name_n,
							u_int16_t			*foot_h,
							u_int16_t			*foot_n,
							struct key_chain	*keys)
{
	u_int8_t			the_name_n[MAXDNAME];
	int					name_specified;
	u_int16_t			the_foot_n;
	int					foot_specified;
	struct key_chain	*the_keys;
	int					delete_keys; /* False if keys are passed in */
	int					ret_val;
	int					first_byte = 0;

	/*
		See what was passed in and set up the "the_*" variables and the
		associated flags
	*/

	if (set == NULL || result == NULL)
		return SR_V_INTERNAL_ERROR;

	if (name_h != NULL || name_n != NULL)
	{
		name_specified = TRUE;
		the_keys = NULL;
		delete_keys = TRUE;

		if (name_h != NULL)
		{
			if (ns_name_pton (name_h, the_name_n, MAXDNAME) == -1)
				return SR_V_INTERNAL_ERROR;
		}
		else
		{
			memcpy (the_name_n, name_n, wire_name_length (name_n));
		}
		res_v_lower_name (the_name_n, &first_byte);

		if (foot_h != NULL || foot_n != NULL)
		{
			foot_specified = TRUE;
			if (foot_h != NULL)
				the_foot_n = htons (*foot_h);
			else
				the_foot_n = *foot_n;
		}
		else
			foot_specified = FALSE;

		if ((ret_val=res_km_fill_chain (&the_keys, the_name_n,
							foot_specified?&the_foot_n:NULL)) != SR_KM_UNSET)
		{
			if (ret_val==SR_KM_MEMORY_ERROR)
				return SR_V_MEMORY_ERROR;
			else
				return SR_V_INTERNAL_ERROR;
		}
	}
	else if (keys != NULL)
	{
		name_specified = FALSE;
		foot_specified = FALSE;
		the_keys = keys;
		delete_keys = FALSE;
	}
	else
	{
		*result = (set->rrs_sig == NULL);
		return SR_V_UNSET;
	}

	return res_v_verify_with_chain (result, set, the_name_n, name_specified,
										the_keys, delete_keys);
}

int res_v_first_name (struct qname_chain *qnames, const u_int8_t *name_n)
{
	struct qname_chain	*qc;

	if (qnames == NULL || name_n==NULL) return FALSE;

	qc = qnames;
	while (qc != NULL && namecmp(qc->qc_name_n,name_n)!=0)
		qc = qc->qc_next;

	return (qc!=NULL && qc->qc_next==NULL);
}
