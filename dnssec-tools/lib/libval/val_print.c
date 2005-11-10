
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#include <stdio.h>
#include <resolv.h>
#include <ctype.h>
#include <strings.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <resolver.h>
#include <validator.h>
#include "val_print.h"
#include "val_cache.h"
#include "val_log.h"
#include "val_support.h"

#define PRINTS(msg,var) if (var) { \
                            val_log("%s%s\n", msg, var); \
                        } \
                        else { \
                            val_log("%sNULL\n", msg); \
                        }
#define PRINTX(msg,arr,len) {\
            int i; \
            val_log("%s0x",msg); \
	    for (i=0; i<len; i++) { \
		val_log("%02x", arr[i]); \
	    } \
	    val_log("\n"); \
}

void dump_rrset(struct rrset_rec *rrset)
{
    while (rrset) {
	struct rr_rec *rr;
	char name[MAXDNAME];

	bzero(name,MAXDNAME);
	if (rrset->rrs_name_n) {
	    ns_name_ntop(rrset->rrs_name_n, name, MAXDNAME);
	}
	PRINTS("    rrs_name    = ", name);

	val_log("    rrs_type    = %s\n", p_type(rrset->rrs_type_h));
	val_log("    rrs_class   = %s\n", p_class(rrset->rrs_class_h));
	val_log("    rrs_ttl     = %d\n", rrset->rrs_ttl_h);
	val_log("    rrs_section = %s\n", p_section(rrset->rrs_section - 1, !ns_o_update));

	val_log("    rrs_data    =\n");
	rr = rrset->rrs_data;
	while (rr) {
	    PRINTX("      ", rr->rr_rdata, rr->rr_rdata_length_h);
	    rr = rr->rr_next;
	}

	val_log("    rrs_sig     =\n");
	rr = rrset->rrs_sig;
	while (rr) {
	    PRINTX("      ", rr->rr_rdata, rr->rr_rdata_length_h);
	    rr = rr->rr_next;
	}

	val_log("\n");
	rrset = rrset->rrs_next;
    }
}

void dump_dinfo(struct domain_info *dinfo)
{
    struct qname_chain *qc;
    int i;

    if (dinfo == NULL) {
	val_log("dinfo = NULL\n");
	return;
    }

    val_log ("domain_info:\n");
    PRINTS("  requested name  = ", dinfo->di_requested_name_h);
    val_log("  requested type  = %s\n", p_type(dinfo->di_requested_type_h));
    val_log("  requested class = %s\n", p_class(dinfo->di_requested_class_h));
    val_log("  resolver error code = %s\n", dinfo->di_res_error);

    val_log("  qnames =\n");
    qc = dinfo->di_qnames;
    while (qc) {
	val_log("    0x");
	for (i=0; i<MAXDNAME; i++) {
	    val_log("%02x", qc->qnc_name_n[i]);
	    if (qc->qnc_name_n[i] == 0x00) {
		break;
	    }
	}
	val_log("\n");
	val_log("      ");
	for (i=0; i<MAXDNAME; i++) {
	    if (isprint(qc->qnc_name_n[i])) {
		val_log(" %c", qc->qnc_name_n[i]);
	    }
	    else {
		val_log("  ");
	    }
	    if (qc->qnc_name_n[i] == 0x00) {
		break;
	    }
	}
	val_log("\n");
	qc = qc->qnc_next;
    }

    val_log("  rrset =\n");
    dump_rrset(dinfo->di_rrset);
}


static void val_print_algorithm (u_int8_t algo)
{

    switch (algo) {
    case   1: val_log(" [RSA/MD5]\n");        break;
    case   2: val_log(" [Diffie-Hellman]\n"); break;
    case   3: val_log(" [DSA/SHA-1]\n");      break;
    case   4: val_log(" [Elliptic Curve]\n"); break;
    case   5: val_log(" [RSA/SHA-1]\n");      break;
    case 252: val_log(" [Indirect]\n");       break;
    case 253: val_log(" [PrivateDNS]\n");     break;
    case 254: val_log(" [PrivateOID]\n");     break;
    case   0:
    case 255: val_log(" [reserved]\n");       break;
    default:  val_log(" [unknown]\n");
    }
}

void val_print_base64(unsigned char * message, int message_len)
{
    BIO *bio, *b64;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_write(bio, message, message_len);
    BIO_flush(bio);
    BIO_free_all(bio);
}

void val_print_rrsig_rdata (const char *prefix, val_rrsig_rdata_t *rdata)
{
	char ctime_buf[1028];
    if (rdata) {
	if (!prefix) prefix = "";
	val_log("%sType Covered         = %d\n", prefix, rdata->type_covered);
	val_log("%sAlgorithm            = %d", prefix, rdata->algorithm);
	val_print_algorithm(rdata->algorithm);
	val_log("%sLabels               = %d\n", prefix, rdata->labels);
	val_log("%sOriginal TTL         = %d\n", prefix, rdata->orig_ttl);
	val_log("%sSignature Expiration = %s",   prefix, ctime_r((const time_t *)(&(rdata->sig_expr)), ctime_buf));
	val_log("%sSignature Inception  = %s",   prefix, ctime_r((const time_t *)(&(rdata->sig_incp)), ctime_buf));
	val_log("%sKey Tag              = %d ", prefix, rdata->key_tag);
	val_log("[0x %04x]\n", rdata->key_tag);
	val_log("%sSigner's Name        = %s\n", prefix, rdata->signer_name);
	val_log("%sSignature            = ", prefix);
	if (log_level > 0) {
	    val_print_base64(rdata->signature, rdata->signature_len);
	}
    }
}

void val_print_dnskey_rdata (const char *prefix, val_dnskey_rdata_t *rdata)
{
    if (rdata) {
	if (!prefix) prefix = "";
	val_log("%sFlags                = %d\n", prefix, rdata->flags);
	val_log("%sProtocol             = %d\n", prefix, rdata->protocol);
	val_log("%sAlgorithm            = %d",   prefix, rdata->algorithm);
	val_print_algorithm(rdata->algorithm);
	val_log("%sKey Tag              = %d", prefix, rdata->key_tag);
	val_log("[0x %04x]\n", rdata->key_tag);
	val_log("%sPublic Key           = ", prefix);
	if (log_level > 0) {
	    val_print_base64(rdata->public_key, rdata->public_key_len);
	}
    }
}

static char *ns_string(struct name_server **server)
{
	if((server == NULL) || (*server == NULL))
		return NULL;

	struct sockaddr_in  *s=(struct sockaddr_in*)(&((*server)->ns_address[0]));
	return inet_ntoa(s->sin_addr);
}

void val_print_assertion_chain(u_char *name_n, u_int16_t class_h, u_int16_t type_h, 
				struct query_chain *queries, struct val_result *results)
{
	char name[MAXDNAME];
	struct val_result *next_result;
	struct query_chain *top_q = NULL;
	char *serv;

	/* Search for the "main" query */
	for (top_q = queries; top_q; top_q=top_q->qc_next) {
		if(!namecmp(top_q->qc_name_n, name_n) &&
			(top_q->qc_class_h == class_h) &&
			(top_q->qc_type_h == type_h))
				break;
	}

	for (next_result = results; next_result; next_result = next_result->next) {
		struct assertion_chain *next_as;
		next_as = next_result->as;

		if (next_as && next_as->ac_data) {
			if(ns_name_ntop(next_as->ac_data->rrs_name_n, name, MAXDNAME-1) != -1) 
				val_log("\tname=%s", name);	
			else
				val_log("\tname=ERR_NAME");
			val_log("\tclass=%s", p_class(next_as->ac_data->rrs_class_h));	
			val_log("\ttype=%s ", p_type(next_as->ac_data->rrs_type_h));	
			val_log("\tfrom-server=%s", 
				((serv = ns_string(&(next_as->ac_data->rrs_respondent_server))) == NULL)?"VAL_CACHE":serv);
			val_log("\tResult=%s : %d\n", p_val_error(next_result->status), next_result->status);

			next_as = next_as->ac_trust;
		}
		else if(top_q != NULL) {
			if(ns_name_ntop(top_q->qc_name_n, name, MAXDNAME-1) != -1) 
				val_log("\tname=%s", name);	
			else
				val_log("\tname=ERR_NAME");
			val_log("\tclass=%s", p_class(top_q->qc_class_h));	
			val_log("\ttype=%s ", p_type(top_q->qc_type_h));	
			if (top_q->qc_respondent_server)
				val_log("\tfrom-server=%s", 
					((serv = ns_string(&(top_q->qc_respondent_server))) == NULL)?"VAL_CACHE":serv);
			val_log("\tResult=%s : %d\n", p_val_error(next_result->status), next_result->status);
		}
		for (next_as = next_result->as; next_as; next_as = next_as->ac_trust) {
			if(ns_name_ntop(next_as->ac_data->rrs_name_n, name, MAXDNAME-1) != -1) 
				val_log("\tname=%s", name);	
			else
				val_log("\tname=ERR_NAME");
			val_log("\tclass=%s", p_class(next_as->ac_data->rrs_class_h));	
			val_log("\ttype=%s ", p_type(next_as->ac_data->rrs_type_h));	
			val_log("\tfrom-server=%s", 
				((serv = ns_string(&(next_as->ac_data->rrs_respondent_server))) == NULL)?"VAL_CACHE":serv);
			val_log("\tstatus=%s : %d\n", p_val_error(next_as->ac_state), next_as->ac_state);	
		}
		val_log("\n");
	}
}

char *p_val_error(int errno)
{
    switch (errno) {
                                                                                                                             
    case NO_ERROR: return "NO_ERROR"; break;
                                                                                                                             
    case NOT_IMPLEMENTED: return "NOT_IMPLEMENTED"; break;
    case OUT_OF_MEMORY: return "OUT_OF_MEMORY"; break;
    case BAD_ARGUMENT: return "BAD_ARGUMENT"; break;
    case INTERNAL_ERROR: return "INTERNAL_ERROR"; break;
    case NO_PERMISSION: return "NO_PERMISSION"; break;
    case RESOURCE_UNAVAILABLE: return "RESOURCE_UNAVAILABLE"; break;
    case CONF_PARSE_ERROR: return "CONF_PARSE_ERROR"; break;
    case NO_POLICY: return "NO_POLICY"; break;
    case NO_SPACE: return "NO_SPACE"; break;
    case UNKNOWN_LOCALE: return "UNKNOWN_LOCALE"; break;
                                                                                                                             
    case DATA_MISSING: return "DATA_MISSING"; break;
    case RRSIG_MISSING: return "RRSIG_MISSING"; break;
    case NO_TRUST_ANCHOR: return "NO_TRUST_ANCHOR"; break;
    case UNTRUSTED_ZONE: return "UNTRUSTED_ZONE"; break;
    case IRRELEVANT_PROOF: return "IRRELEVANT_PROOF"; break;
    case DNSSEC_VERSION_ERROR: return "DNSSEC_VERSION_ERROR"; break;
    case TOO_MANY_LINKS: return "TOO_MANY_LINKS"; break;
    case UNKNOWN_DNSKEY_PROTO: return "UNKNOWN_DNSKEY_PROTO"; break;
    case FLOOD_ATTACK_DETECTED: return "FLOOD_ATTACK_DETECTED"; break;
                                                                                                                             
    case DNSKEY_NOMATCH: return "DNSKEY_NOMATCH"; break;
    case WRONG_LABEL_COUNT: return "WRONG_LABEL_COUNT"; break;
    case SECURITY_LAME: return "SECURITY_LAME"; break;
    case NOT_A_ZONE_KEY: return "NOT_A_ZONE_KEY"; break;
    case RRSIG_NOTYETACTIVE: return "RRSIG_NOTYETACTIVE"; break;
    case RRSIG_EXPIRED: return "RRSIG_EXPIRED"; break;
    case ALGO_NOT_SUPPORTED: return "ALGO_NOT_SUPPORTED"; break;
    case UNKNOWN_ALGO: return "UNKNOWN_ALGO"; break;
    case RRSIG_VERIFIED: return "RRSIG_VERIFIED"; break;
    case RRSIG_VERIFY_FAILED: return "RRSIG_VERIFY_FAILED"; break;
    case NOT_VERIFIED: return "NOT_VERIFIED"; break;
    case KEY_TOO_LARGE: return "KEY_TOO_LARGE"; break;
    case KEY_TOO_SMALL: return "KEY_TOO_SMALL"; break;
    case KEY_NOT_AUTHORIZED: return "KEY_NOT_AUTHORIZED"; break;
    case ALGO_REFUSED: return "ALGO_REFUSED"; break;
    case CLOCK_SKEW: return "CLOCK_SKEW"; break;
    case DUPLICATE_KEYTAG: return "DUPLICATE_KEYTAG"; break;
    case NO_PREFERRED_SEP: return "NO_PREFERRED_SEP"; break;
    case WRONG_RRSIG_OWNER: return "WRONG_RRSIG_OWNER"; break;
    case RRSIG_ALGO_MISMATCH: return "RRSIG_ALGO_MISMATCH"; break;
    case KEYTAG_MISMATCH: return "KEYTAG_MISMATCH"; break;
                                                                                                                             
    case VERIFIED: return "VERIFIED"; break;
    case LOCAL_ANSWER: return "LOCAL_ANSWER"; break;
    case TRUST_KEY: return "TRUST_KEY"; break;
    case TRUST_ZONE: return "TRUST_ZONE"; break;
    case BARE_RRSIG: return "BARE_RRSIG"; break;
    case VALIDATE_SUCCESS: return "VALIDATE_SUCCESS"; break;
                                                                                                                             
    case BOGUS_PROVABLE: return "BOGUS_PROVABLE"; break;
    case BOGUS_UNPROVABLE: return "BOGUS_UNPROVABLE"; break;
    case VALIDATION_ERROR: return "VALIDATION_ERROR"; break;
    case NONEXISTENT_NAME: return "NONEXISTENT_NAME"; break;
    case NONEXISTENT_TYPE: return "NONEXISTENT_TYPE"; break;
    case INCOMPLETE_PROOF: return "INCOMPLETE_PROOF"; break;
    case BOGUS_PROOF: return "BOGUS_PROOF"; break;
    case INDETERMINATE_DS: return "INDETERMINATE_DS"; break;
    case INDETERMINATE_PROOF: return "INDETERMINATE_PROOF"; break;
    case INDETERMINATE_ERROR: return "INDETERMINATE_ERROR"; break;
    case INDETERMINATE_TRUST: return "INDETERMINATE_TRUST"; break;
    case INDETERMINATE_ZONE: return "INDETERMINATE_ZONE"; break;
    /*
    case UNAUTHORIZED_SIGNER: return "UNAUTHORIZED_SIGNER"; break;
    case CONFLICTING_PROOFS: return "CONFLICTING_PROOFS"; break;
    case WAITING: return "WAITING"; break;
    case WAKEUP: return "WAKEUP"; break;
    case OVERREACHING_NSEC: return "OVERREACHING_NSEC"; break;
    case TRUST_ANCHOR_TIMEOUT: return "TRUST_ANCHOR_TIMEOUT"; break;
    case INSUFFICIENT_DATA: return "INSUFFICIENT_DATA"; break;
    case FLOOD_ATTACK_DETECTED: return "FLOOD_ATTACK_DETECTED"; break;
    case DNSSEC_VERSION_ERROR: return "DNSSEC_VERSION_ERROR"; break;
    */
    default:
            if((errno >= DNS_ERROR_BASE) &&
                (errno < DNS_ERROR_LAST))
                return "DNS_ERROR";
            else if (errno < A_LAST_STATE)
                return "UNEVALUATED";
            return "Unknown Error Value";
    }
}
