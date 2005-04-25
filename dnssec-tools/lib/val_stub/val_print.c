#include <stdio.h>
#include <resolv.h>
#include <resolver.h>
#include <ctype.h>
#include <strings.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "val_print.h"
#include "val_cache.h"
#include "val_errors.h"
#include "val_log.h"

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
	val_log("    rrs_status  = %s [%d]\n", p_val_error(rrset->rrs_status), rrset->rrs_status);

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
    PRINTS("  error_message   = ", dinfo->di_error_message);

    val_log("  qnames =\n");
    qc = dinfo->di_qnames;
    while (qc) {
	val_log("    0x");
	for (i=0; i<MAXDNAME; i++) {
	    val_log("%02x", qc->qc_name_n[i]);
	    if (qc->qc_name_n[i] == 0x00) {
		break;
	    }
	}
	val_log("\n");
	val_log("      ");
	for (i=0; i<MAXDNAME; i++) {
	    if (isprint(qc->qc_name_n[i])) {
		val_log(" %c", qc->qc_name_n[i]);
	    }
	    else {
		val_log("  ");
	    }
	    if (qc->qc_name_n[i] == 0x00) {
		break;
	    }
	}
	val_log("\n");
	qc = qc->qc_next;
    }

    val_log("  rrset =\n");
    dump_rrset(dinfo->di_rrset);
}

void dump_val_context (struct val_context *context) {
	struct rrset_rec *cached_info;

    if (!context) {
	val_log("domain_info: NULL\n");
	return;
    }

    val_log ("domain_info:\n");
    if (NULL != (cached_info = get_cached_zones())) {
	val_log("  learned_zones =\n");
	dump_rrset(cached_info);
    }
    else {
	val_log("  learned_zones = NULL\n");
    }

    if (NULL != (cached_info = get_cached_keys())) {
	val_log("  learned_keys =\n");
	dump_rrset(cached_info);
    }
    else {
	val_log("  learned_keys = NULL\n");
    }

    if (NULL != (cached_info = get_cached_ds())) {
	val_log("  learned_ds =\n");
	dump_rrset(cached_info);
    }
    else {
	val_log("  learned_ds = NULL\n");
    }
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
    if (rdata) {
	if (!prefix) prefix = "";
	val_log("%sType Covered         = %d\n", prefix, rdata->type_covered);
	val_log("%sAlgorithm            = %d", prefix, rdata->algorithm);
	val_print_algorithm(rdata->algorithm);
	val_log("%sLabels               = %d\n", prefix, rdata->labels);
	val_log("%sOriginal TTL         = %d\n", prefix, rdata->orig_ttl);
	val_log("%sSignature Expiration = %s",   prefix, ctime((const time_t *)(&(rdata->sig_expr))));
	val_log("%sSignature Inception  = %s",   prefix, ctime((const time_t *)(&(rdata->sig_incp))));
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
