#include <stdio.h>
#include <resolv.h>
#include <resolver.h>
#include <ctype.h>
#include <strings.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "val_print.h"

#define PRINTS(msg,var) if (var) { \
                            printf("%s%s\n", msg, var); \
                        } \
                        else { \
                            printf("%sNULL\n", msg); \
                        }
#define PRINTX(msg,arr,len) {\
            int i; \
            printf("%s0x",msg); \
	    for (i=0; i<len; i++) { \
		printf("%02x", arr[i]); \
	    } \
	    printf("\n"); \
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

	printf("    rrs_type    = %s\n", p_type(rrset->rrs_type_h));
	printf("    rrs_class   = %s\n", p_class(rrset->rrs_class_h));
	printf("    rrs_ttl     = %d\n", rrset->rrs_ttl_h);
	printf("    rrs_section = %s\n", p_section(rrset->rrs_section - 1, !ns_o_update));
	printf("    rrs_status  = %s [%d]\n", p_val_error(rrset->rrs_status), rrset->rrs_status);

	printf("    rrs_data    =\n");
	rr = rrset->rrs_data;
	while (rr) {
	    PRINTX("      ", rr->rr_rdata, rr->rr_rdata_length_h);
	    rr = rr->rr_next;
	}

	printf("    rrs_sig     =\n");
	rr = rrset->rrs_sig;
	while (rr) {
	    PRINTX("      ", rr->rr_rdata, rr->rr_rdata_length_h);
	    rr = rr->rr_next;
	}

	printf("\n");
	rrset = rrset->rrs_next;
    }
}

void dump_dinfo(struct domain_info *dinfo)
{
    struct qname_chain *qc;
    int i;

    if (dinfo == NULL) {
	printf("dinfo = NULL\n");
	return;
    }

    printf ("domain_info:\n");
    PRINTS("  requested name  = ", dinfo->di_requested_name_h);
    printf("  requested type  = %s\n", p_type(dinfo->di_requested_type_h));
    printf("  requested class = %s\n", p_class(dinfo->di_requested_class_h));
    PRINTS("  error_message   = ", dinfo->di_error_message);

    printf("  qnames =\n");
    qc = dinfo->di_qnames;
    while (qc) {
	printf("    0x");
	for (i=0; i<MAXDNAME; i++) {
	    printf("%02x", qc->qc_name_n[i]);
	    if (qc->qc_name_n[i] == 0x00) {
		break;
	    }
	}
	printf("\n");
	printf("      ");
	for (i=0; i<MAXDNAME; i++) {
	    if (isprint(qc->qc_name_n[i])) {
		printf(" %c", qc->qc_name_n[i]);
	    }
	    else {
		printf("  ");
	    }
	    if (qc->qc_name_n[i] == 0x00) {
		break;
	    }
	}
	printf("\n");
	qc = qc->qc_next;
    }

    printf("  rrset =\n");
    dump_rrset(dinfo->di_rrset);
}

void dump_val_context (struct val_context *context) {
    if (!context) {
	printf("domain_info: NULL\n");
	return;
    }

    printf ("domain_info:\n");
    if (context->learned_zones) {
	printf("  learned_zones =\n");
	dump_rrset(context->learned_zones);
    }
    else {
	printf("  learned_zones = NULL\n");
    }

    if (context->learned_keys) {
	printf("  learned_keys =\n");
	dump_rrset(context->learned_keys);
    }
    else {
	printf("  learned_keys = NULL\n");
    }

    if (context->learned_ds) {
	printf("  learned_ds =\n");
	dump_rrset(context->learned_ds);
    }
    else {
	printf("  learned_ds = NULL\n");
    }
}

static void val_print_algorithm (u_int8_t algo)
{

    switch (algo) {
    case   1: printf(" [RSA/MD5]\n");        break;
    case   2: printf(" [Diffie-Hellman]\n"); break;
    case   3: printf(" [DSA/SHA-1]\n");      break;
    case   4: printf(" [Elliptic Curve]\n"); break;
    case   5: printf(" [RSA/SHA-1]\n");      break;
    case 252: printf(" [Indirect]\n");       break;
    case 253: printf(" [PrivateDNS]\n");     break;
    case 254: printf(" [PrivateOID]\n");     break;
    case   0:
    case 255: printf(" [reserved]\n");       break;
    default:  printf(" [unknown]\n");
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
	printf("%sType Covered         = %d\n", prefix, rdata->type_covered);
	printf("%sAlgorithm            = %d", prefix, rdata->algorithm);
	val_print_algorithm(rdata->algorithm);
	printf("%sLabels               = %d\n", prefix, rdata->labels);
	printf("%sOriginal TTL         = %d\n", prefix, rdata->orig_ttl);
	printf("%sSignature Expiration = %s",   prefix, ctime((const time_t *)(&(rdata->sig_expr))));
	printf("%sSignature Inception  = %s",   prefix, ctime((const time_t *)(&(rdata->sig_incp))));
	printf("%sKey Tag              = %d ", prefix, rdata->key_tag);
	printf("[0x %04x]\n", rdata->key_tag);
	printf("%sSigner's Name        = %s\n", prefix, rdata->signer_name);
	printf("%sSignature            = ", prefix);
	val_print_base64(rdata->signature, rdata->signature_len);
    }
}

void val_print_dnskey_rdata (const char *prefix, val_dnskey_rdata_t *rdata)
{
    if (rdata) {
	if (!prefix) prefix = "";
	printf("%sFlags                = %d\n", prefix, rdata->flags);
	printf("%sProtocol             = %d\n", prefix, rdata->protocol);
	printf("%sAlgorithm            = %d",   prefix, rdata->algorithm);
	val_print_algorithm(rdata->algorithm);
	printf("%sKey Tag              = %d", prefix, rdata->key_tag);
	printf("[0x %04x]\n", rdata->key_tag);
	printf("%sPublic Key           = ", prefix);
	val_print_base64(rdata->public_key, rdata->public_key_len);
    }
}
