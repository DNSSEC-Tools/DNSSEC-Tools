
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <resolv.h>

#include <resolver.h>
#include <validator.h>
#include "val_cache.h"
#include "val_support.h"

char *get_hex_string(char *data, int datalen, char *buf, int buflen)
{
	int i;
	char *ptr = buf;
	char *endptr = ptr+buflen;
	strcpy(ptr, "");

	snprintf(ptr, endptr-ptr, "0x");
	ptr += strlen(ptr);

	for (i=0; i<datalen; i++) { 
		snprintf(ptr, endptr-ptr, "%02x", data[i]);
		ptr += strlen(ptr);
	} 

	return buf;
}

static char *get_rr_string(struct rr_rec *rr, char *buf, int buflen)
{
	char *ptr = buf; 
	char *endptr = ptr+buflen;
	while (rr) {
		get_hex_string(rr->rr_rdata, rr->rr_rdata_length_h, ptr, endptr-ptr);
		ptr += strlen(ptr);
	    rr = rr->rr_next;
	}

	return buf;
}

void val_log_rrset(val_context_t *ctx, int level, struct rrset_rec *rrset)
{
	char buf[2049];
    while (rrset) {

		val_log(ctx, level, "rrs_name=%s rrs_type=%s rrs_class=%s rrs_ttl=%d"
			"rrs_section=%s rrs_data=%s rrs_sig=%s",
			rrset->rrs_name_n, p_type(rrset->rrs_type_h), p_class(rrset->rrs_class_h),
			rrset->rrs_ttl_h, p_section(rrset->rrs_section - 1, !ns_o_update),
			get_rr_string(rrset->rrs_data, buf, 2048),
			get_rr_string(rrset->rrs_sig, buf, 2048));
	
		rrset = rrset->rrs_next;
    }
}

static char *get_base64_string(unsigned char *message, int message_len, char *buf, int bufsize)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(message, message_len);
    mem = BIO_push(b64, mem);

    if(-1 == BIO_write(mem, buf, bufsize))
		 strcpy(buf, "");
    BIO_free_all(mem);

	return buf;
}

static const char *get_algorithm_string (u_int8_t algo)
{

    switch (algo) {
    case   1: return "RSA/MD5";        break;
    case   2: return "Diffie-Hellman"; break;
    case   3: return "DSA/SHA-1";      break;
    case   4: return "Elliptic Curve"; break;
    case   5: return "RSA/SHA-1";      break;
    case 252: return "Indirect";       break;
    case 253: return "PrivateDNS";     break;
    case 254: return "PrivateOID";     break;
    case   0:
    case 255: return "reserved";       break;
    default:  return "unknown";
    }
}

void val_log_rrsig_rdata (val_context_t *ctx, int level, const char *prefix, val_rrsig_rdata_t *rdata)
{
	char ctime_buf[1028];
	char buf[1028];
    if (rdata) {
		if (!prefix) prefix = "";
		val_log(ctx, level, "%s Type=%d Algo=%d[%s] Labels=%d OrgTTL=%d "
					"SigExp=%s SigIncp=%s KeyTag=%d[0x %04x] Signer=%s Sig=%s", prefix, 
					rdata->algorithm, get_algorithm_string(rdata->algorithm),
					rdata->labels, rdata->orig_ttl, 
					ctime_r((const time_t *)(&(rdata->sig_expr)), ctime_buf),
					ctime_r((const time_t *)(&(rdata->sig_incp)), ctime_buf),
					rdata->key_tag, rdata->key_tag, rdata->signer_name, 
					get_base64_string(rdata->signature, rdata->signature_len, buf, 1024));
    }
}

void val_log_dnskey_rdata (val_context_t *ctx, int level, const char *prefix, val_dnskey_rdata_t *rdata)
{
	char buf[1028];
    if (rdata) {
		if (!prefix) prefix = "";
		val_log(ctx, level, "%s Flags=%d Prot=%d Algo=%d[%s] KeyTag=%d[0x %04x] PK=%s", prefix,
				rdata->flags, rdata->protocol, 
				rdata->algorithm, get_algorithm_string(rdata->algorithm),
				rdata->key_tag, rdata->key_tag, 
				get_base64_string(rdata->public_key, rdata->public_key_len, buf, 1024));
    }
}

static char *get_ns_string(struct name_server **server)
{
	if((server == NULL) || (*server == NULL))
		return NULL;

	struct sockaddr_in  *s=(struct sockaddr_in*)(&((*server)->ns_address[0]));
	return inet_ntoa(s->sin_addr);
}

#define VAL_LOG_ASSERTION(name_n, class_h, type_h, serv, status) do {\
	char name[MAXDNAME]; \
	char *name_pr, *serv_pr;\
	if(ns_name_ntop(name_n, name, MAXDNAME-1) != -1) \
		name_pr = name;\
	else\
		name_pr = "ERR_NAME";\
	if(serv)\
		serv_pr = ((serv_pr = get_ns_string(&(serv))) == NULL)?"VAL_CACHE":serv_pr;\
	else\
		serv_pr = "NULL";\
	val_log(ctx, level, "name=%s class=%s type=%s from-server=%s status=%s:%d",\
		name_pr, p_class(class_h), p_type(type_h), serv_pr, p_as_error(status), status);\
} while (0)		

#define VAL_LOG_RESULT(name_n, class_h, type_h, serv, status) do {\
	char name[MAXDNAME]; \
	char *name_pr, *serv_pr;\
	if(ns_name_ntop(name_n, name, MAXDNAME-1) != -1) \
		name_pr = name;\
	else\
		name_pr = "ERR_NAME";\
	if(serv)\
		serv_pr = ((serv_pr = get_ns_string(&(serv))) == NULL)?"VAL_CACHE":serv_pr;\
	else\
		serv_pr = "NULL";\
	val_log(ctx, level, "name=%s class=%s type=%s from-server=%s status=%s:%d",\
		name_pr, p_class(class_h), p_type(type_h), serv_pr, p_val_error(status), status);\
} while (0)		

void val_log_assertion_chain(val_context_t *ctx, int level, u_char *name_n, u_int16_t class_h, u_int16_t type_h, 
				struct val_query_chain *queries, struct val_result_chain *results)
{
	struct val_result_chain *next_result;
	struct val_query_chain *top_q = NULL;

	/* Search for the "main" query */
	for (top_q = queries; top_q; top_q=top_q->qc_next) {
		if(!namecmp(top_q->qc_name_n, name_n) &&
			(top_q->qc_class_h == class_h) &&
			(top_q->qc_type_h == type_h))
				break;
	}

	for (next_result = results; next_result; next_result = next_result->val_rc_next) {
		struct val_assertion_chain *next_as;
		next_as = next_result->val_rc_trust;

		if(top_q != NULL) {

			VAL_LOG_RESULT(name_n, class_h, type_h, 
					top_q->qc_respondent_server, next_result->val_rc_status);
			val_log(ctx, level, "Query Status = %s[%d]", 
					p_query_error(top_q->qc_state), top_q->qc_state);
		}

		for (next_as = next_result->val_rc_trust; next_as; next_as = next_as->val_ac_trust) {
			u_char *t_name_n;
			if(next_as->_as->ac_data->rrs_name_n == NULL)
				t_name_n = "NULL_DATA";
			else
				t_name_n = next_as->_as->ac_data->rrs_name_n;

			if(next_as->_as->ac_data == NULL) {
				val_log(ctx, level, "Assertion status = %s[%d]",
					p_as_error(next_as->val_ac_status), next_as->val_ac_status);\
			}
			else {
				VAL_LOG_ASSERTION(t_name_n, next_as->_as->ac_data->rrs_class_h,
					next_as->_as->ac_data->rrs_type_h, next_as->_as->ac_data->rrs_respondent_server, 
					next_as->val_ac_status);
			}
		}
	}
}

char *p_query_error(int err)
{
	if (err < Q_ERROR_BASE) {
		switch(err) {
			case Q_INIT: return "Q_INIT";
			case Q_SENT: return "Q_SENT"; 
			case Q_ANSWERED: return "Q_ANSWERED"; 
			default: break;
		}
	}
	else {
		int dnserr = err - Q_ERROR_BASE;
		switch(dnserr) {
			case SR_CALL_ERROR: return "SR_CALL_ERROR";
			case SR_TSIG_ERROR: return "SR_TSIG_ERROR";
			case SR_MEMORY_ERROR: return "SR_MEMORY_ERROR";
			case SR_NO_ANSWER: return "SR_NO_ANSWER";
			case SR_NO_ANSWER_YET: return "SR_NO_ANSWER_YET";
			case SR_MKQUERY_INTERNAL_ERROR: return "SR_MKQUERY_INTERNAL_ERROR";
			case SR_TSIG_INTERNAL_ERROR: return "SR_TSIG_INTERNAL_ERROR";
			case SR_SEND_INTERNAL_ERROR: return "SR_SEND_INTERNAL_ERROR";
			case SR_RCV_INTERNAL_ERROR: return "SR_RCV_INTERNAL_ERROR";
			case SR_WRONG_ANSWER: return "SR_WRONG_ANSWER";
			case SR_HEADER_BADSIZE: return "SR_HEADER_BADSIZE";
			case SR_NXDOMAIN : return "SR_NXDOMAIN";
			case SR_FORMERR  : return "SR_FORMERR";
			case SR_SERVFAIL : return "SR_SERVFAIL";
			case SR_NOTIMPL  : return "SR_NOTIMPL";
			case SR_REFUSED  : return "SR_REFUSED";
			case SR_GENERIC_FAILURE : return "SR_GENERIC_FAILURE";
			case SR_EDNS_VERSION_ERROR : return "SR_EDNS_VERSION_ERROR";
			case SR_UNSUPP_EDNS0_LABEL : return "SR_UNSUPP_EDNS0_LABEL";
			case SR_SUSPICIOUS_BIT : return "SR_SUSPICIOUS_BIT";
			case SR_NAME_EXPANSION_FAILURE : return "SR_NAME_EXPANSION_FAILURE";
			case SR_REFERRAL_ERROR: return "SR_REFERRAL_ERROR";
			case SR_MISSING_GLUE: return "SR_MISSING_GLUE";
			case SR_CONFLICTING_ANSWERS: return "SR_CONFLICTING_ANSWERS";
			default: break;
		}
	}

	return "UNKNOWN";
}

char *p_as_error(int err)
{
    switch (err) {
                                                                                                                             
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
            if((err >= DNS_ERROR_BASE) && (err < DNS_ERROR_LAST)) {
				int errbase = DNS_ERROR_BASE;
				int dnserr = err - errbase + Q_ERROR_BASE;
                return p_query_error(dnserr);
			} 
            else if (err < A_LAST_STATE)
                return "UNEVALUATED";
            return "Unknown Error Value";
    }
}

char *p_val_error(int err)
{
    switch (err) {

		case R_DONT_KNOW: 
		case R_TRUST_FLAG|R_DONT_KNOW: 
					return "Uninitialized"; break;
		case VAL_INDETERMINATE:
		case R_TRUST_FLAG|VAL_INDETERMINATE:
					return "VAL_INDETERMINATE"; break;
		case VAL_BOGUS: 
		case R_TRUST_FLAG|VAL_BOGUS:
					return "VAL_BOGUS"; break;
		case VAL_LOCAL_ANSWER: 
		case R_TRUST_FLAG|VAL_LOCAL_ANSWER: 
					return "VAL_LOCAL_ANSWER"; break;
		case VAL_BARE_RRSIG: 
		case R_TRUST_FLAG|VAL_BARE_RRSIG: 
					return "VAL_BARE_RRSIG"; break;
		case VAL_NONEXISTENT_NAME: 
		case R_TRUST_FLAG|VAL_NONEXISTENT_NAME: 
					return "VAL_NONEXISTENT_NAME"; break;
		case VAL_NONEXISTENT_TYPE: 
		case R_TRUST_FLAG|VAL_NONEXISTENT_TYPE: 
					return "VAL_NONEXISTENT_TYPE"; break;
		case VAL_ERROR: 
		case R_TRUST_FLAG|VAL_ERROR: 
					return "VAL_ERROR"; break;
		case VAL_PROVABLY_UNSECURE: 
		case R_TRUST_FLAG|VAL_PROVABLY_UNSECURE: 
					return "VAL_PROVABLY_UNSECURE"; break;

		case VAL_SUCCESS: 
					return "VAL_SUCCESS"; break;
    	default:
            if((err >= VAL_DNS_ERROR_BASE) && (err < VAL_DNS_ERROR_LAST)) {
				int errbase = VAL_DNS_ERROR_BASE;
				int dnserr = err - errbase + Q_ERROR_BASE;
                return p_query_error(dnserr);
			} 
            return "Unknown Error Value";
	}                                                                                                                             
}

#ifdef LOG_TO_NETWORK
int send_log_message(char *buffer)
{
	int sock;
	struct sockaddr_in server;
	int length;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return INTERNAL_ERROR;

	server.sin_family = AF_INET;
	server.sin_port = htons(VALIDATOR_LOG_PORT);
	inet_aton(VALIDATOR_LOG_SERVER, &server.sin_addr);
	length=sizeof(struct sockaddr_in);

	if(sendto(sock, buffer, strlen(buffer),0,&server,length) < 0)
		return INTERNAL_ERROR; 

	return NO_ERROR;
}
#endif /* LOG_TO_NETWORK */

void val_log (const val_context_t *ctx, int level, const char *template, ...)
{
	va_list ap;
	const char *id_buf;

	/* Needs to be at least two characters larger than message size */
	char buf[1028]; 
	int log_mask = LOG_UPTO(VAL_LOG_MASK);

	setlogmask(log_mask);
	id_buf = (ctx == NULL)? "libval": ctx->id;
	openlog(id_buf, VAL_LOG_OPTIONS, LOG_USER);
	va_start (ap, template);
	vsyslog(LOG_USER|level, template, ap);
	va_end (ap);
	va_start (ap, template);
	vsnprintf(buf, 1024, template, ap);
	va_end (ap);

#ifdef LOG_TO_NETWORK
	if(LOG_MASK(level) & log_mask) {
		/* We allocated extra space  */
		strcat(buf, "\n");
		send_log_message(buf);
	}
#endif /* LOG_TO_NETWORK */

}
