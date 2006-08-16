
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#include "validator-config.h"

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
#include "val_parse.h"
#include "val_log.h"

char *get_hex_string(const unsigned char *data, int datalen, char *buf, int buflen)
{
	int i;
	char *ptr = buf;
	char *endptr = ptr+buflen;

	if (buf == NULL)
		return NULL;

	strcpy(ptr, "");

	snprintf(ptr, endptr-ptr, "0x");
	ptr += strlen(ptr);

	if (data == NULL)
		return buf;

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
    char buf1[2049], buf2[2049];
    while (rrset) {

		val_log(ctx, level, "rrs->val_rrset_name=%s rrs->val_rrset_type=%s rrs->val_rrset_class=%s rrs->val_rrset_ttl=%d"
			"rrs->val_rrset_section=%s rrs->val_rrset_data=%s rrs->val_rrset_sig=%s",
			rrset->rrs.val_rrset_name_n, p_type(rrset->rrs.val_rrset_type_h), p_class(rrset->rrs.val_rrset_class_h),
			rrset->rrs.val_rrset_ttl_h, p_section(rrset->rrs.val_rrset_section - 1, !ns_o_update),
			get_rr_string(rrset->rrs.val_rrset_data, buf1, 2048),
			get_rr_string(rrset->rrs.val_rrset_sig, buf2, 2048));
	
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
    char ctime_buf1[1028],ctime_buf2[1028];
	char buf[1028];
    if (rdata) {
		if (!prefix) prefix = "";
		val_log(ctx, level, "%s Type=%d Algo=%d[%s] Labels=%d OrgTTL=%d "
					"SigExp=%s SigIncp=%s KeyTag=%d[0x %04x] Signer=%s Sig=%s", prefix, 
					rdata->algorithm, get_algorithm_string(rdata->algorithm),
					rdata->labels, rdata->orig_ttl, 
					ctime_r((const time_t *)(&(rdata->sig_expr)), ctime_buf1),
					ctime_r((const time_t *)(&(rdata->sig_incp)), ctime_buf2),
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

void val_log_assertion( val_context_t *ctx, int level, u_char *name_n, u_int16_t class_h, u_int16_t type_h, 
						struct rr_rec *data, struct name_server *serv, val_astatus_t status) 
{ 
	char name[NS_MAXDNAME]; 
	char *name_pr, *serv_pr;
	int tag = 0;

	if(ns_name_ntop(name_n, name, NS_MAXDNAME-1) != -1) 
		name_pr = name;
	else
		name_pr = "ERR_NAME";
	if(serv)
		serv_pr = ((serv_pr = get_ns_string(&(serv))) == NULL)?"VAL_CACHE":serv_pr;
	else
		serv_pr = "NULL";

	if (type_h == ns_t_dnskey) {
		struct rr_rec *curkey;
		for (curkey = data; curkey; curkey=curkey->rr_next) {
			if(curkey->rr_status == VAL_A_VERIFIED_LINK) {
				/* Extract the key tag */
				val_dnskey_rdata_t dnskey;
				val_parse_dnskey_rdata (curkey->rr_rdata, curkey->rr_rdata_length_h, &dnskey);
				tag = dnskey.key_tag;
				break;
			}	
		}
	}
	if (tag !=0) {
		val_log(ctx, level, "name=%s class=%s type=%s[tag=%d] from-server=%s status=%s:%d",
			name_pr, p_class(class_h), p_type(type_h), tag, serv_pr, p_as_error(status), status);
	}
	else {
		val_log(ctx, level, "name=%s class=%s type=%s from-server=%s status=%s:%d",
			name_pr, p_class(class_h), p_type(type_h), serv_pr, p_as_error(status), status);
	}
} 

#define VAL_LOG_RESULT(name_n, class_h, type_h, serv, status) do {\
	char name[NS_MAXDNAME]; \
	char *name_pr, *serv_pr;\
	if(ns_name_ntop(name_n, name, NS_MAXDNAME-1) != -1) \
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

void val_log_authentication_chain(val_context_t *ctx, int level, u_char *name_n, u_int16_t class_h, u_int16_t type_h, 
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
		struct val_authentication_chain *next_as;
		next_as = next_result->val_rc_trust;

		if(top_q != NULL) {

			VAL_LOG_RESULT(name_n, class_h, type_h, 
					top_q->qc_respondent_server, next_result->val_rc_status);
			val_log(ctx, level, "Query Status = %s[%d]", 
					p_query_error(top_q->qc_state), top_q->qc_state);
		}

		for (next_as = next_result->val_rc_trust; next_as; next_as = next_as->val_ac_trust) {

			if(next_as->val_ac_rrset == NULL) {
				val_log(ctx, level, "Assertion status = %s[%d]",
					p_as_error(next_as->val_ac_status), next_as->val_ac_status);\
			}
			else {
				u_char *t_name_n;
				if(next_as->val_ac_rrset->val_rrset_name_n == NULL)
					t_name_n = (u_char*) "NULL_DATA";
				else
					t_name_n = next_as->val_ac_rrset->val_rrset_name_n;

				val_log_assertion(ctx, level, t_name_n, next_as->val_ac_rrset->val_rrset_class_h,
					next_as->val_ac_rrset->val_rrset_type_h, next_as->val_ac_rrset->val_rrset_data, 
					(struct name_server *)NULL, next_as->val_ac_status);
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

char *p_as_error(val_astatus_t err)
{
    switch (err) {
                                                                                                                             
    case VAL_NO_ERROR: return "VAL_NO_ERROR"; break;
                                                                                                                             
    case VAL_NOT_IMPLEMENTED: return "VAL_NOT_IMPLEMENTED"; break;
    case VAL_BAD_ARGUMENT: return "VAL_BAD_ARGUMENT"; break;
    case VAL_INTERNAL_ERROR: return "VAL_INTERNAL_ERROR"; break;
    case VAL_NO_PERMISSION: return "VAL_NO_PERMISSION"; break;
    case VAL_RESOURCE_UNAVAILABLE: return "VAL_RESOURCE_UNAVAILABLE"; break;
    case VAL_CONF_PARSE_ERROR: return "VAL_CONF_PARSE_ERROR"; break;
    case VAL_CONF_NOT_FOUND: return "VAL_CONF_NOT_FOUND"; break;
    case VAL_NO_POLICY: return "VAL_NO_POLICY"; break;

    case VAL_A_DATA_MISSING: return "VAL_A_DATA_MISSING"; break;
    case VAL_A_RRSIG_MISSING: return "VAL_A_RRSIG_MISSING"; break;
    case VAL_A_DNSKEY_MISSING: return "VAL_A_DNSKEY_MISSING"; break;
    case VAL_A_DS_MISSING: return "VAL_A_DS_MISSING"; break;
    case VAL_A_NO_TRUST_ANCHOR: return "VAL_A_NO_TRUST_ANCHOR"; break;
    case VAL_A_UNTRUSTED_ZONE: return "VAL_A_UNTRUSTED_ZONE"; break;
    case VAL_A_IRRELEVANT_PROOF: return "VAL_A_IRRELEVANT_PROOF"; break;
    case VAL_A_DNSSEC_VERSION_ERROR: return "VAL_A_DNSSEC_VERSION_ERROR"; break;
    case VAL_A_TOO_MANY_LINKS: return "VAL_A_TOO_MANY_LINKS"; break;
    case VAL_A_UNKNOWN_DNSKEY_PROTO: return "VAL_A_UNKNOWN_DNSKEY_PROTO"; break;
    case VAL_A_FLOOD_ATTACK_DETECTED: return "VAL_A_FLOOD_ATTACK_DETECTED"; break;
                                                                                                                             
    case VAL_A_DNSKEY_NOMATCH: return "VAL_A_DNSKEY_NOMATCH"; break;
    case VAL_A_WRONG_LABEL_COUNT: return "VAL_A_WRONG_LABEL_COUNT"; break;
    case VAL_A_SECURITY_LAME: return "VAL_A_SECURITY_LAME"; break;
    case VAL_A_NOT_A_ZONE_KEY: return "VAL_A_NOT_A_ZONE_KEY"; break;
    case VAL_A_RRSIG_NOTYETACTIVE: return "VAL_A_RRSIG_NOTYETACTIVE"; break;
    case VAL_A_RRSIG_EXPIRED: return "VAL_A_RRSIG_EXPIRED"; break;
    case VAL_A_ALGO_NOT_SUPPORTED: return "VAL_A_ALGO_NOT_SUPPORTED"; break;
    case VAL_A_UNKNOWN_ALGO: return "VAL_A_UNKNOWN_ALGO"; break;
    case VAL_A_RRSIG_VERIFIED: return "VAL_A_RRSIG_VERIFIED"; break;
    case VAL_A_RRSIG_VERIFY_FAILED: return "VAL_A_RRSIG_VERIFY_FAILED"; break;
    case VAL_A_NOT_VERIFIED: return "VAL_A_NOT_VERIFIED"; break;
    case VAL_A_KEY_TOO_LARGE: return "VAL_A_KEY_TOO_LARGE"; break;
    case VAL_A_KEY_TOO_SMALL: return "VAL_A_KEY_TOO_SMALL"; break;
    case VAL_A_KEY_NOT_AUTHORIZED: return "VAL_A_KEY_NOT_AUTHORIZED"; break;
    case VAL_A_ALGO_REFUSED: return "VAL_A_ALGO_REFUSED"; break;
    case VAL_A_CLOCK_SKEW: return "VAL_A_CLOCK_SKEW"; break;
    case VAL_A_DUPLICATE_KEYTAG: return "VAL_A_DUPLICATE_KEYTAG"; break;
    case VAL_A_NO_PREFERRED_SEP: return "VAL_A_NO_PREFERRED_SEP"; break;
    case VAL_A_WRONG_RRSIG_OWNER: return "VAL_A_WRONG_RRSIG_OWNER"; break;
    case VAL_A_RRSIG_ALGO_MISMATCH: return "VAL_A_RRSIG_ALGO_MISMATCH"; break;
    case VAL_A_KEYTAG_MISMATCH: return "VAL_A_KEYTAG_MISMATCH"; break;
                                                                                                                             
    case VAL_A_VERIFIED: return "VAL_A_VERIFIED"; break;
    case VAL_A_VERIFIED_LINK: return "VAL_A_VERIFIED_LINK"; break;
    case VAL_A_LOCAL_ANSWER: return "VAL_A_LOCAL_ANSWER"; break;
    case VAL_A_TRUST_KEY: return "VAL_A_TRUST_KEY"; break;
    case VAL_A_TRUST_ZONE: return "VAL_A_TRUST_ZONE"; break;
	case VAL_A_PROVABLY_UNSECURE: return "VAL_A_PROVABLY_UNSECURE"; break;
    case VAL_A_BARE_RRSIG: return "VAL_A_BARE_RRSIG"; break;


	case VAL_A_DONT_VALIDATE: return "VAL_A_DONT_VALIDATE"; break;

    /*
    case VAL_A_UNAUTHORIZED_SIGNER: return "UNAUTHORIZED_SIGNER"; break;
    case VAL_A_CONFLICTING_PROOFS: return "CONFLICTING_PROOFS"; break;
    case VAL_A_OVERREACHING_NSEC: return "OVERREACHING_NSEC"; break;
    case VAL_A_DNSSEC_VERSION_ERROR: return "VAL_A_DNSSEC_VERSION_ERROR"; break;
    */
    default:
            if((err >= VAL_A_DNS_ERROR_BASE) && (err < VAL_A_DNS_ERROR_LAST)) {
				int errbase = VAL_A_DNS_ERROR_BASE;
				int dnserr = err - errbase + Q_ERROR_BASE;
                return p_query_error(dnserr);
			} 
            else if (err < VAL_A_LAST_STATE)
                return "UNEVALUATED";
            return "Unknown Error Value";
    }
}

char *p_val_error(val_status_t err)
{
    switch (err) {

		case VAL_R_DONT_KNOW: 
		case VAL_R_TRUST_FLAG|VAL_R_DONT_KNOW: 
					return "Uninitialized"; break;
		case VAL_INDETERMINATE:
		case VAL_R_TRUST_FLAG|VAL_INDETERMINATE:
					return "VAL_INDETERMINATE"; break;
		case VAL_BOGUS: 
		case VAL_R_TRUST_FLAG|VAL_BOGUS:
					return "VAL_BOGUS"; break;
		case VAL_LOCAL_ANSWER: 
		case VAL_R_TRUST_FLAG|VAL_LOCAL_ANSWER: 
					return "VAL_LOCAL_ANSWER"; break;
		case VAL_BARE_RRSIG: 
		case VAL_R_TRUST_FLAG|VAL_BARE_RRSIG: 
					return "VAL_BARE_RRSIG"; break;
		case VAL_NONEXISTENT_NAME: 
		case VAL_R_TRUST_FLAG|VAL_NONEXISTENT_NAME: 
					return "VAL_NONEXISTENT_NAME"; break;
		case VAL_NONEXISTENT_TYPE: 
		case VAL_R_TRUST_FLAG|VAL_NONEXISTENT_TYPE: 
					return "VAL_NONEXISTENT_TYPE"; break;
		case VAL_ERROR: 
		case VAL_R_TRUST_FLAG|VAL_ERROR: 
					return "VAL_ERROR"; break;
		case VAL_NOTRUST:
					return "VAL_NOTRUST"; break;

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
		return VAL_INTERNAL_ERROR;

	server.sin_family = AF_INET;
	server.sin_port = htons(VALIDATOR_LOG_PORT);
	if (inet_pton(AF_INET, VALIDATOR_LOG_SERVER, &server.sin_addr) != 1)
		goto err;
	length=sizeof(struct sockaddr_in);

	if(sendto(sock, buffer, strlen(buffer),0,&server,length) < 0)
		goto err;

	close(sock);
	return VAL_NO_ERROR;

  err:
	close(sock);
	return VAL_INTERNAL_ERROR;
}
#endif /* LOG_TO_NETWORK */

void val_log (const val_context_t *ctx, int level, const char *template, ...)
{
	va_list ap;

	/* Needs to be at least two characters larger than message size */
	char buf[1028]; 
	int log_mask = LOG_UPTO(VAL_LOG_MASK);

	setlogmask(log_mask);
        snprintf(buf, sizeof(buf), "libval(%d)",
                 (ctx == NULL)? "0": ctx->id);
	openlog(buf, VAL_LOG_OPTIONS, LOG_USER);

	va_start (ap, template);
	vsyslog(LOG_USER|level, template, ap);
	va_end (ap);

#ifdef LOG_TO_NETWORK
	if(LOG_MASK(level) & log_mask) {
		/* We allocated extra space  */
		va_start (ap, template);
		vsnprintf(buf, 1024, template, ap);
		va_end (ap);
		strcat(buf, "\n");
		send_log_message(buf);
	}
#endif /* LOG_TO_NETWORK */
}
