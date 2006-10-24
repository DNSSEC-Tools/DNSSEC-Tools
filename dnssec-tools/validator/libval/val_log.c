
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#include "validator-config.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <resolv.h>
#include <time.h>

#include <resolver.h>
#include <validator.h>
#include "val_cache.h"
#include "val_support.h"
#include "val_parse.h"
#include "val_log.h"
#include "val_crypto.h"

#ifndef HAVE_DECL_P_SECTION
#include "res_debug.h"
#endif

static int      debug_level = LOG_INFO;
static val_log_t *log_head = NULL;

int
val_log_debug_level(void)
{
    return debug_level;
}

void
val_log_set_debug_level(int level)
{
    debug_level = level;
}


char           *
get_hex_string(const unsigned char *data, int datalen, char *buf,
               int buflen)
{
    int             i;
    char           *ptr = buf;
    char           *endptr = ptr + buflen;

    if (buf == NULL)
        return NULL;

    strcpy(ptr, "");

    snprintf(ptr, endptr - ptr, "0x");
    ptr += strlen(ptr);

    if (data == NULL)
        return buf;

    for (i = 0; i < datalen; i++) {
        snprintf(ptr, endptr - ptr, "%02x", data[i]);
        ptr += strlen(ptr);
    }

    return buf;
}

static char    *
get_rr_string(struct rr_rec *rr, char *buf, int buflen)
{
    char           *ptr = buf;
    char           *endptr = ptr + buflen;
    while (rr) {
        get_hex_string(rr->rr_rdata, rr->rr_rdata_length_h, ptr,
                       endptr - ptr);
        ptr += strlen(ptr);
        rr = rr->rr_next;
    }

    return buf;
}

void
val_log_val_rrset_pfx(const val_context_t * ctx, int level, const char *pfx,
                      struct val_rrset *val_rrset)
{
    char            buf1[2049], buf2[2049];
    char            name_p[NS_MAXDNAME];

    if (ns_name_ntop(val_rrset->val_rrset_name_n, name_p, sizeof(name_p)) == -1)
        snprintf(name_p, sizeof(name_p), "ERROR");
    val_log(ctx, level,"%srrs->val_rrset_name=%s rrs->val_rrset_type=%s "
            "rrs->val_rrset_class=%s rrs->val_rrset_ttl=%d "
            "rrs->val_rrset_section=%s\nrrs->val_rrset_data=%s\n"
            "rrs->val_rrset_sig=%s", pfx ? pfx : "", name_p,
            p_type(val_rrset->val_rrset_type_h),
            p_class(val_rrset->val_rrset_class_h),
            val_rrset->val_rrset_ttl_h,
            p_section(val_rrset->val_rrset_section - 1, !ns_o_update),
            get_rr_string(val_rrset->val_rrset_data, buf1, 2048),
            get_rr_string(val_rrset->val_rrset_sig, buf2, 2048));
}

void
val_log_rrset(const val_context_t * ctx, int level, struct rrset_rec *rrset)
{
    while (rrset) {

        val_log_val_rrset_pfx(ctx, level, NULL, &rrset->rrs);
        rrset = rrset->rrs_next;
    }
}


static const char *
get_algorithm_string(u_int8_t algo)
{

    switch (algo) {
    case 1:
        return "RSA/MD5";
        break;
    case 2:
        return "Diffie-Hellman";
        break;
    case 3:
        return "DSA/SHA-1";
        break;
    case 4:
        return "Elliptic Curve";
        break;
    case 5:
        return "RSA/SHA-1";
        break;
    case 252:
        return "Indirect";
        break;
    case 253:
        return "PrivateDNS";
        break;
    case 254:
        return "PrivateOID";
        break;
    case 0:
    case 255:
        return "reserved";
        break;
    default:
        return "unknown";
    }
}

void
val_log_rrsig_rdata(const val_context_t * ctx, int level, const char *prefix,
                    val_rrsig_rdata_t * rdata)
{
    char            ctime_buf1[1028], ctime_buf2[1028];
    char            buf[1028];
    if (rdata) {
        if (!prefix)
            prefix = "";
        val_log(ctx, level, "%s Type=%d Algo=%d[%s] Labels=%d OrgTTL=%d "
                "SigExp=%s SigIncp=%s KeyTag=%d[0x %04x] Signer=%s Sig=%s",
                prefix, rdata->algorithm,
                get_algorithm_string(rdata->algorithm), rdata->labels,
                rdata->orig_ttl,
#ifndef sun
                ctime_r((const time_t *) (&(rdata->sig_expr)), ctime_buf1),
                ctime_r((const time_t *) (&(rdata->sig_incp)), ctime_buf2),
#else
                ctime_r((const time_t *) (&(rdata->sig_expr)), ctime_buf1, sizeof(ctime_buf1)),
                ctime_r((const time_t *) (&(rdata->sig_incp)), ctime_buf2, sizeof(ctime_buf2)),
#endif
                rdata->key_tag, rdata->key_tag, rdata->signer_name,
                get_base64_string(rdata->signature, rdata->signature_len,
                                  buf, 1024));
    }
}

void
val_log_dnskey_rdata(val_context_t * ctx, int level, const char *prefix,
                     val_dnskey_rdata_t * rdata)
{
    char            buf[1028];
    if (rdata) {
        if (!prefix)
            prefix = "";
        val_log(ctx, level,
                "%s Flags=%d Prot=%d Algo=%d[%s] KeyTag=%d[0x %04x] PK=%s",
                prefix, rdata->flags, rdata->protocol, rdata->algorithm,
                get_algorithm_string(rdata->algorithm), rdata->key_tag,
                rdata->key_tag, get_base64_string(rdata->public_key,
                                                  rdata->public_key_len,
                                                  buf, 1024));
    }
}

static char    *
get_ns_string(struct sockaddr *serv)
{
    struct sockaddr_in *sin;
    struct sockaddr_storage *server;
    
    if (serv == NULL) 
        return NULL;

    server = (struct sockaddr_storage *) serv;
    
    /* XXX Need to support IPv6 */
    switch (server->ss_family) {
      case AF_INET:
            sin = (struct sockaddr_in *)server;
            return inet_ntoa(sin->sin_addr);
    }
    return NULL;
}

void
val_log_assertion_pfx(const val_context_t * ctx, int level,
                      const char* prefix, const u_char * name_n,
                      struct val_authentication_chain *next_as)
{
    char            name[NS_MAXDNAME];
    const char     *name_pr, *serv_pr;
    int             tag = 0;

    if (next_as == NULL)
        return;
    
    u_int16_t class_h = next_as->val_ac_rrset->val_rrset_class_h;
    u_int16_t type_h = next_as->val_ac_rrset->val_rrset_type_h; 
    struct rr_rec *data = next_as->val_ac_rrset->val_rrset_data;
    struct sockaddr *serv = next_as->val_ac_rrset->val_rrset_server;
    val_astatus_t status = next_as->val_ac_status;
    
    if (NULL == prefix)
        prefix = "";

    if (ns_name_ntop(name_n, name, sizeof(name)) != -1)
        name_pr = name;
    else
        name_pr = "ERR_NAME";
    if (serv)
        serv_pr =
            ((serv_pr =
              get_ns_string(serv)) == NULL) ? "VAL_CACHE" : serv_pr;
    else
        serv_pr = "NULL";

    if (type_h == ns_t_dnskey) {
        struct rr_rec  *curkey;
        for (curkey = data; curkey; curkey = curkey->rr_next) {
            if ((curkey->rr_status == VAL_A_VERIFIED_LINK) ||
                   (curkey->rr_status == VAL_A_UNKNOWN_ALGO_LINK)) {
                /*
                 * Extract the key tag 
                 */
                val_dnskey_rdata_t dnskey;
                val_parse_dnskey_rdata(curkey->rr_rdata,
                                       curkey->rr_rdata_length_h, &dnskey);
                tag = dnskey.key_tag;
                if (dnskey.public_key)
                    FREE(dnskey.public_key);
                break;
            }
        }
    }
    if (tag != 0) {
        val_log(ctx, level,
                "%sname=%s class=%s type=%s[tag=%d] from-server=%s "
                "status=%s:%d", prefix, name_pr, p_class(class_h),
                p_type(type_h), tag, serv_pr, p_as_error(status), status);
    } else {
        val_log(ctx, level,
                "%sname=%s class=%s type=%s from-server=%s status=%s:%d",
                prefix, name_pr, p_class(class_h), p_type(type_h), serv_pr,
                p_as_error(status), status);
    }
#if 0
    struct rr_rec *rr;
    struct rr_rec *sig = next_as->val_ac_rrset->val_rrset_sig;
    for (rr=data; rr; rr=rr->rr_next) {
        val_log(ctx, level, "    data_status=%s:%d", p_as_error(rr->rr_status), rr->rr_status);
    }
    for (rr=sig; rr; rr=rr->rr_next) {
        val_log(ctx, level, "    sig_status=%s:%d", p_as_error(rr->rr_status), rr->rr_status);
    }
#endif
}

void
val_log_assertion(const val_context_t * ctx, int level,
                  const u_char * name_n,
                  struct val_authentication_chain *next_as)
{
    val_log_assertion_pfx(ctx, level, NULL, name_n, next_as);
}

void
val_log_authentication_chain(const val_context_t * ctx, int level,
                             u_char * name_n, u_int16_t class_h,
                             u_int16_t type_h,
                             struct val_query_chain *queries,
                             struct val_result_chain *results)
{
    struct val_result_chain *next_result;
    struct val_query_chain *top_q = NULL;

    /*
     * Search for the "main" query 
     */
    for (top_q = queries; top_q; top_q = top_q->qc_next) {
        if (!namecmp(top_q->qc_name_n, name_n) &&
            (top_q->qc_class_h == class_h) && (top_q->qc_type_h == type_h))
            break;
    }

    if (top_q != NULL) {
	    char name_p[NS_MAXDNAME]; 
	    const char *name_pr, *serv_pr;
	    if(ns_name_ntop(name_n, name_p, sizeof(name_p)) != -1) 
		    name_pr = name_p;
	    else
		    name_pr = "ERR_NAME";
	    if((top_q->qc_respondent_server) && 
           (top_q->qc_respondent_server->ns_number_of_addresses > 0))
		    serv_pr = ((serv_pr = get_ns_string(
                            (struct sockaddr *)top_q->qc_respondent_server->ns_address[0])) == NULL)?
                "VAL_CACHE":serv_pr;
	    else
		    serv_pr = "NULL";
	    val_log(ctx, level, "Original query: name=%s class=%s type=%s "
                    "from-server=%s, Query-status=%s:%d",
                    name_pr, p_class(class_h), p_type(type_h), serv_pr, 
                    p_query_error(top_q->qc_state), top_q->qc_state);
    }
    else
        val_log(ctx, level, "Original query: UNKNOWN?");

    for (next_result = results; next_result;
         next_result = next_result->val_rc_next) {
        struct val_authentication_chain *next_as;
        int i;

        val_log(ctx, level, "  Result: %s:%d",
                p_val_error(next_result->val_rc_status), 
                next_result->val_rc_status);

        for (next_as = next_result->val_rc_answer; next_as;
             next_as = next_as->val_ac_trust) {

            if (next_as->val_ac_rrset == NULL) {
                val_log(ctx, level, "    Assertion status = %s:%d",
                        p_as_error(next_as->val_ac_status),
                        next_as->val_ac_status);
            } else {
                const u_char   *t_name_n;
                if (next_as->val_ac_rrset->val_rrset_name_n == NULL)
                    t_name_n = (const u_char *) "NULL_DATA";
                else
                    t_name_n = next_as->val_ac_rrset->val_rrset_name_n;

                val_log_assertion_pfx(ctx, level, "    ", t_name_n, next_as);
//                val_log_val_rrset_pfx(ctx, level, "     ",
//                                  next_as->val_ac_rrset);
            }
        }

        if (next_result->val_rc_proof_count > 0) {
            val_log(ctx, level, "    Associated Proofs Follow:");
        }
        for (i=0; i<next_result->val_rc_proof_count; i++) {
            for (next_as = next_result->val_rc_proofs[i]; next_as;
                next_as = next_as->val_ac_trust) {

                if (next_as->val_ac_rrset == NULL) {
                    val_log(ctx, level, "      Assertion status = %s:%d",
                            p_as_error(next_as->val_ac_status),
                            next_as->val_ac_status);
                } else {
                    const u_char   *t_name_n;
                    if (next_as->val_ac_rrset->val_rrset_name_n == NULL)
                        t_name_n = (const u_char *) "NULL_DATA";
                    else
                        t_name_n = next_as->val_ac_rrset->val_rrset_name_n;

                    val_log_assertion_pfx(ctx, level, "      ", t_name_n,
                                          next_as);
                }
            }
        }
    }
}

const char     *
p_query_error(int err)
{
    if (err < Q_ERROR_BASE) {
        switch (err) {
        case Q_INIT:
            return "Q_INIT";
        case Q_SENT:
            return "Q_SENT";
        case Q_ANSWERED:
            return "Q_ANSWERED";
        default:
            break;
        }
    } else {
        int             dnserr = err - Q_ERROR_BASE;
        switch (dnserr) {
        case SR_INTERNAL_ERROR:
            return "SR_INTERNAL_ERROR";
        case SR_TSIG_ERROR:
            return "SR_TSIG_ERROR";
        case SR_NO_ANSWER:
            return "SR_NO_ANSWER";
        case SR_NO_ANSWER_YET:
            return "SR_NO_ANSWER_YET";
        case SR_WRONG_ANSWER:
            return "SR_WRONG_ANSWER";
        case SR_HEADER_BADSIZE:
            return "SR_HEADER_BADSIZE";
        case SR_NXDOMAIN:
            return "SR_NXDOMAIN";
        case SR_FORMERR:
            return "SR_FORMERR";
        case SR_SERVFAIL:
            return "SR_SERVFAIL";
        case SR_NOTIMPL:
            return "SR_NOTIMPL";
        case SR_REFUSED:
            return "SR_REFUSED";
        case SR_DNS_GENERIC_ERROR:
            return "SR_DNS_GENERIC_ERROR";
        case SR_EDNS_VERSION_ERROR:
            return "SR_EDNS_VERSION_ERROR";
        case SR_UNSUPP_EDNS0_LABEL:
            return "SR_UNSUPP_EDNS0_LABEL";
        case SR_SUSPICIOUS_BIT:
            return "SR_SUSPICIOUS_BIT";
        case SR_NAME_EXPANSION_FAILURE:
            return "SR_NAME_EXPANSION_FAILURE";
        case SR_REFERRAL_ERROR:
            return "SR_REFERRAL_ERROR";
        case SR_MISSING_GLUE:
            return "SR_MISSING_GLUE";
        case SR_CONFLICTING_ANSWERS:
            return "SR_CONFLICTING_ANSWERS";
        default:
            break;
        }
    }

    return "UNKNOWN";
}

const char     *
p_as_error(val_astatus_t err)
{
    switch (err) {
    case VAL_A_DATA_MISSING:
        return "VAL_A_DATA_MISSING";
        break;
    case VAL_A_RRSIG_MISSING:
        return "VAL_A_RRSIG_MISSING";
        break;
    case VAL_A_DNSKEY_MISSING:
        return "VAL_A_DNSKEY_MISSING";
        break;
    case VAL_A_DS_MISSING:
        return "VAL_A_DS_MISSING";
        break;
    case VAL_A_NO_TRUST_ANCHOR:
        return "VAL_A_NO_TRUST_ANCHOR";
        break;
    case VAL_A_UNTRUSTED_ZONE:
        return "VAL_A_UNTRUSTED_ZONE";
        break;
    case VAL_A_DNSSEC_VERSION_ERROR:
        return "VAL_A_DNSSEC_VERSION_ERROR";
        break;
    case VAL_A_TOO_MANY_LINKS:
        return "VAL_A_TOO_MANY_LINKS";
        break;
    case VAL_A_UNKNOWN_DNSKEY_PROTO:
        return "VAL_A_UNKNOWN_DNSKEY_PROTO";
        break;
    case VAL_A_FLOOD_ATTACK_DETECTED:
        return "VAL_A_FLOOD_ATTACK_DETECTED";
        break;

    case VAL_A_DNSKEY_NOMATCH:
        return "VAL_A_DNSKEY_NOMATCH";
        break;
    case VAL_A_WRONG_LABEL_COUNT:
        return "VAL_A_WRONG_LABEL_COUNT";
        break;
    case VAL_A_SECURITY_LAME:
        return "VAL_A_SECURITY_LAME";
        break;
    case VAL_A_INVALID_KEY:
        return "VAL_A_INVALID_KEY";
        break;
    case VAL_A_RRSIG_NOTYETACTIVE:
        return "VAL_A_RRSIG_NOTYETACTIVE";
        break;
    case VAL_A_RRSIG_EXPIRED:
        return "VAL_A_RRSIG_EXPIRED";
        break;
    case VAL_A_ALGO_NOT_SUPPORTED:
        return "VAL_A_ALGO_NOT_SUPPORTED";
        break;
    case VAL_A_UNKNOWN_ALGO:
        return "VAL_A_UNKNOWN_ALGO";
        break;
    case VAL_A_RRSIG_VERIFIED:
        return "VAL_A_RRSIG_VERIFIED";
        break;
    case VAL_A_RRSIG_VERIFY_FAILED:
        return "VAL_A_RRSIG_VERIFY_FAILED";
        break;
    case VAL_A_NOT_VERIFIED:
        return "VAL_A_NOT_VERIFIED";
        break;
    case VAL_A_KEY_TOO_LARGE:
        return "VAL_A_KEY_TOO_LARGE";
        break;
    case VAL_A_KEY_TOO_SMALL:
        return "VAL_A_KEY_TOO_SMALL";
        break;
    case VAL_A_KEY_NOT_AUTHORIZED:
        return "VAL_A_KEY_NOT_AUTHORIZED";
        break;
    case VAL_A_ALGO_REFUSED:
        return "VAL_A_ALGO_REFUSED";
        break;
    case VAL_A_NO_PREFERRED_SEP:
        return "VAL_A_NO_PREFERRED_SEP";
        break;
    case VAL_A_RRSIG_ALGO_MISMATCH:
        return "VAL_A_RRSIG_ALGO_MISMATCH";
        break;
    case VAL_A_VERIFIED:
        return "VAL_A_VERIFIED";
        break;
    case VAL_A_VERIFIED_LINK:
        return "VAL_A_VERIFIED_LINK";
        break;
    case VAL_A_UNKNOWN_ALGO_LINK:
        return "VAL_A_UNKNOWN_ALGO_LINK";
        break;
    case VAL_A_LOCAL_ANSWER:
        return "VAL_A_LOCAL_ANSWER";
        break;
    case VAL_A_SIGNING_KEY:
        return "VAL_A_SIGNING_KEY";
        break;
    case VAL_A_TRUST_KEY:
        return "VAL_A_TRUST_KEY";
        break;
    case VAL_A_TRUST_ZONE:
        return "VAL_A_TRUST_ZONE";
        break;
    case VAL_A_PROVABLY_UNSECURE:
        return "VAL_A_PROVABLY_UNSECURE";
        break;
    case VAL_A_BARE_RRSIG:
        return "VAL_A_BARE_RRSIG";
        break;


    case VAL_A_DONT_VALIDATE:
        return "VAL_A_DONT_VALIDATE";
        break;

    case VAL_A_UNSET:
        return "VAL_A_UNSET";
        break;

        /*
         * case VAL_A_UNAUTHORIZED_SIGNER: return "UNAUTHORIZED_SIGNER"; break;
         * case VAL_A_CONFLICTING_PROOFS: return "CONFLICTING_PROOFS"; break;
         * case VAL_A_OVERREACHING_NSEC: return "OVERREACHING_NSEC"; break;
         * case VAL_A_DNSSEC_VERSION_ERROR: return "VAL_A_DNSSEC_VERSION_ERROR"; break;
         */
    default:
        if ((err >= VAL_A_DNS_ERROR_BASE) && (err < VAL_A_DNS_ERROR_LAST)) {
            int             errbase = VAL_A_DNS_ERROR_BASE;
            int             dnserr = err - errbase + Q_ERROR_BASE;
            return p_query_error(dnserr);
        } else if (err < VAL_A_LAST_STATE)
            return "UNEVALUATED";
        return "Unknown Error Value";
    }
}

const char     *
p_val_error(val_status_t err)
{
    switch (err) {

    case VAL_R_DONT_KNOW:
    case VAL_R_TRUST_FLAG | VAL_R_DONT_KNOW:
        return "Uninitialized";
        break;
    case VAL_INDETERMINATE:
    case VAL_R_TRUST_FLAG | VAL_INDETERMINATE:
        return "VAL_INDETERMINATE";
        break;
    case VAL_BOGUS:
    case VAL_R_TRUST_FLAG | VAL_BOGUS:
        return "VAL_BOGUS";
        break;
    case VAL_LOCAL_ANSWER:
    case VAL_R_TRUST_FLAG | VAL_LOCAL_ANSWER:
        return "VAL_LOCAL_ANSWER";
        break;
    case VAL_BARE_RRSIG:
    case VAL_R_TRUST_FLAG | VAL_BARE_RRSIG:
        return "VAL_BARE_RRSIG";
        break;
    case VAL_NONEXISTENT_NAME:
    case VAL_R_TRUST_FLAG | VAL_NONEXISTENT_NAME:
        return "VAL_NONEXISTENT_NAME";
        break;
    case VAL_NONEXISTENT_TYPE:
    case VAL_R_TRUST_FLAG | VAL_NONEXISTENT_TYPE:
        return "VAL_NONEXISTENT_TYPE";
        break;
    case VAL_ERROR:
    case VAL_R_TRUST_FLAG | VAL_ERROR:
        return "VAL_ERROR";
        break;
    case VAL_PROVABLY_UNSECURE:
        return "VAL_PROVABLY_UNSECURE";
        break;
    case VAL_NOTRUST:
        return "VAL_NOTRUST";
        break;
    case VAL_SUCCESS:
        return "VAL_SUCCESS";
        break;

    default:
        if ((err >= VAL_DNS_ERROR_BASE) && (err < VAL_DNS_ERROR_LAST)) {
            int             errbase = VAL_DNS_ERROR_BASE;
            int             dnserr = err - errbase + Q_ERROR_BASE;
            return p_query_error(dnserr);
        }
        return "Unknown Error Value";
    }
}

static void
val_log_insert(val_log_t * logp)
{
    val_log_t      *tmp_log;

    if (NULL == logp)
        return;

    for (tmp_log = log_head; tmp_log && tmp_log->next;
         tmp_log = tmp_log->next);

    if (NULL == tmp_log)
        log_head = logp;
    else
        tmp_log->next = logp;
}

void
val_log_udp(val_log_t * logp, const val_context_t * ctx, int level,
            const char *template, va_list ap)
{
    /** Needs to be at least two characters larger than message size */
    char            buf[1028];
    int             length = sizeof(struct sockaddr_in);

    if (NULL == logp)
        return;

    /** We allocated extra space  */
    vsnprintf(buf, sizeof(buf) - 2, template, ap);
    strcat(buf, "\n");
    
    sendto(logp->opt.udp.sock, buf, strlen(buf),0,
           (struct sockaddr *)&logp->opt.udp.server,length);

    return;
}

void
val_log_filep(val_log_t * logp, const val_context_t * ctx, int level,
              const char *template, va_list ap)
{
    if (NULL == logp)
        return;

    if (NULL == logp->opt.file.fp) {
        logp->opt.file.fp = fopen(logp->opt.file.name, "a");
        if (NULL == logp->opt.file.fp)
            return;
    }
    vfprintf(logp->opt.file.fp, template, ap);
    fprintf(logp->opt.file.fp, "\n");
}

void
val_log_syslog(val_log_t * logp, const val_context_t * ctx, int level,
               const char *template, va_list ap)
{
    /*
     * Needs to be at least two characters larger than message size 
     */
    char            buf[sizeof("libval(0000000000000000)..")];

    snprintf(buf, sizeof(buf), "libval(%s)",
             (ctx == NULL) ? "0" : ctx->id);
    openlog(buf, VAL_LOG_OPTIONS, logp->opt.syslog.facility);

    vsyslog(logp->opt.syslog.facility | level, template, ap);
}

val_log_t      *
val_log_create_logp(int level)
{
    val_log_t      *logp;

    logp = MALLOC(sizeof(val_log_t));
    if (NULL == logp)
        return NULL;
    memset(logp, 0, sizeof(val_log_t));

    if (level < 0)
        logp->level = debug_level;
    else if (level > LOG_DEBUG)
        logp->level = LOG_DEBUG;
    else
        logp->level = level;

    return logp;
}

val_log_t      *
val_log_add_udp(int level, char *host, int port)
{
    val_log_t      *logp;

    if ((NULL == host) || (0 == port))
        return NULL;

    logp = val_log_create_logp(level);
    if (NULL == logp)
        return NULL;

    if (-1 == logp->opt.udp.sock) {
        logp->opt.udp.sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (logp->opt.udp.sock < 0) {
            FREE(logp);
            return NULL;
        }
    }

    logp->opt.udp.server.sin_family = AF_INET;
    logp->opt.udp.server.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &logp->opt.udp.server.sin_addr) <= 0) {
        close(logp->opt.udp.sock);
        FREE(logp);
        logp = NULL;
    }

    return logp;
}

val_log_t      *
val_log_add_filep(int level, FILE * p)
{
    val_log_t      *logp;

    if (NULL == p)
        return NULL;

    logp = val_log_create_logp(level);
    if (NULL == logp)
        return NULL;

    logp->opt.file.fp = p;
    logp->logf = val_log_filep;

    val_log_insert(logp);

    return logp;
}

val_log_t      *
val_log_add_file(int level, const char *filen)
{
    val_log_t      *logp;
    FILE           *filep;

    if (NULL == filen)
        return NULL;

    filep = fopen(filen, "a");

    logp = val_log_add_filep(level, filep);
    if (NULL == logp)
        fclose(filep);

    return logp;
}

val_log_t      *
val_log_add_syslog(int level, int facility)
{
    val_log_t      *logp;

    logp = val_log_create_logp(level);
    if (NULL == logp)
        return NULL;

    logp->opt.syslog.facility = facility;
    logp->logf = val_log_syslog;

    val_log_insert(logp);

    return logp;
}

val_log_t      *
val_log_add_optarg(char *str, int use_stderr)
{
    val_log_t      *logp;
    char           *l;
                /** assume we can write to string */
    int             level;

    if (NULL == str)
        return NULL;

    l = strchr(str, ':');
    if ((NULL == l) || (0 == l[1])) {
        if (use_stderr)
            fprintf(stderr, "unknown output format string\n");
        return NULL;
    }
    *l++ = 0;
    level = atoi(str);
    str = l;

    switch (*str) {

    case 'f':                  /* file */
        l = strchr(str, ':');
        if ((NULL == l) || (0 == l[1])) {
            if (use_stderr)
                fprintf(stderr, "file requires a filename parameter\n");
            return NULL;
        }
        str = ++l;
        logp = val_log_add_file(level, str);
        break;

    case 's':                  /* stderr|stdout */
        if (0 == strcmp(str, "stderr"))
            logp = val_log_add_filep(level, stderr);
        else if (0 == strcmp(str, "stdout"))
            logp = val_log_add_filep(level, stdout);
        else if (0 == strcmp(str, "syslog")) {
            int             facility;
            l = strchr(str, ':');
            if ((NULL != l) && (0 != l[1])) {
                str = ++l;
                facility = atoi(str) << 3;
            } else
                facility = LOG_USER;
            logp = val_log_add_syslog(level, facility);
        } else {
            if (use_stderr)
                fprintf(stderr, "unknown output format string\n");
            return NULL;
        }
        break;

    case 'n':                  /* net/udp */
        {
            char           *host;
            int             port;

            l = strchr(str, ':');
            if ((NULL == l) || (0 == l[1])) {
                if (use_stderr)
                    fprintf(stderr, "net requires a host parameter\n");
                return NULL;
            }
            host = str = ++l;

            l = strchr(str, ':');
            if ((NULL == l) || (0 == l[1])) {
                if (use_stderr)
                    fprintf(stderr, "net requires a port parameter\n");
                return NULL;
            }
            *l++ = 0;
            port = atoi(str);

            logp = val_log_add_udp(level, host, port);
        }
        break;

    default:
        fprintf(stderr, "unknown output format type\n");
        return NULL;
    }

    return logp;
}

void
val_log(const val_context_t * ctx, int level, const char *template, ...)
{
    va_list         ap;
    val_log_t      *logp = log_head;

    if (NULL == template)
        return;

    for (; NULL != logp; logp = logp->next) {

        /** check individual level */
        if ((level > logp->level) || (NULL == logp->logf))
            continue;

        va_start(ap, template);
        (*logp->logf) (logp, ctx, level, template, ap);
        va_end(ap);
    }
}
