
/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
/*
 * DESCRIPTION
 * Contains the implementation for the logging functionality in libval
 */
#include "validator-internal.h"

#include "val_cache.h"
#include "val_support.h"
#include "val_parse.h"
#include "val_crypto.h"

static int      debug_level = LOG_INFO;
static val_log_t *default_log_head = NULL;

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

int
val_log_highest_debug_level(void)
{
    val_log_t      *tmp_log;
    int             level = 0;

    for (tmp_log = default_log_head; tmp_log; tmp_log = tmp_log->next)
        if (tmp_log->level > level)
            level = tmp_log->level;

    return level;
}

char           *
get_hex_string(const u_char *data, size_t datalen, char *buf,
               size_t buflen)
{
    size_t             i;
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
        if (ptr >= endptr) {
            strncpy(buf, "ERR:BadHash", buflen);
            return buf;
        }
        snprintf(ptr, endptr - ptr, "%02x", data[i]);
        ptr += strlen(ptr);
    }

    return buf;
}

static char    *
get_rr_string(struct val_rr_rec *rr, char *buf, size_t buflen)
{
    char           *ptr = buf;
    char           *endptr = ptr + buflen;
    while (rr) {
        get_hex_string(rr->rr_rdata, rr->rr_rdata_length, ptr,
                       endptr - ptr);
        ptr += strlen(ptr);
        rr = rr->rr_next;
    }

    return buf;
}

void
val_log_val_rrset_pfx(const val_context_t * ctx, int level,
                      const char *pfx, struct val_rrset_rec *val_rrset_rec)
{
    char            buf1[2049], buf2[2049];

    if (!val_rrset_rec)
        return;

    val_log(ctx, level, "%srrs->val_rrset_name=%s rrs->val_rrset_type=%s "
            "rrs->val_rrset_class=%s rrs->val_rrset_ttl=%d "
            "rrs->val_rrset_section=%s\nrrs->val_rrset_data=%s\n"
            "rrs->val_rrset_sig=%s", pfx ? pfx : "", 
            val_rrset_rec->val_rrset_name,
            p_type(val_rrset_rec->val_rrset_type),
            p_class(val_rrset_rec->val_rrset_class),
            val_rrset_rec->val_rrset_ttl,
            p_section(val_rrset_rec->val_rrset_section - 1, !ns_o_update),
            get_rr_string(val_rrset_rec->val_rrset_data, buf1, 2048),
            get_rr_string(val_rrset_rec->val_rrset_sig, buf2, 2048));
}

static const char *
get_algorithm_string(u_char algo)
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
val_log_rrsig_rdata(const val_context_t * ctx, int level,
                    const char *prefix, val_rrsig_rdata_t * rdata)
{
    char            ctime_buf1[1028], ctime_buf2[1028];
    char            buf[1028];
    struct timeval  tv_sig1, tv_sig2;

    if (rdata) {
        if (!prefix)
            prefix = "";

        memset(&tv_sig1, 0, sizeof(tv_sig1));
        memset(&tv_sig2, 0, sizeof(tv_sig2));
        tv_sig1.tv_sec = rdata->sig_expr; 
        tv_sig2.tv_sec = rdata->sig_incp; 

        GET_TIME_BUF((const time_t *)(&tv_sig1.tv_sec), ctime_buf1);
        GET_TIME_BUF((const time_t *)(&tv_sig2.tv_sec), ctime_buf2);

        val_log(ctx, level, "%s Type=%d Algo=%d[%s] Labels=%d OrgTTL=%d "
                "SigExp=%s SigIncp=%s KeyTag=%d[0x %04x] Signer=%s Sig=%s",
                prefix, rdata->algorithm,
                get_algorithm_string(rdata->algorithm), rdata->labels,
                rdata->orig_ttl,
                ctime_buf1, ctime_buf2,
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

const char    *
val_get_ns_string(struct sockaddr *serv, char *dst, size_t size)
{
    struct sockaddr_in *sin;
#ifdef VAL_IPV6
    struct sockaddr_in6 *sin6;
#endif
    struct sockaddr_storage *server;
    const char *addr = NULL;

    if ((serv == NULL) || (dst == NULL))
        return NULL;

    server = (struct sockaddr_storage *) serv;

    switch (server->ss_family) {
    case AF_INET:
        sin = (struct sockaddr_in *) server;
        INET_NTOP(AF_INET, ((struct sockaddr *)sin), 
            sizeof(struct sockaddr_in), dst, size, addr);
        return addr;
#ifdef VAL_IPV6
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) server;
        INET_NTOP(AF_INET6, ((struct sockaddr *)sin6), 
            sizeof(struct sockaddr_in), dst, size, addr);
        return addr;
#endif
    }
    return NULL;
}

void
val_log_assertion_pfx(const val_context_t * ctx, int level,
                      const char *prefix, const char * name_pr,
                      struct val_authentication_chain *next_as)
{
    char            name_buf[INET6_ADDRSTRLEN + 1];
    const char     *serv_pr;
    int             tag = 0;
    int             class_h;
    int             type_h;
    struct          val_rr_rec  *data;
    struct          sockaddr *serv;
    val_astatus_t   status;
    struct val_rr_rec  *curkey;
#undef VAL_LOG_SIG
#ifdef VAL_LOG_SIG
    struct          val_rr_rec  *sig;
    struct val_rr_rec  *cursig;
#endif


    if (next_as == NULL)
        return;

    class_h = next_as->val_ac_rrset->val_rrset_class;
    type_h = next_as->val_ac_rrset->val_rrset_type;
    data = next_as->val_ac_rrset->val_rrset_data;
#ifdef VAL_LOG_SIG
    sig = next_as->val_ac_rrset->val_rrset_sig;
#endif
    serv = next_as->val_ac_rrset->val_rrset_server;
    status = next_as->val_ac_status;

    if (NULL == prefix)
        prefix = "";

    if (serv)
        serv_pr =
            ((serv_pr =
              val_get_ns_string(serv, name_buf, sizeof(name_buf))) == NULL) ?  "VAL_CACHE" : serv_pr;
    else
        serv_pr = "NULL";

    if (type_h == ns_t_dnskey) {
        for (curkey = data; curkey; curkey = curkey->rr_next) {
            if ((curkey->rr_status == VAL_AC_VERIFIED_LINK) ||
                (curkey->rr_status == VAL_AC_TRUST_POINT) ||
                (curkey->rr_status == VAL_AC_UNKNOWN_ALGORITHM_LINK)) {
                /*
                 * Extract the key tag 
                 */
                val_dnskey_rdata_t dnskey;
                if (VAL_NO_ERROR != val_parse_dnskey_rdata(curkey->rr_rdata,
                                       curkey->rr_rdata_length, &dnskey)) {
                    val_log(ctx, LOG_INFO, "val_log_assertion_pfx(): Cannot parse DNSKEY data");
                } else {
                    tag = dnskey.key_tag;
                    if (dnskey.public_key)
                        FREE(dnskey.public_key);
                }
                break;
            }
        }
    }

    if (tag != 0) {
        val_log(ctx, level,
                "%sname=%s class=%s type=%s[tag=%d] from-server=%s "
                "status=%s:%d", prefix, name_pr, p_class(class_h),
                p_type(type_h), tag, serv_pr, p_ac_status(status), status);
    } else {
        val_log(ctx, level,
                "%sname=%s class=%s type=%s from-server=%s status=%s:%d",
                prefix, name_pr, p_class(class_h), p_type(type_h), serv_pr,
                p_ac_status(status), status);
    }
#ifdef VAL_LOG_SIG
    for (cursig = sig; cursig; cursig = cursig->rr_next) {
        char incpTime[1028];
        char exprTime[1028];
        struct timeval  tv_sig;
        val_rrsig_rdata_t rrsig;

        val_parse_rrsig_rdata(cursig->rr_rdata, cursig->rr_rdata_length, &rrsig);

        memset(&tv_sig, 0, sizeof(tv_sig));
        tv_sig.tv_sec = rrsig.sig_incp;
        GET_TIME_BUF((const time_t *)(&tv_sig.tv_sec), incpTime);

        memset(&tv_sig, 0, sizeof(tv_sig));
        tv_sig.tv_sec = rrsig.sig_expr;
        GET_TIME_BUF((const time_t *)(&tv_sig.tv_sec), exprTime);

        val_log(ctx, level,
                "%s    ->tag=%d status=%s sig-incep=%s sig-expr=%s",
                prefix, rrsig.key_tag,
                p_ac_status(cursig->rr_status),
                incpTime, exprTime);
    }
#endif

#ifdef VAL_LOG_SIG
    struct val_rr_rec  *rr;
    struct val_rr_rec  *sig = next_as->val_ac_rrset->val_rrset_sig;
    for (rr = data; rr; rr = rr->rr_next) {
        val_log(ctx, level, "    data_status=%s:%d",
                p_ac_status(rr->rr_status), rr->rr_status);
    }
    for (rr = sig; rr; rr = rr->rr_next) {
        val_log(ctx, level, "    sig_status=%s:%d",
                p_ac_status(rr->rr_status), rr->rr_status);
    }
#endif
}

void
val_log_assertion(const val_context_t * ctx, int level,
                  const char * name,
                  struct val_authentication_chain *next_as)
{
    val_log_assertion_pfx(ctx, level, NULL, name, next_as);
}

void
val_log_authentication_chain(const val_context_t * ctx, int level,
                             const char * name_p, int class_h,
                             int type_h,
                             struct val_result_chain *results)
{
    struct val_result_chain *next_result;
    int real_type_h;
    int real_class_h;

    if (results == NULL) { 
        return;
    } 
    
    for (next_result = results; next_result;
         next_result = next_result->val_rc_next) {
        struct val_authentication_chain *next_as;
        int             i;

        /* Display the correct owner name, class,type for the record */
        if (next_result->val_rc_rrset) {
            real_type_h = next_result->val_rc_rrset->val_rrset_type; 
            real_class_h = next_result->val_rc_rrset->val_rrset_class; 
        } else {
            real_type_h = type_h;
            real_class_h = class_h;
        }

        if (val_isvalidated(next_result->val_rc_status)) {
            val_log(ctx, level, "Validation result for {%s, %s(%d), %s(%d)}: %s:%d (Validated)",
                    name_p, p_class(real_class_h), real_class_h,
                    p_type(real_type_h), real_type_h,
                    p_val_status(next_result->val_rc_status),
                    next_result->val_rc_status);
        } else if (val_istrusted(next_result->val_rc_status)) {
            val_log(ctx, level, "Validation result for {%s, %s(%d), %s(%d)}: %s:%d (Trusted but not Validated)",
                    name_p, p_class(real_class_h), real_class_h,
                    p_type(real_type_h), real_type_h,
                    p_val_status(next_result->val_rc_status),
                    next_result->val_rc_status);
        } else {
            val_log(ctx, level, "Validation result for {%s, %s(%d), %s(%d)}: %s:%d (Untrusted)",
                    name_p, p_class(real_class_h), real_class_h,
                    p_type(real_type_h), real_type_h,
                    p_val_status(next_result->val_rc_status),
                    next_result->val_rc_status);
        }

        for (next_as = next_result->val_rc_answer; next_as;
             next_as = next_as->val_ac_trust) {

            if (next_as->val_ac_rrset == NULL) {
                val_log(ctx, level, "    Assertion status = %s:%d",
                        p_ac_status(next_as->val_ac_status),
                        next_as->val_ac_status);
            } else {
                const char   *t_name;
                t_name = next_as->val_ac_rrset->val_rrset_name;
                if (t_name == NULL)
                    t_name = (const char *) "NULL_DATA";

                val_log_assertion_pfx(ctx, level, "    ", t_name,
                                      next_as);
                //                val_log_val_rrset_pfx(ctx, level, "     ",
                //                                  next_as->val_ac_rrset);
            }
        }

        for (i = 0; i < next_result->val_rc_proof_count; i++) {
            val_log(ctx, level, "    Proof of non-existence [%d of %d]", 
                    i+1, next_result->val_rc_proof_count);
            for (next_as = next_result->val_rc_proofs[i]; next_as;
                 next_as = next_as->val_ac_trust) {
                if (next_as->val_ac_rrset == NULL) {
                    val_log(ctx, level, "      Assertion status = %s:%d",
                            p_ac_status(next_as->val_ac_status),
                            next_as->val_ac_status);
                } else {
                    const char   *t_name;
                    t_name = next_as->val_ac_rrset->val_rrset_name;
                    if (t_name == NULL)
                        t_name = (const char *) "NULL_DATA";

                    val_log_assertion_pfx(ctx, level, "      ", t_name,
                                          next_as);
                }
            }
        }
    }
}

const char     *
p_query_status(int err)
{
    switch (err) {
        case Q_INIT:
            return "Q_INIT";
        case Q_SENT:
            return "Q_SENT";
        case Q_ANSWERED:
            return "Q_ANSWERED";
        case (Q_WAIT_FOR_A_GLUE|Q_WAIT_FOR_AAAA_GLUE):
        case Q_WAIT_FOR_A_GLUE:
        case Q_WAIT_FOR_AAAA_GLUE:
            return "Q_WAIT_FOR_GLUE";
        case Q_QUERY_ERROR:
            return "Q_QUERY_ERROR";
        case Q_RESPONSE_ERROR:
            return "Q_RESPONSE_ERROR";
        case Q_WRONG_ANSWER:
            return "Q_WRONG_ANSWER";
        case Q_REFERRAL_ERROR:
            return "Q_REFERRAL_ERROR";
        case Q_MISSING_GLUE:
            return "Q_MISSING_GLUE";
        case Q_CONFLICTING_ANSWERS:
            return "Q_CONFLICTING_ANSWERS";
        default:
            break;
    }

    return "UNKNOWN";
}

const char     *
p_ac_status(val_astatus_t err)
{
    switch (err) {

    case VAL_AC_IGNORE_VALIDATION:
        return "VAL_AC_IGNORE_VALIDATION";
        break;
    case VAL_AC_UNTRUSTED_ZONE:
        return "VAL_AC_UNTRUSTED_ZONE";
        break;
    case VAL_AC_PINSECURE:
        return "VAL_AC_PINSECURE";
        break;
    case VAL_AC_BARE_RRSIG:
        return "VAL_AC_BARE_RRSIG";
        break;
    case VAL_AC_NO_LINK:
        return "VAL_AC_NO_LINK";
        break;
    case VAL_AC_TRUST:
        return "VAL_AC_TRUST";
        break;

    case VAL_AC_RRSIG_MISSING:
        return "VAL_AC_RRSIG_MISSING";
        break;
    case VAL_AC_DNSKEY_MISSING:
        return "VAL_AC_DNSKEY_MISSING";
        break;
    case VAL_AC_DS_MISSING:
        return "VAL_AC_DS_MISSING";
        break;
        
    case VAL_AC_DATA_MISSING:
        return "VAL_AC_DATA_MISSING";
        break;
    case VAL_AC_DNS_ERROR:
        return "VAL_AC_DNS_ERROR";
        break;
        
    case VAL_AC_NOT_VERIFIED:
        return "VAL_AC_NOT_VERIFIED";
        break;
    case VAL_AC_WRONG_LABEL_COUNT:
        return "VAL_AC_WRONG_LABEL_COUNT";
        break;
    case VAL_AC_INVALID_RRSIG:
        return "VAL_AC_INVALID_RRSIG";
        break;
    case VAL_AC_RRSIG_NOTYETACTIVE:
        return "VAL_AC_RRSIG_NOTYETACTIVE";
        break;
    case VAL_AC_RRSIG_EXPIRED:
        return "VAL_AC_RRSIG_EXPIRED";
        break;
    case VAL_AC_RRSIG_VERIFY_FAILED:
        return "VAL_AC_RRSIG_VERIFY_FAILED";
        break;
    case VAL_AC_RRSIG_ALGORITHM_MISMATCH:
        return "VAL_AC_RRSIG_ALGORITHM_MISMATCH";
        break;
    case VAL_AC_DNSKEY_NOMATCH:
        return "VAL_AC_DNSKEY_NOMATCH";
        break;
    case VAL_AC_UNKNOWN_DNSKEY_PROTOCOL:
        return "VAL_AC_UNKNOWN_DNSKEY_PROTOCOL";
        break;
    case VAL_AC_DS_NOMATCH:
        return "VAL_AC_DS_NOMATCH";
        break;
    case VAL_AC_INVALID_KEY:
        return "VAL_AC_INVALID_KEY";
        break;
    case VAL_AC_INVALID_DS:
        return "VAL_AC_INVALID_KEY";
        break;
    case VAL_AC_ALGORITHM_NOT_SUPPORTED:
        return "VAL_AC_ALGORITHM_NOT_SUPPORTED";
        break;

    case VAL_AC_VERIFIED:
        return "VAL_AC_VERIFIED";
        break;
    case VAL_AC_RRSIG_VERIFIED:
        return "VAL_AC_RRSIG_VERIFIED";
        break;
    case VAL_AC_WCARD_VERIFIED:
        return "VAL_AC_WCARD_VERIFIED";
        break;
    case VAL_AC_RRSIG_VERIFIED_SKEW:
        return "VAL_AC_RRSIG_VERIFIED_SKEW";
        break;
    case VAL_AC_WCARD_VERIFIED_SKEW:
        return "VAL_AC_WCARD_VERIFIED_SKEW";
        break;
    case VAL_AC_TRUST_POINT:
        return "VAL_AC_TRUST_POINT";
        break;
    case VAL_AC_SIGNING_KEY:
        return "VAL_AC_SIGNING_KEY";
        break;
    case VAL_AC_VERIFIED_LINK:
        return "VAL_AC_VERIFIED_LINK";
        break;
    case VAL_AC_UNKNOWN_ALGORITHM_LINK:
        return "VAL_AC_UNKNOWN_ALGORITHM_LINK";
        break;

    default:
        return "UNEVALUATED";
    }
}

const char     *
p_val_status(val_status_t err)
{
    switch (err) {

    case VAL_BOGUS:
        return "VAL_BOGUS";
        break;
    case VAL_DNS_ERROR:
        return "VAL_DNS_ERROR";
        break;
    case VAL_NOTRUST:
        return "VAL_NOTRUST";
        break;
    case VAL_SUCCESS:
        return "VAL_SUCCESS";
        break;
    case VAL_NONEXISTENT_NAME:
        return "VAL_NONEXISTENT_NAME";
        break;
    case VAL_NONEXISTENT_TYPE:
        return "VAL_NONEXISTENT_TYPE";
        break;
    case VAL_NONEXISTENT_NAME_NOCHAIN:
        return "VAL_NONEXISTENT_NAME_NOCHAIN";
        break;
    case VAL_NONEXISTENT_TYPE_NOCHAIN:
        return "VAL_NONEXISTENT_TYPE_NOCHAIN";
        break;
    case VAL_PINSECURE:
        return "VAL_PINSECURE";
        break;
    case VAL_PINSECURE_UNTRUSTED:
        return "VAL_PINSECURE_UNTRUSTED";
        break;
    case VAL_BARE_RRSIG:
        return "VAL_BARE_RRSIG";
        break;
    case VAL_IGNORE_VALIDATION:
        return "VAL_IGNORE_VALIDATION";
        break;
    case VAL_UNTRUSTED_ZONE:
        return "VAL_UNTRUSTED_ZONE";
        break;
    case VAL_OOB_ANSWER:
        return "VAL_OOB_ANSWER";
        break;

    case VAL_TRUSTED_ANSWER:
        return "VAL_TRUSTED_ANSWER";
        break;
    case VAL_VALIDATED_ANSWER:
        return "VAL_VALIDATED_ANSWER";
        break;
    case VAL_UNTRUSTED_ANSWER:
        return "VAL_UNTRUSTED_ANSWER";
        break;

    default:
        return "Unknown Error Value";
    }
}

const char     *
p_val_err(int err) {
    
    switch (err) {
        case VAL_NO_ERROR:
           return "VAL_NO_ERROR";
           break;

        case VAL_NOT_IMPLEMENTED: 
           return "VAL_NOT_IMPLEMENTED";
           break;

        case VAL_RESOURCE_UNAVAILABLE:
           return "VAL_RESOURCE_UNAVAILABLE"; 
           break;

        case VAL_BAD_ARGUMENT:
           return "VAL_BAD_ARGUMENT";
           break;

        case VAL_INTERNAL_ERROR:
           return "VAL_INTERNAL_ERROR";
           break;

        case VAL_NO_PERMISSION:
           return "VAL_NO_PERMISSION";
           break;

        case VAL_CONF_PARSE_ERROR:
           return "VAL_CONF_PARSE_ERROR";
           break;

        case VAL_CONF_NOT_FOUND:
           return "VAL_CONF_NOT_FOUND";
           break;
                       
        case VAL_NO_POLICY:
           return "VAL_NO_POLICY";
           break;

    }

    return "Unknown Error Code";
}



/* *********************************************************************
 *
 * Logging output
 *
 * *********************************************************************/

static void
val_log_insert(val_log_t **log_head, val_log_t * logp)
{
    val_log_t      *tmp_log;

    if (NULL == logp)
        return;

    if (log_head == NULL)
        log_head = &default_log_head;

    for (tmp_log = *log_head; tmp_log && tmp_log->next;
         tmp_log = tmp_log->next);

    if (NULL == tmp_log)
        *log_head = logp;
    else
        tmp_log->next = logp;
}

void
val_log_callback(val_log_t * logp, const val_context_t * ctx, int level,
            const char *template, va_list ap)
{
    /** Needs to be at least two characters larger than message size */
    char            buf[1028];

    if (NULL == logp)
        return;

    res_gettimeofday_buf(buf, sizeof(buf) - 2);
    vsnprintf(&buf[19], sizeof(buf) - 21, template, ap);

    (*(logp->opt.cb.func))(logp, level, buf);

    return;
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

    res_gettimeofday_buf(buf, sizeof(buf) - 2);
    vsnprintf(&buf[19], sizeof(buf) - 21, template, ap);
    strcat(buf, "\n");

    sendto(logp->opt.udp.sock, buf, strlen(buf), 0,
           (struct sockaddr *) &logp->opt.udp.server, length);

    return;
}

void
val_log_filep(val_log_t * logp, const val_context_t * ctx, int level,
              const char *template, va_list ap)
{
    char            buf[1028];

    if (NULL == logp)
        return;

    res_gettimeofday_buf(buf, sizeof(buf) - 2);
    if (NULL == logp->opt.file.fp) {
        logp->opt.file.fp = fopen(logp->opt.file.name, "a");
        if (NULL == logp->opt.file.fp)
            return;
    }
    vsnprintf(&buf[19], sizeof(buf) - 21, template, ap);

    fprintf(logp->opt.file.fp, "%s\n", buf);
    fflush(logp->opt.file.fp);
}

#ifdef HAVE_SYSLOG_H
void
val_log_syslog(val_log_t * logp, const val_context_t * ctx, int level,
               const char *template, va_list ap)
{
    /*
     * Needs to be at least two characters larger than message size 
     */
    char            buf[1028];

    res_gettimeofday_buf(buf, sizeof(buf) - 2);
    snprintf(&buf[19], sizeof(buf) - 21, " libval(%s)",
            (ctx == NULL) ? "0" : ctx->id);

    openlog(buf, VAL_LOG_OPTIONS, logp->opt.syslog.facility);

    vsyslog(logp->opt.syslog.facility | level, template, ap);
}
#endif

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
val_log_add_udp(val_log_t **log_head, int level, char *host, int port)
{
    val_log_t      *logp;

    if ((NULL == host) || (0 == port))
        return NULL;

    logp = val_log_create_logp(level);
    if (NULL == logp)
        return NULL;

    if (-1 == logp->opt.udp.sock) {
        logp->opt.udp.sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (logp->opt.udp.sock == INVALID_SOCKET) {
            FREE(logp);
            return NULL;
        }
    }

    logp->opt.udp.server.sin_family = AF_INET;
    logp->opt.udp.server.sin_port = htons(port);
    if (INET_PTON(AF_INET, host, ((struct sockaddr *)(&logp->opt.udp.server)), 
                sizeof(logp->opt.udp.server)) <= 0) {
        CLOSESOCK(logp->opt.udp.sock);
        FREE(logp);
        logp = NULL;
    }

    logp->logf = val_log_udp;
    val_log_insert(log_head, logp);

    return logp;
}

val_log_t      *
val_log_add_cb(val_log_t **log_head, int level, val_log_cb_t func)
{
    val_log_t      *logp;

    if (NULL == func)
        return NULL;

    logp = val_log_create_logp(level);
    if (NULL == logp)
        return NULL;

    logp->opt.cb.func = func;
    logp->logf = val_log_callback;

    val_log_insert(log_head, logp);

    return logp;
}

val_log_t      *
val_log_add_filep(val_log_t **log_head, int level, FILE * p)
{
    val_log_t      *logp;

    if (NULL == p)
        return NULL;

    logp = val_log_create_logp(level);
    if (NULL == logp)
        return NULL;

    logp->opt.file.fp = p;
    logp->logf = val_log_filep;

    val_log_insert(log_head, logp);

    return logp;
}

val_log_t      *
val_log_add_file(val_log_t **log_head, int level, const char *filen)
{
    val_log_t      *logp;
    FILE           *filep;

    if (NULL == filen)
        return NULL;

    filep = fopen(filen, "a");

    logp = val_log_add_filep(log_head, level, filep);
    if (NULL == logp) {
        if (filep)
            fclose(filep);
    }

    return logp;
}

#ifdef HAVE_SYSLOG_H
val_log_t      *
val_log_add_syslog(val_log_t **log_head, int level, int facility)
{
    val_log_t      *logp;

    logp = val_log_create_logp(level);
    if (NULL == logp)
        return NULL;

    logp->opt.syslog.facility = facility;
    logp->logf = val_log_syslog;

    val_log_insert(log_head, logp);

    return logp;
}
#endif

/* Add log target to system list */
val_log_t      *
val_log_add_optarg(const char *str_in, int use_stderr)
{
    return val_log_add_optarg_to_list(&default_log_head, str_in, use_stderr);
}

/* Add log target to a given list */
val_log_t      *
val_log_add_optarg_to_list(val_log_t **log_head, const char *str_in, int use_stderr)
{
    val_log_t      *logp = NULL;
    char           *l, *copy, *str;
    int             level;

    if ((NULL == str_in) || (NULL == (copy = strdup(str_in))))
        return NULL;

    l = strchr(copy, ':');
    if ((NULL == l) || (0 == l[1])) {
        if (use_stderr)
            fprintf(stderr, "unknown output format string\n");
        goto err;
    }
    *l++ = 0;
    level = (int)strtol(copy, (char **)NULL, 10);
    str = l;

    switch (*str) {

    case 'f':                  /* file */
        l = strchr(str, ':');
        if ((NULL == l) || (0 == l[1])) {
            if (use_stderr)
                fprintf(stderr, "file requires a filename parameter\n");
            goto err;
        }
        str = ++l;
        logp = val_log_add_file(log_head, level, str);
        break;

    case 's':                  /* stderr|stdout */
        if (0 == strcmp(str, "stderr"))
            logp = val_log_add_filep(log_head, level, stderr);
        else if (0 == strcmp(str, "stdout"))
            logp = val_log_add_filep(log_head, level, stdout);
#ifdef HAVE_SYSLOG_H
        else if (0 == strcmp(str, "syslog")) {
            int             facility;
            l = strchr(str, ':');
            if ((NULL != l) && (0 != l[1])) {
                str = ++l;
                facility = ((int)strtol(str, (char **)NULL, 10)) << 3;
            } else
                facility = LOG_USER;
            logp = val_log_add_syslog(log_head, level, facility);
        }
#else
        else if (0 == strcmp(str, "syslog")) {
            fprintf(stderr, "syslog not supported on system.\n");
        }
#endif
        else {
            if (use_stderr)
                fprintf(stderr, "unknown output format string\n");
            goto err;
        }
        break;

    case 'n':                  /* net/udp */
        {
            char           *host;
            int             port;

            l = strchr(str, ':');
            if ((NULL == l) || (0 == l[1])) {
                goto err;
            }
            host = str = ++l;

            l = strchr(str, ':');
            if ((NULL == l) || (0 == l[1])) {
                if (use_stderr)
                    fprintf(stderr, "net requires a port parameter\n");
                goto err;
            }
            *l++ = 0;
            port = (int)strtol(str, (char **)NULL, 10);

            logp = val_log_add_udp(log_head, level, host, port);
        }
        break;

    default:
        fprintf(stderr, "unknown output format type\n");
        break;
    }

err:
    free(copy);
    return logp;

}


void
val_log_ap(const val_context_t * ctx, int level, const char *log_template,
           va_list ap)
{
    va_list         aq;
    val_log_t      *logp = default_log_head;

    if (NULL == log_template)
        return;

    for (; NULL != logp; logp = logp->next) {

        /** check individual level */
        if ((level > logp->level) || (NULL == logp->logf))
            continue;

        va_copy(aq, ap);
        (*logp->logf) (logp, ctx, level, log_template, aq);
        va_end(aq);
    }

    if (NULL == ctx)
        return;

    logp = ctx->val_log_targets;
    for (; NULL != logp; logp = logp->next) {

        /** check individual level */
        if ((level > logp->level) || (NULL == logp->logf))
            continue;

        va_copy(aq, ap);
        (*logp->logf) (logp, ctx, level, log_template, aq);
        va_end(aq);
    }
}

void
val_log(const val_context_t * ctx, int level, const char *format, ...)
{
    va_list         ap;
    val_log_t      *logp = default_log_head;

    if (NULL == format)
        return;

    for (; NULL != logp; logp = logp->next) {

        /** check individual level */
        if ((level > logp->level) || (NULL == logp->logf))
            continue;

        va_start(ap, format);
        (*logp->logf) (logp, ctx, level, format, ap);
        va_end(ap);
    }

    if (NULL == ctx)
        return;

    logp = ctx->val_log_targets;
    for (; NULL != logp; logp = logp->next) {

        /** check individual level */
        if ((level > logp->level) || (NULL == logp->logf))
            continue;

        va_start(ap, format);
        (*logp->logf) (logp, ctx, level, format, ap);
        va_end(ap);
    }
}
