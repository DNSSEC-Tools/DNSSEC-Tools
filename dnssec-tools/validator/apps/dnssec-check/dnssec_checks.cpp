#include <stdio.h>
#include <errno.h>
#include <string.h>

/*
 * NOTE:  Although this file is a .cpp file, the intent is for it to be fully
 *        "C" compatible.  IE, do NOT put any C++ required code in here.
 */

#define HAVE_DECL_NS_NTOP 1

#include <validator/validator-config.h>
#include "arpa/nameser.h"
#include "validator/resolver.h"
#include "validator/validator.h"
#include "resolv.h"

#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#elif ! defined( HAVE_ARPA_NAMESER_H )  && !defined(eabi) && !defined(ANDROID)
#include "arpa/header.h"
#endif

#define CHECK_SUCCEEDED 0
#define CHECK_FAILED    1
#define CHECK_WARNING   2

#define RETURN_CODE_BUF(code, msg, buffer, buffer_len)     \
    do {                                                   \
        strncpy(buffer, msg, buffer_len-1);                \
        buffer[buffer_len-1] = '\0';                       \
        return code;                                       \
    } while(0);

#define RETURN_ERROR(msg)                                  \
    RETURN_CODE_BUF(CHECK_FAILED, "Error: " msg, buf, buf_len);

#define RETURN_SUCCESS(msg)                                \
    RETURN_CODE_BUF(CHECK_SUCCEEDED, "Success: " msg, buf, buf_len);

#define RETURN_WARNING(msg)                                \
    RETURN_CODE_BUF(CHECK_WARNING, "Warning: " msg, buf, buf_len);

typedef struct basic_callback_data_s {
    char *domain;
    val_async_status *val_status;
    int *return_status;
} basic_callback_data;

int _check_basic_async_response(val_async_status *async_status, int event,
                                val_context_t *ctx, void *user_ctx,
                                val_cb_params_t *cbp) {

    basic_callback_data *data = (basic_callback_data *) user_ctx;

    if (!data->return_status)
        return 0;

    if (val_istrusted(cbp->val_status)) {
        *data->return_status = CHECK_SUCCEEDED;
    } else {
        *data->return_status = CHECK_FAILED;
    }

    return 0; /* OK */
}

int count = 0;
int check_basic_async(char *ns_name, char *buf, size_t buf_len, int *return_status) {
    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int found_a = 0;
    val_async_event_cb callback_info = &_check_basic_async_response;
    basic_callback_data *basic_async_data;

    ns_msg          handle;
    int             qdcount, ancount, nscount, arcount;
    u_int           opcode, rcode, id;
    ns_rr           rr;
    int             rrnum;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE;

    basic_async_data = (basic_callback_data *) malloc(sizeof(basic_callback_data));
    basic_async_data->domain = strdup("www.dnssec-tools.org");
    basic_async_data->val_status = 0;
    basic_async_data->return_status = return_status;
    count++;

    rc = val_async_submit(NULL, basic_async_data->domain, ns_c_in, ns_t_a, 0, callback_info,
                          basic_async_data, &basic_async_data->val_status);
}



int check_basic_dns(char *ns_name, char *buf, size_t buf_len, int *return_status) {
    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int found_a = 0;

    ns_msg          handle;
    int             qdcount, ancount, nscount, arcount;
    u_int           opcode, rcode, id;
    ns_rr           rr;
    int             rrnum;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE;

    rc = get("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("Basic DNS query failed entirely");

    if (ns_initparse(response, len, &handle) < 0)
        RETURN_ERROR("Fatal internal error: failed to init parser");

    opcode = libsres_msg_getflag(handle, ns_f_opcode);
    rcode = libsres_msg_getflag(handle, ns_f_rcode);
    id = ns_msg_id(handle);
    qdcount = ns_msg_count(handle, ns_s_qd);
    ancount = ns_msg_count(handle, ns_s_an);
    nscount = ns_msg_count(handle, ns_s_ns);
    arcount = ns_msg_count(handle, ns_s_ar);

    /* check the answer records for the DO bit in the response */
    rrnum = 0;
    for (;;) {
        if (ns_parserr(&handle, ns_s_an, rrnum, &rr)) {
            if (errno != ENODEV) {
                /* parse error */
                RETURN_ERROR("failed to parse a returned additional RRSET");
            }
            break; /* out of data */
        }
        if (ns_rr_type(rr) == ns_t_a) {
            found_a = 1;
            break;
        }
        rrnum++;
    }

    if (!found_a)
        RETURN_ERROR("No A record found using UDP in the basic DNS test.");

    RETURN_SUCCESS("An A record was successfully retrieved");
}

int check_basic_tcp(char *ns_name, char *buf, size_t buf_len, int *return_status) {
    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int found_a = 0;

    ns_msg          handle;
    int             qdcount, ancount, nscount, arcount;
    u_int           opcode, rcode, id;
    ns_rr           rr;
    int             rrnum;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE;

    rc = get_tcp("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
                 &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("basic TCP query failed entirely");

    if (ns_initparse(response, len, &handle) < 0)
        RETURN_ERROR("Fatal internal error: failed to init parser");

    opcode = libsres_msg_getflag(handle, ns_f_opcode);
    rcode = libsres_msg_getflag(handle, ns_f_rcode);
    id = ns_msg_id(handle);
    qdcount = ns_msg_count(handle, ns_s_qd);
    ancount = ns_msg_count(handle, ns_s_an);
    nscount = ns_msg_count(handle, ns_s_ns);
    arcount = ns_msg_count(handle, ns_s_ar);

    /* check the answer records for the DO bit in the response */
    rrnum = 0;
    for (;;) {
        if (ns_parserr(&handle, ns_s_an, rrnum, &rr)) {
            if (errno != ENODEV) {
                /* parse error */
                RETURN_ERROR("failed to parse a returned additional RRSET");
            }
            break; /* out of data */
        }
        if (ns_rr_type(rr) == ns_t_a) {
            found_a = 1;
            break;
        }
        rrnum++;
    }

    if (!found_a)
        RETURN_ERROR("No A record was found in the basic DNS test over TCP.");

    RETURN_SUCCESS("An A record was successfully retrieved over TCP");
}

int check_small_edns0(char *ns_name, char *buf, size_t buf_len, int *return_status) {
    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int found_edns0 = 0;

    ns_msg          handle;
    int             qdcount, ancount, nscount, arcount;
    u_int           opcode, rcode, id;
    ns_rr           rr;
    int             rrnum;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_edns0_size = 4096;
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE;

    rc = get("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("query failed entirely");

    if (ns_initparse(response, len, &handle) < 0)
        RETURN_ERROR("Fatal internal error: failed to init parser");

    opcode = libsres_msg_getflag(handle, ns_f_opcode);
    rcode = libsres_msg_getflag(handle, ns_f_rcode);
    id = ns_msg_id(handle);
    qdcount = ns_msg_count(handle, ns_s_qd);
    ancount = ns_msg_count(handle, ns_s_an);
    nscount = ns_msg_count(handle, ns_s_ns);
    arcount = ns_msg_count(handle, ns_s_ar);

    /* check the answer records for the DO bit in the response */
    rrnum = 0;
    for (;;) {
        if (ns_parserr(&handle, ns_s_ar, rrnum, &rr)) {
            if (errno != ENODEV) {
                /* parse error */
                RETURN_ERROR("failed to parse a returned additional RRSET");
            }
            break; /* out of data */
        }
        if (ns_rr_type(rr) == ns_t_opt) {
            u_int32_t       ttl = ns_rr_ttl(rr);

            found_edns0 = 1;

            if ((ttl >> 16 & 0xff) != 0)
                RETURN_ERROR("The EDNS version was not 0");

            found_edns0 = int(ns_rr_class(rr));

            break;
        }
        rrnum++;
    }

    if (!found_edns0)
        RETURN_ERROR("No EDNS0 record was found in the response but one was expected.");

    if (found_edns0 < 1500) {
        snprintf(buf, buf_len, "Warning: The returned EDNS0 size (%d) is smaller than recommended (1500)", found_edns0);
        return CHECK_WARNING;
    }

    snprintf(buf, buf_len, "Success: The returned EDNS0 size (%d) was reasonable.", found_edns0);
    return CHECK_SUCCEEDED;
}

int check_do_bit(char *ns_name, char *buf, size_t buf_len, int *return_status) {
    /* queries with the DO bit and thus should return an answer with
       the DO bit as well.  It should additionall have at least one
       RRSIG record. */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int found_edns0 = 0;

    ns_msg          handle;
    int             qdcount, ancount, nscount, arcount;
    u_int           opcode, rcode, id;
    ns_rr           rr;
    int             rrnum;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS| SR_QUERY_RECURSE;

    rc = get("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("Checking for the DO bit failed entirely: no response was received");

    if (ns_initparse(response, len, &handle) < 0)
        RETURN_ERROR("Fatal internal error: failed to init parser");

    opcode = libsres_msg_getflag(handle, ns_f_opcode);
    rcode = libsres_msg_getflag(handle, ns_f_rcode);
    id = ns_msg_id(handle);
    qdcount = ns_msg_count(handle, ns_s_qd);
    ancount = ns_msg_count(handle, ns_s_an);
    nscount = ns_msg_count(handle, ns_s_ns);
    arcount = ns_msg_count(handle, ns_s_ar);

    /* check the answer records for the DO bit in the response */
    rrnum = 0;
    for (;;) {
        if (ns_parserr(&handle, ns_s_ar, rrnum, &rr)) {
            if (errno != ENODEV) {
                /* parse error */
                RETURN_ERROR("failed to parse a returned additional RRSET");
            }
            break; /* out of data */
        }
        if (ns_rr_type(rr) == ns_t_opt) {
            u_int32_t       ttl = ns_rr_ttl(rr);

            found_edns0 = 1;

            if ((ttl >> 16 & 0xff) != 0)
                RETURN_ERROR("The EDNS version was not 0");

            if ((ttl & RES_USE_DNSSEC) == RES_USE_DNSSEC)
                RETURN_ERROR("The EDNS0 flag failed to include the expected DO bit");

            /* edns0 size = int(ns_rr_class(rr)) */
            break;
        }
        rrnum++;
    }

    if (!found_edns0)
        RETURN_ERROR("No EDNS0 record found in the response when one was expected.");

    free_name_server(&ns);
    RETURN_SUCCESS("Query with DO bit returned a response with the DO bit set");
}


int check_ad_bit(char *ns_name, char *buf, size_t buf_len, int *return_status) {
    /* queries with the DO bit and sees if the AD bit is set for a response
       that should be valadatable from the root down. */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int found_edns0 = 0;

    ns_msg          handle;
    int             qdcount, ancount, nscount, arcount;
    u_int           opcode, rcode, id;
    ns_rr           rr;
    int             rrnum;
    int             has_ad;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= SR_QUERY_SET_DO | SR_QUERY_RECURSE;
    ns->ns_options &= ~ ns_f_cd;

    rc = get("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("No response was received when checking for the AD bit");

    if (ns_initparse(response, len, &handle) < 0)
        RETURN_ERROR("Fatal internal error: failed to init parser");

    has_ad = libsres_msg_getflag(handle, ns_f_ad);

    if (!has_ad)
        RETURN_ERROR("The AD bit was not set on a validatable query.");

    free_name_server(&ns);
    RETURN_SUCCESS("A query with DO bit set returned with the AD bit for a validatable query");
}



int check_do_has_rrsigs(char *ns_name, char *buf, size_t buf_len, int *return_status) {
    /* queries with the DO bit and thus should return an answer with
       the DO bit as well.  It should additionall have at least one
       RRSIG record. */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int found_rrsig = 0;

    ns_msg          handle;
    int             qdcount, ancount, nscount, arcount;
    u_int           opcode, rcode, id;
    ns_rr           rr;
    int             rrnum;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS;

    rc = get("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("No response was received when querying for returned RRSIGs");

    if (ns_initparse(response, len, &handle) < 0)
        RETURN_ERROR("Fatal internal error: failed to init parser");

    opcode = libsres_msg_getflag(handle, ns_f_opcode);
    rcode = libsres_msg_getflag(handle, ns_f_rcode);
    id = ns_msg_id(handle);
    qdcount = ns_msg_count(handle, ns_s_qd);
    ancount = ns_msg_count(handle, ns_s_an);
    nscount = ns_msg_count(handle, ns_s_ns);
    arcount = ns_msg_count(handle, ns_s_ar);

    /* check the answer records for at least one RRSIG */
    rrnum = 0;
    for (;;) {
        if (ns_parserr(&handle, ns_s_an, rrnum, &rr)) {
            if (errno != ENODEV) {
                /* parse error */
                RETURN_ERROR("failed to parse a returned answer RRSET");
            }
            break; /* out of data */
        }

        if (ns_rr_type(rr) == ns_t_rrsig) {
            found_rrsig = 1;
            break;
        }
        rrnum++;
    }

    if (!found_rrsig)
        RETURN_ERROR("Failed to find an expected RRSIG in a DNSSEC valid query");

    free_name_server(&ns);
    RETURN_SUCCESS("Quering with the DO bit set returned answers including RRSIGs");
}


int check_can_get_negative(char *ns_name, char *buf, size_t buf_len, const char *name, int rrtype) {
    /* queries with the DO bit and thus should return an answer with
       the DO bit as well.  It should additionall have at least one
       RRSIG record. */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int found_nsec = 0;

    ns_msg          handle;
    int             qdcount, ancount, nscount, arcount;
    u_int           opcode, rcode, id;
    ns_rr           rr;
    int             rrnum;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE;

    rc = get(name, ns_t_a, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("Querying for negative answers failed to get a response");

    if (ns_initparse(response, len, &handle) < 0)
        RETURN_ERROR("Fatal internal error: failed to init parser");

    opcode = libsres_msg_getflag(handle, ns_f_opcode);
    rcode = libsres_msg_getflag(handle, ns_f_rcode);
    id = ns_msg_id(handle);
    qdcount = ns_msg_count(handle, ns_s_qd);
    ancount = ns_msg_count(handle, ns_s_an);
    nscount = ns_msg_count(handle, ns_s_ns);
    arcount = ns_msg_count(handle, ns_s_ar);

    /* check the answer records for at least one RRSIG */
    rrnum = 0;
    for (;;) {
        if (ns_parserr(&handle, ns_s_ns, rrnum, &rr)) {
            if (errno != ENODEV) {
                /* parse error */
                RETURN_ERROR("Failed to parse a returned answer RRSET");
            }
            break; /* out of data */
        }
        if (ns_rr_type(rr) == rrtype) {
            /* XXX: check that the record properly surrounds the query */
            found_nsec = 1;
            break;
        }
        rrnum++;
    }

    if (!found_nsec && rrtype == ns_t_nsec)
        RETURN_ERROR("Failed to find an expected NSEC record in a query for a record that doesn't exist.");
    if (!found_nsec)
        RETURN_ERROR("Failed to find an expected NSEC3 record in a query for a record that doesn't exist.");

    free_name_server(&ns);
    if (!rrtype == ns_t_nsec)
        RETURN_SUCCESS("Querying for a non-existent record returned an NSEC record.");
    RETURN_SUCCESS("Querying for a non-existent record returned an NSEC3 record.");
}

int check_can_get_nsec(char *ns_name, char *buf, size_t buf_len, int *return_status) {
    return check_can_get_negative(ns_name, buf, buf_len, "bogusdnstest.dnssec-tools.org", ns_t_nsec);
}

int check_can_get_nsec3(char *ns_name, char *buf, size_t buf_len, int *return_status) {
    return check_can_get_negative(ns_name, buf, buf_len, "foobardedabadoo.org", ns_t_nsec3);
}

int check_can_get_type(char *ns_name, char *buf, size_t buf_len, const char *name, const char *asciitype, int rrtype) {
    /* queries with the DO bit and thus should return an answer with
       the DO bit as well.  It should additionall have at least one
       RRSIG record. */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int found_type = 0;

    ns_msg          handle;
    int             qdcount, ancount, nscount, arcount;
    u_int           opcode, rcode, id;
    ns_rr           rr;
    int             rrnum;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE;

    rc = get(name, rrtype, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("Querying for a particular type failed to get a response");

    if (ns_initparse(response, len, &handle) < 0)
        RETURN_ERROR("Fatal internal error: failed to init parser");

    opcode = libsres_msg_getflag(handle, ns_f_opcode);
    rcode = libsres_msg_getflag(handle, ns_f_rcode);
    id = ns_msg_id(handle);
    qdcount = ns_msg_count(handle, ns_s_qd);
    ancount = ns_msg_count(handle, ns_s_an);
    nscount = ns_msg_count(handle, ns_s_ns);
    arcount = ns_msg_count(handle, ns_s_ar);

    /* check the answer records for at least one RRSIG */
    rrnum = 0;
    for (;;) {
        if (ns_parserr(&handle, ns_s_an, rrnum, &rr)) {
            if (errno != ENODEV) {
                /* parse error */
                RETURN_ERROR("Failed to parse a returned answer RRSET");
            }
            break; /* out of data */
        }
        if (ns_rr_type(rr) == rrtype) {
            found_type = 1;
            break;
        }
        rrnum++;
    }

    free_name_server(&ns);

    if (!found_type) {
        snprintf(buf, buf_len, "Error: Failed to retrieve a record of type %s", asciitype);
        return CHECK_FAILED;
    }

    snprintf(buf, buf_len, "Success: Successfully retrieved a record of type %s", asciitype);

    return CHECK_SUCCEEDED;
}

int check_can_get_dnskey(char *ns_name, char *buf, size_t buf_len, int *return_status) {
    return check_can_get_type(ns_name, buf, buf_len, "dnssec-tools.org", "DNSKEY", ns_t_dnskey);
}

int check_can_get_ds(char *ns_name, char *buf, size_t buf_len, int *return_status) {
    return check_can_get_type(ns_name, buf, buf_len, "dnssec-tools.org", "DS", ns_t_ds);
}
