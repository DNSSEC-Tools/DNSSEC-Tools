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

#define CHECK_CRITICAL  -1
#define CHECK_SUCCEEDED 0
#define CHECK_FAILED    1
#define CHECK_WARNING   2

/* Syncronous macros */

#define SET_MESSAGE(msg, buffer, buffer_len)               \
    do {                                                   \
        strncpy(buffer, msg, buffer_len-1);                \
        buffer[buffer_len-1] = '\0';                       \
    } while(0);

#define RETURN_CODE_BUF(code, msg, buffer, buffer_len)     \
    do {                                                   \
        strncpy(buffer, msg, buffer_len-1);                \
        buffer[buffer_len-1] = '\0';                       \
        if (testStatus)                                    \
            *testStatus = code;                            \
        return code;                                       \
    } while(0);

#define RETURN_ERROR(msg)                                  \
    RETURN_CODE_BUF(CHECK_FAILED, "Error: " msg, buf, buf_len);

#define RETURN_CRITICAL(msg)                               \
    RETURN_CODE_BUF(CHECK_CRITICAL, "Critical: " msg, buf, buf_len);

#define RETURN_SUCCESS(msg)                                \
    RETURN_CODE_BUF(CHECK_SUCCEEDED, "Success: " msg, buf, buf_len);

#define RETURN_WARNING(msg)                                \
    RETURN_CODE_BUF(CHECK_WARNING, "Warning: " msg, buf, buf_len);

/* Asyncronous Macros */
#define SET_CODE_BUF(code, msg, buffer, buffer_len)        \
    do {                                                   \
        strncpy(buffer, msg, buffer_len-1);                \
        buffer[buffer_len-1] = '\0';                       \
        *testStatus = (code == CHECK_CRITICAL ? CHECK_FAILED : code);                          \
        return code;                                       \
    } while(0);

#define SET_CRITICIAL(msg)                                  \
    SET_CODE_BUF(CHECK_CRITICAL, "CRITICIAL: " msg, buf, buf_len);

#define SET_ERROR(msg)                                  \
    SET_CODE_BUF(CHECK_FAILED, "Error: " msg, buf, buf_len);

#define SET_SUCCESS(msg)                                \
    SET_CODE_BUF(CHECK_SUCCEEDED, "Success: " msg, buf, buf_len);

#define SET_WARNING(msg)                                \
    SET_CODE_BUF(CHECK_WARNING, "Warning: " msg, buf, buf_len);

typedef int (AsyncCallback) (u_char *buffer, size_t buffer_size, int status,
                             int *testReturnStatus, void *localData);

typedef struct outstanding_query_s {
    int                      live;
    struct expected_arrival *ea;
    AsyncCallback           *callback;
    int                     *testReturnStatus;
    void                    *localData;
} outstanding_query;

int maxcount = 0;
static outstanding_query outstanding_queries[1024];

/*
 * Async Loop processing
 */
int
check_outstanding_async() {
    int i, ret_val, handled = 0;

    for(i = 0; i < maxcount; i++) {
        u_char             *response_data = NULL;
        size_t              response_length = 0;
        struct name_server *server = NULL;
        fd_set              fds;
        int                 numfds = 0;
        struct timeval      tv;

        tv.tv_sec = 0;
        tv.tv_usec = 1;

        /* are we waiting on this one? */
        if (!outstanding_queries[i].live)
            continue;

        res_async_query_select_info(outstanding_queries[i].ea, &numfds, &fds, &tv);

        /* XXX: get fds */
        if (!res_async_ea_isset(outstanding_queries[i].ea, &fds))
            continue;

        /* much from _resolver_rcv_one -> val_resquery_async_rcv */
        ret_val = res_async_query_handle(outstanding_queries[i].ea, &handled, &fds);

        if (ret_val == SR_NO_ANSWER_YET)
            continue;

        ret_val = res_io_get_a_response(outstanding_queries[i].ea, &response_data,
                                        &response_length, &server);
        ret_val = res_map_srio_to_sr(ret_val);

        (*(outstanding_queries[i].callback))(response_data, response_length,
                                             ret_val,
                                             outstanding_queries[i].testReturnStatus,
                                             outstanding_queries[i].localData);

        outstanding_queries[i].live = 0;
    }
}

void
add_outstanding_async_query(struct expected_arrival *ea, AsyncCallback *callback,
                            int *testReturnStatus, void *localData) {
    int i = 0;

    if (ea == NULL || callback == NULL)
        return;

    while(i < maxcount) {
        if(!outstanding_queries[i].live)
            break;
        i++;
    }
    outstanding_queries[i].live = 1;
    outstanding_queries[i].ea = ea;
    outstanding_queries[i].callback = callback;
    outstanding_queries[i].testReturnStatus = testReturnStatus;
    outstanding_queries[i].localData = localData;
    if (maxcount <= i)
        maxcount = i+1;
}

void
collect_async_query_select_info(fd_set *fds, int *numfds) {
    int i;
    struct timeval      tv;

    tv.tv_sec = 0;
    tv.tv_usec = 1;

    for(i = 0; i < maxcount; i++) {
        res_async_query_select_info(outstanding_queries[i].ea, numfds, fds, &tv);
    }
}

/*
 * DNS convenience routines
 */

int count_types(u_char *response, size_t len, char *buf, size_t buf_len, int rr_type, ns_sect rr_section)
{
    int             rc;
    ns_msg          handle;
    int             qdcount, ancount, nscount, arcount;
    u_int           opcode, rcode, id;
    ns_rr           rr;
    int             rrnum;
    int             count = 0;
    int             found_type = 0;
    int             ts, *testStatus = &ts;

    if (ns_initparse(response, len, &handle) < 0)
        RETURN_CRITICAL("Fatal internal error: failed to init parser");

    opcode = libsres_msg_getflag(handle, ns_f_opcode);
    rcode = libsres_msg_getflag(handle, ns_f_rcode);

    id = ns_msg_id(handle);
    qdcount = ns_msg_count(handle, ns_s_qd);
    ancount = ns_msg_count(handle, ns_s_an);
    nscount = ns_msg_count(handle, ns_s_ns);
    arcount = ns_msg_count(handle, ns_s_ar);

    //fprintf(stderr, "section counts: %d,%d,%d,%d\n", qdcount, ancount, nscount, arcount);

    /* check the answer records for the DO bit in the response */
    rrnum = 0;
    for (;;) {
        if (ns_parserr(&handle, rr_section, rrnum, &rr)) {
            if (errno != ENODEV) {
                /* parse error */
                RETURN_ERROR("failed to parse a returned additional RRSET");
            }
            break; /* out of data */
        }
        if (ns_rr_type(rr) == rr_type) {
            found_type = 1;
            count++;
        }
        rrnum++;
    }

    //fprintf(stderr, "count of type %d: count=%d / found=%d\n", rr_type, count, found_type);

    /* set some generic records, but tests should really reset these */
    if (!found_type) {
        SET_MESSAGE("No record found.", buf, buf_len);
        return 0;
    }

    SET_MESSAGE("A record was successfully retrieved", buf, buf_len);
    return count;
}

/******************************************************************************
 * TESTS
 ******************************************************************************/

/* LIBVAL specific async testing (not used in general unless testing libval itself) */

#ifndef VAL_NO_ASYNC
typedef struct basic_callback_data_s {
    char *domain;
    val_async_status *val_status;
    int *testStatus;
} basic_callback_data;

int _check_basic_async_response(val_async_status *async_status, int event,
                                val_context_t *ctx, void *user_ctx,
                                val_cb_params_t *cbp) {

    basic_callback_data *data = (basic_callback_data *) user_ctx;

    if (!data->testStatus)
        return 0;

    if (val_istrusted(cbp->val_status)) {
        *data->testStatus = CHECK_SUCCEEDED;
    } else {
        *data->testStatus = CHECK_FAILED;
    }

    return 0; /* OK */
}

int count = 0;
int check_basic_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
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
    basic_async_data->testStatus = testStatus;
    count++;

    rc = val_async_submit(NULL, basic_async_data->domain, ns_c_in, ns_t_a, 0, callback_info,
                          basic_async_data, &basic_async_data->val_status);
}

#endif /* !VAL_NO_ASYNC */

/*
 * BASIC DNS (over UDP) testing
 */
int check_basic_dns(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int             rrnum;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE;

    rc = get("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("Basic DNS query failed entirely");

    rrnum = count_types(response, len, buf, buf_len, ns_t_a, ns_s_an);
    
    if (rrnum <= 0)
        RETURN_ERROR("No A record found using UDP in the basic DNS test.");

    RETURN_SUCCESS("An A record was successfully retrieved");
}

#ifndef VAL_NO_ASYNC
int _check_basic_dns_async_response(u_char *response, size_t response_size,
                                    int rc, int *testStatus, void *localData) {
    int             rrnum;
    char            buf[1024];
    size_t          buf_len = sizeof(buf);

    if (rc != SR_UNSET)
        SET_ERROR("Basic DNS query failed entirely");

    rrnum = count_types(response, response_size, buf, buf_len, ns_t_a, ns_s_an);
    
    if (rrnum <= 0)
        SET_ERROR("No A record found using UDP in the basic DNS test.");

    SET_SUCCESS("An A record was successfully retrieved");
}

int check_basic_dns_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    struct expected_arrival *ea;
    struct name_server *ns;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE;

    ea = res_async_query_send("www.dnssec-tools.org", ns_t_a, ns_c_in, ns);
    add_outstanding_async_query(ea, _check_basic_dns_async_response,
                                testStatus, NULL);
}
#endif /* VAL_NO_ASYNC */

int check_basic_tcp(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
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

int check_small_edns0_results(u_char *response, size_t response_size, char *buf, size_t buf_len, int *testStatus) {
    ns_msg          handle;
    int             rrnum = 0;
    int             found_edns0 = 0;
    ns_rr           rr;

    if (ns_initparse(response, response_size, &handle) < 0)
        RETURN_ERROR("Fatal internal error: failed to init parser");

    /* check the answer records for the DO bit in the response */
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
        *testStatus = CHECK_WARNING;
        return CHECK_WARNING;
    }

    *testStatus = CHECK_SUCCEEDED;
    snprintf(buf, buf_len, "Success: The returned EDNS0 size (%d) was reasonable.", found_edns0);
    return CHECK_SUCCEEDED;
}

int check_small_edns0(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
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

    return check_small_edns0_results(response, len, buf, buf_len, testStatus);
}

#ifndef VAL_NO_ASYNC
int _check_small_edns0_async_response(u_char *response, size_t response_size,
                                      int rc, int *testStatus, void *localData) {
    int             rrnum;
    char            buf[1024];
    size_t          buf_len = sizeof(buf);

    if (rc != SR_UNSET)
        SET_ERROR("Basic DNS query failed entirely");

    return check_small_edns0_results(response, response_size, buf, buf_len, testStatus);
}

int check_small_edns0_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    struct expected_arrival *ea;
    struct name_server *ns;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_edns0_size = 4096;
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE;

    ea = res_async_query_send(ns_name, ns_t_a, ns_c_in, ns);
    add_outstanding_async_query(ea, _check_small_edns0_async_response,
                                testStatus, NULL);
}
#endif /* VAL_NO_ASYNC */

int check_do_bit(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
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


int check_ad_bit(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
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



int check_do_has_rrsigs(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
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

    rrnum = count_types(response, len, buf, buf_len, ns_t_rrsig, ns_s_an);

    if (rrnum <= 0)
        RETURN_ERROR("Failed to find an expected RRSIG in a DNSSEC valid query");

    RETURN_SUCCESS("Quering with the DO bit set returned answers including RRSIGs");
}

#ifndef VAL_NO_ASYNC
int _check_has_rrsigs_async_response(u_char *response, size_t response_size,
                                     int rc, int *testStatus, void *localData) {
    int rrnum;
    char            buf[1024];
    size_t          buf_len = sizeof(buf);

    if (rc != SR_UNSET)
        SET_ERROR("Basic DNS query failed entirely");

    rrnum = count_types(response, response_size, buf, buf_len, ns_t_a, ns_s_an);
    
    if (rrnum <= 0)
        SET_ERROR("No A record found using UDP in the basic DNS test.");

    SET_SUCCESS("An A record was successfully retrieved");
}

int check_do_has_rrsigs_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    struct expected_arrival *ea;
    struct name_server *ns;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS;

    ea = res_async_query_send("www.dnssec-tools.org", ns_t_a, ns_c_in, ns);
    add_outstanding_async_query(ea, _check_has_rrsigs_async_response,
                                testStatus, NULL);
}
#endif /* VAL_NO_ASYNC */


int check_can_get_negative(char *ns_name, char *buf, size_t buf_len, const char *name, int rrtype) {
    /* queries with the DO bit and thus a bad query should return an answer with
       an NSEC or NSEC3 record based on the parent zones type. */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int found_nsec = 0;
    int ts = 0, *testStatus = &ts;

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

    rrnum = count_types(response, len, buf, buf_len,
                        rrtype, ns_s_ns);

    if (rrnum <= 0 && rrtype == ns_t_nsec)
        RETURN_ERROR("Failed to find an expected NSEC record in a query for a record that doesn't exist.");
    if (rrnum <= 0)
        RETURN_ERROR("Failed to find an expected NSEC3 record in a query for a record that doesn't exist.");

    free_name_server(&ns);
    if (!rrtype == ns_t_nsec)
        RETURN_SUCCESS("Querying for a non-existent record returned an NSEC record.");
    RETURN_SUCCESS("Querying for a non-existent record returned an NSEC3 record.");
}

int check_can_get_nsec(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_negative(ns_name, buf, buf_len, "bogusdnstest.dnssec-tools.org", ns_t_nsec);
}

int check_can_get_nsec3(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_negative(ns_name, buf, buf_len, "foobardedabadoo.org", ns_t_nsec3);
}

#ifndef VAL_NO_ASYNC
int _check_negative_async_response(u_char *response, size_t response_size,
                                    int rc, int *testStatus, void *localData) {
    int             rrnum;
    char            buf[1024];
    size_t          buf_len = sizeof(buf);
    int            *expected_type = (int*) localData;
    int             rrtype = *expected_type;


    if (rc != SR_UNSET)
        SET_ERROR("Query for a negative response failed to get an answer entirely");

    rrnum = count_types(response, response_size, buf, buf_len, rrtype, ns_s_ns);
    free(expected_type);

    if (rrnum <= 0 && rrtype == ns_t_nsec)
        SET_ERROR("Failed to find an expected NSEC record in a query for a record that doesn't exist.");
    if (rrnum <= 0)
        SET_ERROR("Failed to find an expected NSEC3 record in a query for a record that doesn't exist.");

    if (!rrtype == ns_t_nsec)
        SET_SUCCESS("Querying for a non-existent record returned an NSEC record.");
    SET_SUCCESS("Querying for a non-existent record returned an NSEC3 record.");
}

int check_can_get_negative_async(char *ns_name, char *buf, size_t buf_len, const char *name, int *testStatus, int rrtype) {
    /* queries with the DO bit and thus a bad query should return an answer with
       an NSEC or NSEC3 record based on the parent zones type. */

    struct name_server *ns;
    struct expected_arrival *ea;
    int *expected_type = (int *) malloc(sizeof(int));

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE;

    *expected_type = rrtype;
    ea = res_async_query_send(name, ns_t_a, ns_c_in, ns);
    add_outstanding_async_query(ea, _check_negative_async_response,
                                testStatus, expected_type);

    return 0;
}


int check_can_get_nsec_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_negative_async(ns_name, buf, buf_len, "bogusdnstest.dnssec-tools.org", testStatus, ns_t_nsec);
}

int check_can_get_nsec3_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_negative_async(ns_name, buf, buf_len, "foobardedabadoo.org", testStatus, ns_t_nsec3);
}
#endif /* VAL_NO_ASYNC */

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
    int ts = 0, *testStatus = &ts;

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

int check_can_get_dnskey(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_type(ns_name, buf, buf_len, "dnssec-tools.org", "DNSKEY", ns_t_dnskey);
}

int check_can_get_ds(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_type(ns_name, buf, buf_len, "dnssec-tools.org", "DS", ns_t_ds);
}
