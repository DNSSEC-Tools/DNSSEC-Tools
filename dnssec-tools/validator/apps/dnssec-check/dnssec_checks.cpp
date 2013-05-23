#include <stdio.h>
#include <errno.h>
#include <string.h>

/*
 * NOTE:  Although this file is a .cpp file, the intent is for it to be fully
 *        "C" compatible.  IE, do NOT put any C++ required code in here.
 */

#define HAVE_DECL_NS_NTOP 1

#include <validator/validator-config.h>
#include "validator/resolver.h"
#include "validator/validator.h"

#include "dnssec_checks.h"

#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

/* libsres functions that they don't export */
extern "C" {
    struct expected_arrival *
            res_async_query_create(const char *name, const u_int16_t type_h,
                                   const u_int16_t class_h, struct name_server *pref_ns,
                                   u_int flags);
    void    res_switch_all_to_tcp(struct expected_arrival *ea);
    int     res_io_queue_ea(int *transaction_id, struct expected_arrival *new_ea);
    int     res_io_send(struct expected_arrival *shipit);
    int     res_sq_free_expected_arrival(struct expected_arrival **ea);
}

/* Syncronous macros */

#define SET_MESSAGE(msg, buffer, buffer_len)               \
    do {                                                   \
        strncpy(buffer, msg, buffer_len-1);                \
        buffer[buffer_len-1] = '\0';                       \
    } while(0);

#define RETURN_SOMETHING_END(code, what, buffer, buffer_len)     \
    buffer[buffer_len-1] = '\0';                       \
    if (testStatus)                                    \
        *testStatus = (code == CHECK_CRITICAL ? CHECK_FAILED : code);                          \
    return what;                                       \
   } while(0);

#define RETURN_SOMETHING_CODE_BUF(code, what, msg, buffer, buffer_len)     \
    do {                                                   \
        strncpy(buffer, msg, buffer_len-1);                \
        RETURN_SOMETHING_END(code, what, buffer, buffer_len)

#define RETURN_SOMETHING_CODE_BUF1(code, what, msg, buffer, buffer_len, arg1)     \
    do {                                                   \
        snprintf(buffer, buffer_len-1, msg, arg1);         \
        RETURN_SOMETHING_END(code, what, buffer, buffer_len)

#define RETURN_SOMETHING_CODE_BUF2(code, what, msg, buffer, buffer_len, arg1, arg2)     \
    do {                                                   \
        snprintf(buffer, buffer_len-1, msg, arg1);         \
        RETURN_SOMETHING_END(code, what, buffer, buffer_len)

#define RETURN_CODE_BUF(code, msg, buffer, buffer_len)              RETURN_SOMETHING_CODE_BUF(code, code, msg, buffer, buffer_len)
#define RETURN_CODE_BUF1(code, msg, buffer, buffer_len, arg1)       RETURN_SOMETHING_CODE_BUF1(code, code, msg, buffer, buffer_len, arg1)
#define RETURN_CODE_BUF2(code, msg, buffer, buffer_len, arg1, arg2) RETURN_SOMETHING_CODE_BUF2(code, code, msg, buffer, buffer_len, arg1, arg2)

#define RETURN_ERROR(msg)     RETURN_CODE_BUF(CHECK_FAILED,    "Error: "    msg, buf, buf_len);
#define RETURN_CRITICAL(msg)  RETURN_CODE_BUF(CHECK_CRITICAL,  "Critical: " msg, buf, buf_len);
#define RETURN_SUCCESS(msg)   RETURN_CODE_BUF(CHECK_SUCCEEDED, "Success: "  msg, buf, buf_len);
#define RETURN_WARNING(msg)   RETURN_CODE_BUF(CHECK_WARNING,   "Warning: "  msg, buf, buf_len);

#define RETURN_ERROR1(msg, arg1)     RETURN_CODE_BUF1(CHECK_FAILED,    "Error: "    msg, buf, buf_len, arg1);
#define RETURN_CRITICAL1(msg, arg1)  RETURN_CODE_BUF1(CHECK_CRITICAL,  "Critical: " msg, buf, buf_len, arg1);
#define RETURN_SUCCESS1(msg, arg1)   RETURN_CODE_BUF1(CHECK_SUCCEEDED, "Success: "  msg, buf, buf_len, arg1);
#define RETURN_WARNING1(msg, arg1)   RETURN_CODE_BUF1(CHECK_WARNING,   "Warning: "  msg, buf, buf_len);

/* Asyncronous Macros */
#define SET_CODE_BUF(code,  msg, buffer, buffer_len)                RETURN_SOMETHING_CODE_BUF(code, , msg, buffer, buffer_len)
#define SET_CODE_BUF1(code, msg, buffer, buffer_len, arg1)          RETURN_SOMETHING_CODE_BUF1(code, , msg, buffer, buffer_len, arg1)
#define SET_CODE_BUF2(code, msg, buffer, buffer_len, arg1, arg2)    RETURN_SOMETHING_CODE_BUF2(code, , msg, buffer, buffer_len, arg1, arg2)


#define SET_CRITICIAL(msg)         SET_CODE_BUF(CHECK_CRITICAL, "CRITICIAL: " msg, buf, buf_len);
#define SET_ERROR(msg)             SET_CODE_BUF(CHECK_FAILED, "Error: " msg, buf, buf_len);
#define SET_SUCCESS(msg)           SET_CODE_BUF(CHECK_SUCCEEDED, "Success: " msg, buf, buf_len);
#define SET_WARNING(msg)           SET_CODE_BUF(CHECK_WARNING, "Warning: " msg, buf, buf_len);

#define SET_CRITICIAL1(msg, arg1)  SET_CODE_BUF1(CHECK_CRITICAL, "CRITICIAL: " msg, buf, buf_len, arg1);
#define SET_ERROR1(msg, arg1)      SET_CODE_BUF1(CHECK_FAILED, "Error: " msg, buf, buf_len, arg1);
#define SET_SUCCESS1(msg, arg1)    SET_CODE_BUF1(CHECK_SUCCEEDED, "Success: " msg, buf, buf_len, arg1);

#define SET_WARNING1(msg, arg1)    SET_CODE_BUF1(CHECK_WARNING, "Warning: " msg, buf, buf_len, arg1);

/* Async related definitions */

typedef void (AsyncCallback) (u_char *buffer, size_t buffer_size, int status,
                              int *testReturnStatus, char *buf, size_t buf_len, void *localData);

typedef struct outstanding_query_s {
    int                      live;
    struct expected_arrival *ea;
    AsyncCallback           *callback;
    int                     *testReturnStatus;
    void                    *localData;
    char                    *statusBuffer;
    size_t                   statusBuffer_len;
} outstanding_query;

int maxcount = 0;
int outstandingCount = 0;
static outstanding_query outstanding_queries[1024];

typedef struct async_info_s {
        int             rr_type;
        const char *rr_type_name;
} async_info;

async_info *malloc_async_info(int rr_type, const char *rr_type_name) {
    async_info *ret = (async_info *) malloc(sizeof(async_info));
    ret->rr_type = rr_type;
    ret->rr_type_name = rr_type_name;
    return ret;
}

/*
 * Async Loop processing
 */

int
async_requests_remaining() {
    return outstandingCount;
}

void
async_cancel_outstanding() {
    int i;
    for(i = 0; i < maxcount; i++) {
        if (outstanding_queries[i].live) {
            res_io_cancel_all_remaining_attempts(outstanding_queries[i].ea);
            outstanding_queries[i].live = 0;
        }
    }
    outstandingCount = 0;
}

void
check_queued_sends() {
    int i;
    for(i = 0; i < maxcount; i++) {
        if (*outstanding_queries[i].testReturnStatus == CHECK_QUEUED) {
            *outstanding_queries[i].testReturnStatus = CHECK_CRITICAL;
            res_io_send(outstanding_queries[i].ea);
        }
    }
}

void
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
        if (!outstanding_queries[i].live || *outstanding_queries[i].testReturnStatus == CHECK_QUEUED)
            continue;

        FD_ZERO(&fds);
        res_async_query_select_info(outstanding_queries[i].ea, &numfds, &fds, &tv);

//        if (!res_async_ea_isset(outstanding_queries[i].ea, &fds))
//            continue;

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
                                             outstanding_queries[i].statusBuffer,
                                             outstanding_queries[i].statusBuffer_len,
                                             outstanding_queries[i].localData);
        outstandingCount--;

        outstanding_queries[i].live = 0;
        res_sq_free_expected_arrival(&outstanding_queries[i].ea);
    }
}

void
add_outstanding_async_query(struct expected_arrival *ea, AsyncCallback *callback,
                            int *testReturnStatus, char *statusBuffer, size_t statusBuffer_len,
                            void *localData) {
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
    outstanding_queries[i].statusBuffer = statusBuffer;
    outstanding_queries[i].statusBuffer_len = statusBuffer_len;
    outstanding_queries[i].localData = localData;
    if (maxcount <= i)
        maxcount = i+1;
    outstandingCount++;
}

void
collect_async_query_select_info(fd_set *udp_fds, int *numUdpFds, fd_set *tcp_fds, int *numTcpFds) {
    int i;
    struct timeval      tv;

    tv.tv_sec = 0;
    tv.tv_usec = 1;

    int live = 0;
    for(i = 0; i < maxcount; i++) {
        if (outstanding_queries[i].ea && outstanding_queries[i].ea->ea_using_stream)
            res_async_query_select_info(outstanding_queries[i].ea, numTcpFds, tcp_fds, &tv);
        else
            res_async_query_select_info(outstanding_queries[i].ea, numUdpFds, udp_fds, &tv);
        if (outstanding_queries[i].live)
            live++;
    }
}

/*
 * DNS convenience routines
 */

int count_types(u_char *response, size_t len, char *buf, size_t buf_len, int rr_type, ns_sect rr_section, const char *rr_type_name)
{
    ns_msg          handle;
    ns_rr           rr;
    int             rrnum;
    int             count = 0;
    int             found_type = 0;
    int             *testStatus = NULL;

    if (ns_initparse(response, len, &handle) < 0)
        RETURN_CRITICAL("Fatal internal error: failed to init parser");

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
        RETURN_SOMETHING_CODE_BUF1(0, 0, "No %s record found.", buf, buf_len, rr_type_name)
    }

    RETURN_SOMETHING_CODE_BUF1(count, count, "At least one %s record was successfully retrieved", buf, buf_len, rr_type_name)
}

void _check_has_one_type_section_async(u_char *response, size_t response_size,
                                       int rc, int *testStatus, char *buf, size_t buf_len,
                                       int rrtype, ns_sect rrsection, const char *rrtypename) {
    int             rrnum;

    if (rc != SR_UNSET)
        SET_ERROR("Basic DNS query failed entirely");

    rrnum = count_types(response, response_size, buf, buf_len, rrtype, rrsection, rrtypename);

    if (rrnum <= 0)
        SET_ERROR1("No %s record found the DNS response.", rrtypename);

    SET_SUCCESS1("At least one %s record was successfully retrieved", rrtypename);
}

void _check_has_one_type_async(u_char *response, size_t response_size,
                              int rc, int *testStatus, char *buf, size_t buf_len, void *localData) {
    async_info *info = (async_info *) localData;

    _check_has_one_type_section_async(response, response_size, rc, testStatus, buf, buf_len, info->rr_type, ns_s_an, info->rr_type_name);
    free(localData);
}

static struct name_server *
_parse_name_server(char *ns_name, int flags) {
    struct name_server *ns;

    ns = parse_name_server(ns_name, NULL);

    if (!ns)
        return NULL;

    ns->ns_options |= flags;

    /* 1 retry at 1 second */
    ns->ns_retrans = 1;
    ns->ns_retry = 1;

    return ns;
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
        return -1;

    if (val_istrusted(cbp->val_status)) {
        *data->testStatus = CHECK_SUCCEEDED;
    } else {
        *data->testStatus = CHECK_FAILED;
    }

    return 0;
}

int count = 0;
void check_basic_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    struct name_server *ns;
    val_async_event_cb callback_info = &_check_basic_async_response;
    basic_callback_data *basic_async_data;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);

    basic_async_data = (basic_callback_data *) malloc(sizeof(basic_callback_data));
    basic_async_data->domain = strdup("www.dnssec-tools.org");
    basic_async_data->val_status = 0;
    basic_async_data->testStatus = testStatus;
    count++;

    val_async_submit(NULL, basic_async_data->domain, ns_c_in, ns_t_a, 0, callback_info,
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

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);

    rc = get("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("Basic DNS query failed entirely");

    rrnum = count_types(response, len, buf, buf_len, ns_t_a, ns_s_an, "A");
    
    if (rrnum <= 0)
        RETURN_ERROR("No A record found using UDP in the basic DNS test.");

    RETURN_SUCCESS("An A record was successfully retrieved");
}

#ifndef VAL_NO_ASYNC

int check_basic_dns_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    struct expected_arrival *ea;
    struct name_server *ns;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);

    ea = res_async_query_send("www.dnssec-tools.org", ns_t_a, ns_c_in, ns);
    add_outstanding_async_query(ea, _check_has_one_type_async,
                                testStatus, buf, buf_len, malloc_async_info(ns_t_a, "A"));
    return CHECK_CRITICAL;
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
    ns_rr           rr;
    int             rrnum;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);

    rc = get_tcp("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
                 &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("basic TCP query failed entirely");

    if (ns_initparse(response, len, &handle) < 0)
        RETURN_ERROR("Fatal internal error: failed to init parser");

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

#ifndef VAL_NO_SYNC
int check_basic_tcp_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    struct expected_arrival *ea;
    struct name_server *ns;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);

    ea = res_async_query_create("www.dnssec-tools.org", ns_t_a, ns_c_in, ns, 0);
    res_switch_all_to_tcp(ea);
    //*testStatus = CHECK_QUEUED;
    res_io_send(ea);
    add_outstanding_async_query(ea, _check_has_one_type_async,
                                testStatus, buf, buf_len, malloc_async_info(ns_t_a, "A (over tcp)"));
    return CHECK_CRITICAL;
}
#endif /* !VAL_NO_ASYNC */

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

    if (found_edns0 < 1480) {
        snprintf(buf, buf_len, "Warning: The returned EDNS0 size (%d) is smaller than recommended (1480)", found_edns0);
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

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);
    ns->ns_edns0_size = 4096;

    rc = get("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("query failed entirely");

    return check_small_edns0_results(response, len, buf, buf_len, testStatus);
}

#ifndef VAL_NO_ASYNC
void _check_small_edns0_async_response(u_char *response, size_t response_size,
                                      int rc, int *testStatus, char *buf, size_t buf_len, void *localData) {
    if (rc != SR_UNSET)
        SET_ERROR("Basic DNS query failed entirely");

    check_small_edns0_results(response, response_size, buf, buf_len, testStatus);
}

int check_small_edns0_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    struct expected_arrival *ea;
    struct name_server *ns;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);
    ns->ns_edns0_size = 4096;

    ea = res_async_query_send(ns_name, ns_t_a, ns_c_in, ns);
    add_outstanding_async_query(ea, _check_small_edns0_async_response,
                                testStatus, buf, buf_len, NULL);
    return CHECK_CRITICAL;
}
#endif /* VAL_NO_ASYNC */

int check_an_edns0_bit(u_char *response, size_t response_size, char *buf, size_t buf_len, int *testStatus, int bit, const char *bitName)
{
    ns_msg          handle;
    int             found_bit = 0;
    int             rrnum;
    ns_rr           rr;

    if (ns_initparse(response, response_size, &handle) < 0)
        RETURN_ERROR("Fatal internal error: failed to init parser");

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


            if ((ttl >> 16 & 0xff) != 0)
                RETURN_ERROR("The EDNS version was not 0");

            if ((ttl & bit) == bit)
                RETURN_ERROR("The EDNS0 flag failed to include the expected bit");

            found_bit = 1;

            /* edns0 size = int(ns_rr_class(rr)) */
            break;
        }
        rrnum++;
    }

    if (!found_bit)
        RETURN_ERROR1("No %s bit found in the response when one was expected.", bitName);

    RETURN_SUCCESS1("A query successfully returned a response with the %s bit set", bitName);
}

int check_do_bit(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    /* queries with the DO bit and thus should return an answer with
       the DO bit as well.  It should additionall have at least one
       RRSIG record. */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS| SR_QUERY_RECURSE);

    rc = get("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
             &server, &response, &len);


    if (rc != SR_UNSET)
        RETURN_ERROR("Checking for the DO bit failed entirely: no response was received");

    free_name_server(&ns);

    return check_an_edns0_bit(response, len, buf, buf_len, testStatus, RES_USE_DNSSEC, "DO");
}

#ifndef VAL_NO_ASYNC

void _check_do_bit_async_response(u_char *response, size_t response_size,
                             int rc, int *testStatus, char *buf, size_t buf_len, void *localData) {

    if (rc != SR_UNSET)
        SET_ERROR("DO bit DNS query failed entirely");

    check_an_edns0_bit(response, response_size, buf, buf_len, testStatus, RES_USE_DNSSEC, "DO");
}

int check_do_bit_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    struct expected_arrival *ea;
    struct name_server *ns;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);
    ns->ns_edns0_size = 4096;

    ea = res_async_query_send("www.dnssec-tools.org", ns_t_a, ns_c_in, ns);
    add_outstanding_async_query(ea, _check_do_bit_async_response,
                                testStatus, buf, buf_len, NULL);
    return CHECK_CRITICAL;
}
#endif /* VAL_NO_ASYNC */

int check_a_flag(int rc, u_char *response, size_t response_size, char *buf, size_t buf_len, int *testStatus, int flag, const char *flagName)
{
    ns_msg          handle;
    int             has_flag = 0;

    if (rc != SR_UNSET)
        RETURN_ERROR("Checking for the DO bit failed entirely: no response was received");

    if (ns_initparse(response, response_size, &handle) < 0)
        RETURN_ERROR("Fatal internal error: failed to init parser");

    has_flag = libsres_msg_getflag(handle, flag);

    if (!has_flag)
        RETURN_ERROR1("The %s bit was not set on a response to a validatable query.", flagName);

    RETURN_SUCCESS1("A response was received with the expected %s bit set.", flagName);
}



int check_ad_bit(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    /* queries with the DO bit and sees if the AD bit is set for a response
       that should be valadatable from the root down. */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;

    ns = _parse_name_server(ns_name, SR_QUERY_SET_DO | SR_QUERY_RECURSE);
    ns->ns_options &= ~ ns_f_cd;

    rc = get("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
             &server, &response, &len);

    return check_a_flag(rc, response, len, buf, buf_len, testStatus, ns_f_ad, "AD");
}

#ifndef VAL_NO_ASYNC
void _check_ad_bit_async_response(u_char *response, size_t response_size,
                                 int rc, int *testStatus, char *buf, size_t buf_len, void *localData) {
    if (rc != SR_UNSET)
        SET_ERROR("Basic DNS query failed entirely");

    check_a_flag(rc, response, response_size, buf, buf_len, testStatus, ns_f_ad, "AD");
}

int check_ad_bit_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    struct expected_arrival *ea;
    struct name_server *ns;

    ns = _parse_name_server(ns_name, SR_QUERY_SET_DO | SR_QUERY_RECURSE);
    ns->ns_options &= ~ ns_f_cd;

    ea = res_async_query_send("www.dnssec-tools.org", ns_t_a, ns_c_in, ns);
    add_outstanding_async_query(ea, _check_ad_bit_async_response,
                                testStatus, buf, buf_len, NULL);
    return CHECK_CRITICAL;
}
#endif /* !VAL_NO_ASYNC */

int check_do_has_rrsigs(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    /* queries with the DO bit and thus should return an answer with
       the DO bit as well.  It should additionall have at least one
       RRSIG record. */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int rrnum;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS);

    rc = get("www.dnssec-tools.org", ns_t_a, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("No response was received when querying for returned RRSIGs");

    rrnum = count_types(response, len, buf, buf_len, ns_t_rrsig, ns_s_an, "RRSIG");

    if (rrnum <= 0)
        RETURN_ERROR("Failed to find an expected RRSIG in a DNSSEC valid query");

    RETURN_SUCCESS("Quering with the DO bit set returned answers including RRSIGs");
}

#ifndef VAL_NO_ASYNC
void _check_has_rrsigs_async_response(u_char *response, size_t response_size,
                                     int rc, int *testStatus, char *buf, size_t buf_len, void *localData) {
    int rrnum;

    if (rc != SR_UNSET)
        SET_ERROR("Basic DNS query failed entirely");

    rrnum = count_types(response, response_size, buf, buf_len, ns_t_a, ns_s_an, "A");
    
    if (rrnum <= 0)
        SET_ERROR("No A record found using UDP in the basic DNS test.");

    SET_SUCCESS("An A record was successfully retrieved");
}

int check_do_has_rrsigs_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    struct expected_arrival *ea;
    struct name_server *ns;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS);

    ea = res_async_query_send("www.dnssec-tools.org", ns_t_a, ns_c_in, ns);
    add_outstanding_async_query(ea, _check_has_rrsigs_async_response,
                                testStatus, buf, buf_len, NULL);
    return CHECK_CRITICAL;
}
#endif /* VAL_NO_ASYNC */


int check_can_get_negative(char *ns_name, char *buf, size_t buf_len, const char *name, int rrtype, const char *rrtypename) {
    /* queries with the DO bit and thus a bad query should return an answer with
       an NSEC or NSEC3 record based on the parent zones type. */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int ts = 0, *testStatus = &ts;

    int             rrnum;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);

    rc = get(name, ns_t_a, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("Querying for negative answers failed to get a response");

    rrnum = count_types(response, len, buf, buf_len,
                        rrtype, ns_s_ns, rrtypename);

    if (rrnum <= 0)
        RETURN_ERROR1("Failed to find an expected %s record in a query for a record that doesn't exist.", rrtypename);

    free_name_server(&ns);
    RETURN_SUCCESS1("Querying for a non-existent record returned an %s record.", rrtypename);
}

int check_can_get_nsec(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_negative(ns_name, buf, buf_len, "bogusdnstest.dnssec-tools.org", ns_t_nsec, "NSEC");
}

int check_can_get_nsec3(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_negative(ns_name, buf, buf_len, "foobardedabadoo.org", ns_t_nsec3, "NSEC3");
}

#ifndef VAL_NO_ASYNC
void _check_negative_async_response(u_char *response, size_t response_size,
                                    int rc, int *testStatus, char *buf, size_t buf_len, void *localData) {
    int             rrnum;
    int            *expected_type = (int*) localData;
    int             rrtype = *expected_type;


    if (rc != SR_UNSET)
        SET_ERROR("Query for a negative response failed to get an answer entirely");

    rrnum = count_types(response, response_size, buf, buf_len, rrtype, ns_s_ns, "XXXUNKOWN");
    free(expected_type);

    if (rrnum <= 0 && rrtype == ns_t_nsec)
        SET_ERROR("Failed to find an expected NSEC record in a query for a record that doesn't exist.");
    if (rrnum <= 0)
        SET_ERROR("Failed to find an expected NSEC3 record in a query for a record that doesn't exist.");

    if (rrtype == ns_t_nsec)
        SET_SUCCESS("Querying for a non-existent record returned an NSEC record.");
    SET_SUCCESS("Querying for a non-existent record returned an NSEC3 record.");
}

int check_can_get_negative_async(char *ns_name, char *buf, size_t buf_len, const char *name, int *testStatus, int rrtype) {
    /* queries with the DO bit and thus a bad query should return an answer with
       an NSEC or NSEC3 record based on the parent zones type. */

    struct name_server *ns;
    struct expected_arrival *ea;
    int *expected_type = (int *) malloc(sizeof(int));

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);

    *expected_type = rrtype;
    ea = res_async_query_send(name, ns_t_a, ns_c_in, ns);
    add_outstanding_async_query(ea, _check_negative_async_response,
                                testStatus, buf, buf_len, expected_type);
    return CHECK_CRITICAL;
}


int check_can_get_nsec_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_negative_async(ns_name, buf, buf_len, "bogusdnstest.dnssec-tools.org", testStatus, ns_t_nsec);
}

int check_can_get_nsec3_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_negative_async(ns_name, buf, buf_len, "foobardedabadoo.org", testStatus,  ns_t_nsec3);
}
#endif /* VAL_NO_ASYNC */

int check_can_get_type(char *ns_name, char *buf, size_t buf_len, const char *name, const char *asciitype, int *testStatus,
                       int rrtype, const char *rrtypename) {
    /* queries with the DO bit and thus should return an answer with
       the DO bit as well.  It should additionall have at least one
       RRSIG record. */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;

    int             rrnum;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);

    rc = get(name, rrtype, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("Querying for a particular type failed to get a response");

    rrnum = count_types(response, len, buf, buf_len, rrtype, ns_s_an, rrtypename);

    free_name_server(&ns);

    if (rrnum <= 0) {
        snprintf(buf, buf_len, "Error: Failed to retrieve a record of type %s", asciitype);
        return CHECK_FAILED;
    }

    snprintf(buf, buf_len, "Success: Successfully retrieved a record of type %s", asciitype);

    return CHECK_SUCCEEDED;
}

int check_can_get_dnskey(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_type(ns_name, buf, buf_len, "dnssec-tools.org", "DNSKEY", testStatus, ns_t_dnskey, "DNSKEY");
}

int check_can_get_ds(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_type(ns_name, buf, buf_len, "dnssec-tools.org", "DS", testStatus, ns_t_ds, "DS");
}

#ifndef VAL_NO_ASYNC
int check_can_get_type_async(char *ns_name, char *buf, size_t buf_len, const char *name, const char *asciitype,
                             int *testStatus, int rrtype, const char *rrtypename) {
    /* queries with the DO bit and thus a bad query should return an answer with
       an NSEC or NSEC3 record based on the parent zones type. */

    struct name_server *ns;
    struct expected_arrival *ea;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);

    ea = res_async_query_send(name, rrtype, ns_c_in, ns);
    add_outstanding_async_query(ea, _check_has_one_type_async,
                                testStatus, buf, buf_len, malloc_async_info(rrtype, rrtypename));
    return CHECK_CRITICAL;
}

int check_can_get_dnskey_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_type_async(ns_name, buf, buf_len, "dnssec-tools.org", "DNSKEY", testStatus, ns_t_dnskey, "DNSKEY");
}

int check_can_get_ds_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    return check_can_get_type_async(ns_name, buf, buf_len, "dnssec-tools.org", "DS", testStatus, ns_t_ds, "DS");
}


#endif /* VAL_NO_ASYNC */

int check_can_get_signed_dname(char *ns_name, char *buf, size_t buf_len, const char *name, int rrtype, const char *rrtypename) {
    // XXX
}


#ifndef VAL_NO_ASYNC
void _check_dname_async_response(u_char *response, size_t response_size,
                                 int rc, int *testStatus, char *buf, size_t buf_len, void *localData) {
    int             rrnum;
    ns_msg          handle;
    ns_rr           rr;

    if (rc != SR_UNSET)
        SET_ERROR("Query for a dname response failed to get an answer entirely");


    /* Check for DNAME */
    rrnum = count_types(response, response_size, buf, buf_len, ns_t_dname, ns_s_an, "DNAME");

    if (rrnum <= 0)
        SET_ERROR("Failed to find an expected DNAME record.");



    /* Check for an RRSIG that signs the DNAME */
    if (ns_initparse(response, response_size, &handle) < 0)
        SET_ERROR("Fatal internal error: failed to init parser");
    rrnum = 0;
    for (;;) {
        if (ns_parserr(&handle, ns_s_an, rrnum, &rr)) {
            if (errno != ENODEV) {
                /* parse error */
                SET_ERROR("failed to parse a returned additional RRSET");
            }
            break; /* out of data */
        }
        if (ns_rr_type(rr) == ns_t_rrsig) {
            // XXX: check signing type
            SET_SUCCESS("Querying for a record in a DNAMEd zone returned a DNAME and a signature.");
        }
        rrnum++;
    }

    SET_ERROR("Failed to find an expected RRSIG on the DNAME record.");
}

int check_can_get_signed_dname_async(char *ns_name, char *buf, size_t buf_len, int *testStatus) {
    /* queries with the DO bit for something that should be DNAMEd to elsewhere.  The answer should have both a DNAME record,
     * and a signature on that record. The CNAME is optional so we don't check it.
     */

    struct name_server *ns;
    struct expected_arrival *ea;

    ns = _parse_name_server(ns_name, SR_QUERY_VALIDATING_STUB_FLAGS | SR_QUERY_RECURSE);

    ea = res_async_query_send("good-a.dname-good-ns.test.dnssec-tools.org", ns_t_a, ns_c_in, ns);
    add_outstanding_async_query(ea, _check_dname_async_response,
                                testStatus, buf, buf_len, NULL);
    return CHECK_CRITICAL;
}

#endif /* VAL_NO_ASYNC */
