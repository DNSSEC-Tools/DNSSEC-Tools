/*
// validator tests
//
// example file format:
//
// # a suite for nsec3
// nsec3:
// "Test Case 2" www.n0.n1u.ws.nsec3.org ns_c_in ns_t_a
//     VAL_PINSECURE;
// "Test Case 3" www.n3.n1s.ws.nsec3.org ns_c_in ns_t_a,
//     VAL_SUCCESS;
*/

#include "validator-config.h"
#include <validator/validator.h>
#include <validator/resolver.h>
#include "validator_driver.h"

typedef struct testcase_st {
    char               *desc;
    char               *qn;
    int                 qc;
    int                 qt;
    int                 qr[MAX_TEST_RESULTS];
#ifndef VAL_NO_ASYNC
    val_async_status   *as;
#endif
    struct val_response resp;
    struct testcase_st *next;
} testcase;

typedef struct testsuite_st {
    char                *name;
    testcase            *head;
    int                 in_flight;
    int                 remaining;
    struct testsuite_st *next;
} testsuite;

static testsuite * testsuite_head = NULL;

extern int             
val_get_token(char **buf_ptr,
              char *end_ptr,
              int *line_number,
              char *conf_token,
              int conf_limit, int *endst, 
              const char *comment_c, char endstmt_c,
              int ignore_space);

static void
selftest_cleanup(void)
{
    testsuite *tmp_s;
    testcase  *tmp_c;

    while (NULL != testsuite_head) {
        tmp_s = testsuite_head;
        FREE(tmp_s->name);
        while (NULL != (tmp_c = tmp_s->head)) {
            FREE(tmp_c->desc);
            FREE(tmp_c->qn);
            tmp_s->head = tmp_c->next;
            FREE(tmp_c);
        }
        testsuite_head = tmp_s->next;
        FREE(tmp_s);
    }
}


/*
 * parse dns class
 *
 * expects an integer or literal value, null terminated, with no
 * leading whitespace.
 *
 * returns dns class, or 0 on error.
 */
static int
vtc_parse_class(const char *dns_class)
{
    int rtn;
    int       rc;
    
    if (NULL == dns_class)
        return 0;

    /*
     * try the easy case first
     */
    if (isdigit(*dns_class)) {
        rc = atoi(dns_class);
        if ((rc < 0) || (rc >= 0xffff))
            rtn = 0;
        else
            rtn = rc;
        return rtn;
    }

    /*
     * try various literal schemes
     */
    if (0 == strncasecmp(dns_class, "ns_c_", 5))
        dns_class += 5;
    else if (0 == strncasecmp(dns_class, "c_", 2))
        dns_class += 2;

    rtn = res_nametoclass(dns_class, &rc);
    if (! rc)
        rtn = 0;

    return rtn;
}

/*
 * parse dns type
 *
 * expects an integer or literal value, null terminated, with no
 * leading whitespace.
 *
 * returns dns type, or 0 on error.
 */
static int
vtc_parse_type(const char *dns_class)
{
    int rtn;
    int       rc;
    
    if (NULL == dns_class)
        return 0;

    /*
     * try the easy case first
     */
    if (isdigit(*dns_class)) {
        rc = atoi(dns_class);
        if ((rc < 0) || (rc >= 0xffff))
            rtn = 0;
        else
            rtn = rc;
        return rtn;
    }

    /*
     * try various literal schemes
     */
    if (0 == strncasecmp(dns_class, "ns_t_", 5))
        dns_class += 5;
    else if (0 == strncasecmp(dns_class, "t_", 5))
        dns_class += 2;

    rtn = res_nametotype(dns_class, &rc);
    if (! rc)
        rtn = 0;

    return rtn;
}

static int
vtc_parse_result(const char *result)
{
    typedef struct result_map_st {
        const char *name;
        int   val;
    } result_map;
    int i;
    result_map rm[] = {
        {"BOGUS", VAL_BOGUS},
        {"BOGUS_PROOF", VAL_BOGUS},
        {"INCOMPLETE_PROOF", VAL_BOGUS},
        {"IRRELEVANT_PROOF", VAL_BOGUS},
        {"DNS_ERROR", VAL_DNS_ERROR},
        {"NOTRUST", VAL_NOTRUST},
        {"SUCCESS", VAL_SUCCESS},
        {"NONEXISTENT_NAME", VAL_NONEXISTENT_NAME},
        {"NONEXISTENT_TYPE", VAL_NONEXISTENT_TYPE},
        {"NONEXISTENT_NAME_NOCHAIN", VAL_NONEXISTENT_NAME_NOCHAIN},
        {"NONEXISTENT_TYPE_NOCHAIN", VAL_NONEXISTENT_TYPE_NOCHAIN},
        {"PINSECURE", VAL_PINSECURE},
        {"PINSECURE_UNTRUSTED", VAL_PINSECURE_UNTRUSTED},
        {"BARE_RRSIG", VAL_BARE_RRSIG},
        {"IGNORE_VALIDATION", VAL_IGNORE_VALIDATION},
        {"UNTRUSTED_ZONE", VAL_UNTRUSTED_ZONE},
        {"OOB_ANSWER", VAL_OOB_ANSWER},
        {"TRUSTED_ANSWER", VAL_TRUSTED_ANSWER},
        {"VALIDATED_ANSWER", VAL_VALIDATED_ANSWER},
        {"UNTRUSTED_ANSWER", VAL_UNTRUSTED_ANSWER},
        {NULL, 0}
    };


    if (0 == strncasecmp(result, "VAL_", 4))
        result += 4;

    for (i = 0; rm[i].name; ++ i)
        if (0 == strncasecmp(result, rm[i].name, strlen(rm[i].name)))
            return rm[i].val;

    return 0;
}

static testsuite *
find_suite(const char *name)
{
    testsuite      *curr_suite = testsuite_head;

    for(; NULL != curr_suite; curr_suite = curr_suite->next)
        if (0 == strcmp(name, curr_suite->name))
            return curr_suite;
    
    return NULL;
}

/*
 * Make sense of the validator testcase configuration file
 */
int
read_val_testcase_file(const char *filename)
{
    int             fd;
#ifdef HAVE_FLOCK
    struct flock    fl;
#endif
    int             retval = VAL_NO_ERROR, endst = 0;
    char            token[1025];
    int             line_number = 1;
    testsuite      *curr_suite = NULL;
    testcase       *tmp_case = NULL, *tail = NULL;
    char *buf_ptr, *end_ptr;
    char *buf = NULL;
    struct stat sb;
   
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        return VAL_CONF_NOT_FOUND;
    }
#ifdef HAVE_FLOCK
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_RDLCK;
    fcntl(fd, F_SETLKW, &fl);
#endif

    if (0 != fstat(fd, &sb)) {
        retval = VAL_CONF_NOT_FOUND;
        goto err;
    }

    buf = (char *) MALLOC (sb.st_size * sizeof(char));
    if (buf == NULL) {
        retval = VAL_OUT_OF_MEMORY;
        goto err;
    }
    buf_ptr = buf;
    end_ptr = buf+sb.st_size;
   
    if (-1 == read(fd, buf, sb.st_size)) {
        retval = VAL_CONF_NOT_FOUND;
        goto err;
    }
 
    testsuite_head = calloc(1, sizeof(*curr_suite));
    if (NULL == testsuite_head) {
        retval = VAL_OUT_OF_MEMORY;
        goto err;
    }
    testsuite_head->name = strdup("");
    tail = testsuite_head->head;
    curr_suite = testsuite_head;

    for (; (buf_ptr < end_ptr) && (VAL_NO_ERROR == retval); ++line_number) {
        char * pos;
        int i;

        retval = val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token),
                           &endst, "#", ';', 0);
        if ((VAL_NO_ERROR != retval) || (buf_ptr >= end_ptr))
            break;
        if (endst) {
            retval = VAL_CONF_PARSE_ERROR;
            break;
        }

        pos = strchr(token, ':');
        /** suites end with ':' */
        if ((NULL != pos) && (0 == pos[1])) {
            *pos = 0;

            curr_suite = find_suite(token);
            if (NULL == curr_suite) {
                /** new suite */
                curr_suite = calloc(1, sizeof(*curr_suite));
                if (NULL == curr_suite) {
                    retval = VAL_OUT_OF_MEMORY;
                    break;
                }
                curr_suite->name = strdup(token);
                tail = NULL;
                curr_suite->next = testsuite_head;
                testsuite_head = curr_suite;
            }
            else {
                /** find tail of existing suite */
                tail = curr_suite->head;
                while(tail && tail->next)
                    tail = tail->next;
            }

            retval = val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token),
                                   &endst, "#", ';', 0);
            if (VAL_NO_ERROR != retval)
                break;
            if (endst || (buf_ptr >= end_ptr)) {
                retval = VAL_CONF_PARSE_ERROR;
                break;
            }
        }

        /** allocate temp case, if needed */
        if (NULL == tmp_case) {
            tmp_case = calloc(1, sizeof(*tmp_case));
            if (NULL == tmp_case) {
                retval = VAL_OUT_OF_MEMORY;
                break;
            }
        }
        else {
            if (NULL != tmp_case->desc)
                free(tmp_case->desc);
            if (NULL != tmp_case->qn)
                free(tmp_case->qn);
        }
            
        tmp_case->desc = strdup(token);
        if (NULL == tmp_case->desc) {
            retval = VAL_OUT_OF_MEMORY;
            break;
        }
        
        retval = val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token),
                           &endst, "#", ';', 0);
        if (VAL_NO_ERROR != retval)
            break;
        if (endst || (buf_ptr >= end_ptr)) {
            retval = VAL_CONF_PARSE_ERROR;
            break;
        }
        tmp_case->qn = strdup(token);
        if (NULL == tmp_case->qn) {
            retval = VAL_OUT_OF_MEMORY;
            break;
        }
        
        retval = val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token),
                           &endst, "#", ';', 0);
        if (VAL_NO_ERROR != retval)
            break;
        if (endst || (buf_ptr >= end_ptr)) {
            retval = VAL_CONF_PARSE_ERROR;
            break;
        }
        tmp_case->qc = vtc_parse_class(token);
        if (0 == tmp_case->qc) {
            val_log(NULL, LOG_ERR, "invalid class %s", token);
            retval = VAL_CONF_PARSE_ERROR;
            break;
        }
        
        retval = val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token),
                           &endst, "#", ';', 0);
        if (VAL_NO_ERROR != retval)
            break;
        if (endst || (buf_ptr >= end_ptr)) {
            retval = VAL_CONF_PARSE_ERROR;
            break;
        }
        tmp_case->qt = vtc_parse_type(token);
        if (0 == tmp_case->qt) {
            val_log(NULL, LOG_ERR, "invalid type %s", token);
            retval = VAL_CONF_PARSE_ERROR;
            break;
        }

        i = 0;
        while (!endst && (buf_ptr <end_ptr) && (i<MAX_TEST_RESULTS)) {
            retval = val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token),
                               &endst, "#", ';', 0);
            if (VAL_NO_ERROR != retval)
                break;
            if ((buf_ptr < end_ptr) || endst) {
                tmp_case->qr[i] = vtc_parse_result(token);
                if (0 == tmp_case->qr[i]) {
                    val_log(NULL, LOG_ERR, "invalid result %s", token);
                    retval = VAL_CONF_PARSE_ERROR;
                    break;
                }
            }
            if (endst)
                break;
            ++i;
        }
        if (!endst)
            retval = VAL_CONF_PARSE_ERROR;
        if (VAL_NO_ERROR != retval)
            break;

        if (NULL == tail) {
            tail = curr_suite->head = tmp_case;
        }
        else {
            tail->next = tmp_case;
            tail = tail->next;
        }
        tmp_case = NULL;
    } 

    if (NULL != tmp_case) {
        if (NULL != tmp_case->desc)
            free(tmp_case->desc);
        if (NULL != tmp_case->qn)
            free(tmp_case->qn);
        free(tmp_case);
    }

#ifdef DEBUG_TESTING
    for(tail = testcases; tail; tail = tail->next) {
        int i;
        val_log(NULL, LOG_DEBUG, "desc '%s' query '%s', %d %d",
                tail->desc, tail->qn, tail->qc,
                tail->qt);
        for (i = 0; i < MAX_TEST_RESULTS; ++i) {
            if (0 == tail->qr[i])
                break;
            val_log(NULL, LOG_DEBUG, " result %d %d", i, tail->qr[i]);
        }
    }
#endif

err:
#ifdef HAVE_FLOCK
    fl.l_type = F_UNLCK;
    fcntl(fd, F_SETLKW, &fl);
#endif
    close(fd);
    if (buf)
        free(buf);

    if (retval != VAL_NO_ERROR) {
        val_log(NULL, LOG_ERR, "Error around line %d of %s", line_number-1,
            filename);
        exit(2);
    }

    return retval;
}

int
run_suite(val_context_t *context, testcase *curr_test, int tcs, int tce,
          u_int32_t flags, int *failed, int doprint)
{
    int i, rc, run = 0;
    struct val_response resp;

    memset(&resp, 0, sizeof(resp));

    for (i = tcs;
         curr_test != NULL && curr_test->desc != NULL && i <= tce;
         curr_test = curr_test->next) {

        ++run;
        fprintf(stderr, "%d: ", ++i);
        rc = sendquery(context, curr_test->desc,
                       curr_test->qn, curr_test->qc,
                       curr_test->qt, flags, curr_test->qr, 0, &resp);
        if (doprint) {
            fprintf(stderr, "%s: ****RESPONSE**** \n", curr_test->desc);
            print_val_response(&resp);
        }

        if (resp.vr_response)
            FREE(resp.vr_response);

        if (rc)
            ++(*failed);
        fprintf(stderr, "\n");
    }

    return run;
}

#ifndef VAL_NO_ASYNC
int
suite_async_callback(val_async_status *as)
{
    testsuite *suite;
    if (NULL == as || NULL == as->val_as_cb_user_ctx) {
        val_log(as->val_as_ctx, LOG_ERR, "bad parameter for callback\n");
        return VAL_BAD_ARGUMENT;
    }

    suite = (testsuite *)as->val_as_cb_user_ctx;

    --suite->in_flight;
    --suite->remaining;

    val_log(as->val_as_ctx, LOG_INFO,
            "query completed; %d in flight, %d remaining\n",
            suite->in_flight, suite->remaining);
    return VAL_NO_ERROR;
}

int
run_suite_async(val_context_t *context, testsuite *suite, testcase *start_test,
                int tcs, int tce, u_int32_t flags, int *failed, int doprint,
                int max_in_flight)
{
    int i, j, rc, run = 0, burst = 5, nfds, unsent, ready;
    fd_set             activefds;
    struct timeval     timeout, now;
    testcase          *curr_test = start_test;

    if (!curr_test || !suite)
        return 0;

    i = tcs;
    suite->remaining = tce - tcs + 1;
    suite->in_flight = 0;

    while (suite->remaining || suite->in_flight) {
        /** send up to burst queries */
        for (j = 0;
             suite->in_flight < max_in_flight &&
                 i <= tce &&
                 j < burst &&
                 curr_test;
             ++i, ++j, curr_test = curr_test->next) {
            rc = val_async_submit(context, curr_test->qn, curr_test->qc,
                                  curr_test->qt, flags, &curr_test->as);
            if ((rc != VAL_NO_ERROR) || (!curr_test->as)) {
                val_log(context, LOG_ERR, "error sending %i %s\n", i,
                        curr_test->desc);
                continue;
            }
            memset(&curr_test->resp, 0, sizeof(curr_test->resp));
            curr_test->as->val_as_result_cb = &suite_async_callback;
            curr_test->as->val_as_cb_user_ctx = suite;
            ++run;
            ++suite->in_flight;
        }
        unsent = tce - i + 1;

        /** set up fdset/timeout for select */
        FD_ZERO(&activefds);
        nfds = 0;
        timeout.tv_sec = LONG_MAX;
        val_async_select_info(context, &activefds, &nfds, &timeout);
        if (0 == nfds) {
            val_log(context, LOG_DEBUG,
                    "no file decsriptors set for requests\n");
            rc = val_async_check(context, &activefds, &nfds, 0);
            val_async_select_info(context, &activefds, &nfds, &timeout);
        }
        /** adjust libsres absolute timeout to select relative timeout */
        if (timeout.tv_sec == LONG_MAX)
            timeout.tv_sec = 1;
        else {
            gettimeofday(&now, NULL);
            if (timeout.tv_sec > now.tv_sec)
                timeout.tv_sec -= now.tv_sec;
            else
                timeout.tv_sec = 0;
        }

        /** don't sleep too long if more queries are waiting to be sent */
        if (unsent && suite->in_flight < max_in_flight && timeout.tv_sec > 0) {
            val_log(context, LOG_DEBUG,
                    "reducing timeout so we can send more requests\n");
            timeout.tv_sec = 0;
            timeout.tv_usec = 500;
        }
        val_log(context, LOG_INFO,
                "select @ %d, %d fds, timeout %ld, %d in flight, %d unsent\n",
               now.tv_sec, nfds, timeout.tv_sec, suite->in_flight, unsent);
        if ((nfds > 0) && (val_log_debug_level() >= LOG_DEBUG)) {
            val_log(context, LOG_DEBUG, "activefds: ");
            i = getdtablesize();
            if (i > FD_SETSIZE)
                i = FD_SETSIZE;
            for (--i; i >= 0; --i)
                if (FD_ISSET(i, &activefds)) {
                    val_log(context, LOG_DEBUG, "%d ", i);
                }
            val_log(context, LOG_DEBUG, "\n");
        }

        fflush(stdout);
        ready = select(nfds, &activefds, NULL, NULL, &timeout);
        gettimeofday(&now, NULL);
        val_log(context, LOG_DEBUG, "%d fds @ %d\n", ready, now.tv_sec);
        if (ready < 0 && errno == EINTR)
            continue;

        /** no ready fd; check for timeouts/retries */
        if (ready == 0) {
            gettimeofday(&now, NULL);
            now.tv_usec = 0;
            val_log(context, LOG_DEBUG, "timeout @ %ld\n", now.tv_sec);
        }

        rc = val_async_check(context, &activefds, &nfds, 0);

    } /* while(remaining) */

    return run;
}
#endif /* ndef VAL_NO_ASYNC */

int
run_test_suite(val_context_t *context, int tcs, int tce, u_int32_t flags,
               testsuite *suite, int doprint, int max_in_flight)
{
    int             failed = 0, run_cnt = 0, i, tc_count, s, us;
    testcase        *curr_test, *start_test = NULL;
    struct timeval     now, start;

    if (NULL == suite)
        return 1;

    /*
     * Count the number of testcase entries
     */
    tc_count = 0;
    curr_test = suite->head;
    for (i = 0; curr_test != NULL; curr_test = curr_test->next) {
        if (++i == tcs)
            start_test = curr_test;
        ++tc_count;
    }
    if (!start_test)
        start_test = suite->head;

    if (-1 == tce)
        tce = tc_count - 1;

    if ((tce >= tc_count) || (tcs >= tc_count)) {
        fprintf(stderr,
                "Invalid test case number (must be 0-%d)\n", tc_count);
        return 1;
    }
    tc_count = tce - tcs + 1;

    fprintf(stderr, "Suite '%s': Running %d tests\n", suite->name, tc_count);

    gettimeofday(&start, NULL);
#ifndef VAL_NO_ASYNC
    if (max_in_flight > 1)
        run_cnt = run_suite_async(context, suite, start_test, tcs, tce, flags,
                                  &failed, doprint, max_in_flight);
    else
#endif /* ndef VAL_NO_ASYNC */
        run_cnt = run_suite(context, start_test, tcs, tce, flags, &failed,
                            doprint);

    gettimeofday(&now, NULL);

    now.tv_sec--;
    now.tv_usec += 1000000L;
    s = now.tv_sec - start.tv_sec;
    us = now.tv_usec - start.tv_usec;
    if (us > 1000000L){
        us -= 1000000L;
        s++;
    }
    fprintf(stderr, "Suite '%s': Final results: %d/%d succeeded (%d failed)\n",
            suite->name, run_cnt - failed, run_cnt, failed);
    fprintf(stderr, "   runtime was %d.%d seconds\n", s, us);

    return 0;
}

int
self_test(val_context_t *context, int tcs, int tce, u_int32_t flags,
          const char *tests_file, const char *suites, int doprint,
          int max_in_flight)
{
    testsuite *suite;
    int rc;

    if (NULL == testsuite_head) {
        if (NULL == tests_file)
            tests_file = VALIDATOR_TESTCASES;
        read_val_testcase_file(tests_file);
        atexit(selftest_cleanup);
    }

    suite = testsuite_head;

    if (NULL == suites) {

        while(NULL != suite) {
            rc = run_test_suite(context, tcs, tce, flags, suite, doprint,
                                max_in_flight);
            /** does rc mean anything? */
            suite = suite->next;
        }
    }
    else {
        char *next, *name, *name_save;
        name = name_save = strdup(suites);
        while(name && *name) {
            
            next = strchr(name, ':');
            if (NULL != next)
                *next++ = 0;


            suite = find_suite(name);
            if (NULL == suite)
                fprintf(stderr, "unknown suite %s\n", name);
            else {
                rc = run_test_suite(context, tcs, tce, flags, suite, doprint,
                                    max_in_flight);
                /** does rc mean anything? */
            }
            
            name = next;
        }
        free(name_save);
    }

    return 0;
}
