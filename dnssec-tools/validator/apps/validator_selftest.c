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

#include "validator/validator-config.h"
#include <validator/validator.h>
#include <validator/resolver.h>
#include "validator_driver.h"

typedef struct testcase_st {
    char               *desc;
    char               *qn; /* name */
    int                 qc; /* class */
    int                 qt; /* type */
    int                 qr[MAX_TEST_RESULTS]; /* expected rc */
    struct timeval      start;
#ifndef VAL_NO_ASYNC
    val_async_status   *as;
#endif
    struct val_response resp;
    struct testcase_st *next;
} testcase;

typedef struct testsuite_st {
    char                *name;
    testcase            *head;
    struct testsuite_st *next;
} testsuite;

typedef struct testsuite_stats_st {
    int                 in_flight;
    int                 remaining;
    int                 failed;
} testsuite_stats;

#ifndef VAL_NO_ASYNC
typedef struct async_cbd_st {
    val_context_t      *ctx;
    testcase           *tc;
    testsuite_stats    *ss;
    int                 doprint;
} async_cbd;
#endif


extern int             
val_get_token(char **buf_ptr,
              char *end_ptr,
              int *line_number,
              char *conf_token,
              int conf_limit, int *endst, 
              const char *comment_c, char endstmt_c,
              int ignore_space);

static void
selftest_cleanup(testsuite *head)
{
    testsuite *tmp_s;
    testcase  *tmp_c;

    while (NULL != head) {
        tmp_s = head;
        FREE(tmp_s->name);
        while (NULL != (tmp_c = tmp_s->head)) {
            FREE(tmp_c->desc);
            FREE(tmp_c->qn);
            tmp_s->head = tmp_c->next;
            FREE(tmp_c);
        }
        head = tmp_s->next;
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
        if (strlen(result) == strlen(rm[i].name) &&
            0 == strncasecmp(result, rm[i].name, strlen(rm[i].name)))
            return rm[i].val;

    return 0;
}

static testsuite *
find_suite(testsuite *head, const char *name)
{
    testsuite      *curr_suite = head;

    for(; NULL != curr_suite; curr_suite = curr_suite->next)
        if (0 == strcmp(name, curr_suite->name))
            return curr_suite;
    
    return NULL;
}

/*
 * Make sense of the validator testcase configuration file
 */
int
read_val_testcase_file(const char *filename, testsuite **head)
{
    int             fd;
#ifdef HAVE_FLOCK
    struct flock    fl;
#endif
    int             retval = VAL_NO_ERROR, endst = 0;
    char            token[1025];
    int             line_number = 1;
    testsuite      *curr_suite = NULL, *testsuite_head = NULL;
    testcase       *tmp_case = NULL, *tail = NULL;
    char *buf_ptr, *end_ptr;
    char *buf = NULL;
    struct stat sb;
   
    if (NULL == filename || NULL == head)
        return VAL_BAD_ARGUMENT;

    *head = NULL;

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

            curr_suite = find_suite(testsuite_head, token);
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

    *head = testsuite_head;

    return retval;
}

int
run_suite(val_context_t *context, testcase *curr_test, int tcs, int tce,
          u_int32_t flags, int *failed, int doprint)
{
    int i, rc, run = 0;
    struct val_response resp;
#ifdef VAL_FD_LEAK_TEST
    int startfd;
#endif

    for (i = tcs;
         curr_test != NULL && curr_test->desc != NULL && i <= tce;
         curr_test = curr_test->next) {

        memset(&resp, 0, sizeof(resp));

#ifdef VAL_FD_LEAK_TEST
        startfd = socket(AF_INET,SOCK_DGRAM,0);
        if (-1 == startfd) {
            fprintf(stderr,"\n\nsocket failed\n");
            break;
        }
        close(startfd);
#endif

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

#ifdef VAL_FD_LEAK_TEST
        rc = socket(AF_INET,SOCK_DGRAM,0);
        if (rc > 0) {
            if (rc != startfd)
                fprintf(stderr,"\n**** end fd %d != start %d\n", rc, startfd);
            else
                fprintf(stderr,"\n**** end fd %d == start %d\n", rc, startfd);
            close(rc);
        }
#endif
    }

    return run;
}

void
print_full_rr(const char *indent, struct val_rr_rec *rr)
{
    struct val_rr_rec *t_rr = rr;
    char buf[1024];

    while (t_rr) {
        printf("\n");
        printf("%srr_status = %s\n", indent, p_ac_status(t_rr->rr_status));
        printf("%srr_data_length = %d\n", indent, (int)t_rr->rr_rdata_length);
        get_hex_string(t_rr->rr_rdata, t_rr->rr_rdata_length, buf, sizeof(buf));
        printf("%srr_data = %s\n", indent, buf);
        t_rr = t_rr->rr_next;
    }
}


void
print_full_rrec(const char *indent, struct val_rrset_rec *rrec)
{
    char name_buf[INET6_ADDRSTRLEN + 1];
    const char *serv;
    struct val_rr_rec *rr;

    if (rrec) {
        printf("%sval_rrset_rcode = %d\n", indent, rrec->val_rrset_rcode);
        printf("%sval_rrset_name = %s\n", indent, rrec->val_rrset_name);
        printf("%sval_rrset_class = %d\n", indent, rrec->val_rrset_class);
        printf("%sval_rrset_type = %d\n", indent, rrec->val_rrset_type);
        printf("%sval_rrset_ttl = %ld\n", indent, rrec->val_rrset_ttl);
        printf("%sval_rrset_section = %d\n", indent, rrec->val_rrset_section);

        serv = val_get_ns_string(rrec->val_rrset_server, name_buf, sizeof(name_buf));
        if (serv == NULL)
            serv = "NULL";
        printf("%sval_rrset_server = %s\n", indent, serv);

        print_full_rr(indent, rrec->val_rrset_data);
        print_full_rr(indent, rrec->val_rrset_sig);
    }
}

void
print_full_ac(const char *indent, struct val_authentication_chain *ac)
{
    char curin[1024];
    struct val_authentication_chain *t_ac = ac;
    char *cp = curin;

    strncpy(curin, indent, sizeof(curin));
    while (t_ac) {
        printf("\n");
        strncat(curin, "\t", sizeof(curin)-(cp++ - curin));
        printf("%sval_rc_status = %s\n", curin, p_ac_status(t_ac->val_ac_status));        
        print_full_rrec(curin, t_ac->val_ac_rrset);
        t_ac = t_ac->val_ac_trust;
    }
}

void
print_full_result(struct val_result_chain *results)
{
    int i;
    struct val_result_chain *res = results;

    while (res) {

        printf("\tval_rc_status = %s\n", p_val_status(res->val_rc_status));        
        printf("\val_rc_alias = %s\n", res->val_rc_alias);

        print_full_rrec("\t\t", res->val_rc_rrset);
        print_full_ac("\t\t", res->val_rc_answer);
        for (i = 0; i < res->val_rc_proof_count; i++) {
            print_full_ac("\t\t", res->val_rc_proofs[i]);
            printf("\n");
        }

        res = res->val_rc_next;
    }
}


#ifndef VAL_NO_ASYNC
int
suite_async_callback(val_async_status *as, int event,
                     val_context_t *ctx, void *cb_data, val_cb_params_t *cbp)
{
    async_cbd *acbd;
    testcase  *tc;
    if ((NULL == cb_data) || (NULL == cbp)) {
        val_log(ctx, LOG_ERR, "bad parameter for callback");
        return VAL_BAD_ARGUMENT;
    }

    acbd = (async_cbd *)cb_data;
    --acbd->ss->in_flight;
    --acbd->ss->remaining;
    tc = acbd->tc;

    val_log(ctx, LOG_INFO,
            "as 0x%x %s query completed; %d in flight, %d remaining",
            as, cbp->name, acbd->ss->in_flight, acbd->ss->remaining);

    if (cbp->retval == VAL_NO_ERROR) {

        int ret_val = compose_answer(tc->qn, tc->qt, tc->qc, cbp->results,
                                     &tc->resp);

        if (VAL_NO_ERROR != ret_val) {
            fprintf(stderr, "%s: \t", tc->desc);
            fprintf(stderr, "FAILED: Error in compose_answer(): %d\n",
                    ret_val);
            ++acbd->ss->failed;
        }
        else {
            if (tc->resp.vr_response == NULL) {
                fprintf(stderr, "FAILED: No response\n");
            } else if (acbd->doprint) {
                print_val_response(&tc->resp);
            }
            FREE(tc->resp.vr_response);

            ret_val = check_results(acbd->ctx, tc->desc, tc->qn, tc->qc, tc->qt,
                                    tc->qr, cbp->results, 0, &tc->start);
            if (0 != ret_val) {
                ++acbd->ss->failed;
            }

            /*
             * print_full_result(cbp->results);
             */
        }

        val_free_result_chain(cbp->results);
        cbp->results = NULL;
    } else {
        fprintf(stderr, "%s: \t", tc->desc);
        fprintf(stderr, "FAILED: Error during async resolution: %s\n",
                p_val_err(cbp->retval));
        ++acbd->ss->failed;
    }

    free(acbd);

    return VAL_NO_ERROR;
}

int
run_suite_async(val_context_t *context, testsuite *suite, testcase *start_test,
                int tcs, int tce, u_int32_t flags, int *failed, int doprint,
                int max_in_flight)
{
    int i, j, rc, run = 0, burst = max_in_flight, nfds, unsent, ready;
    fd_set             activefds;
    struct timeval     timeout, now;
    testcase          *curr_test = start_test;
    async_cbd         *acbd;
    testsuite_stats    suite_stats, *sstats = &suite_stats;

    if (!curr_test || !suite)
        return 0;

    if (tcs > tce) {
        fprintf(stderr,"bad range\n");
        return 0;
    }

    memset(sstats, 0x00, sizeof(suite_stats));
    i = tcs;
    sstats->remaining = tce - tcs + 1;
    sstats->in_flight = 0;
    sstats->failed = 0;
    timeout.tv_sec = 60; /* 1 min */
    timeout.tv_usec = 0;

    while (sstats->remaining) {
        /** send up to burst queries */
        for (j = 0;
             sstats->in_flight < max_in_flight &&
                 i <= tce &&
                 j < burst &&
                 curr_test;
             ++i, ++j, curr_test = curr_test->next) {
            val_log(context, LOG_DEBUG, "starting test %i (max %d) %s", i, tce,
                    curr_test->desc);
            memset(&curr_test->resp, 0, sizeof(curr_test->resp));
            acbd = (async_cbd*) MALLOC(sizeof(async_cbd));
            acbd->ss = sstats;
            acbd->tc = curr_test;
            acbd->ctx = context;
            acbd->doprint = doprint;
            rc = val_async_submit(context, curr_test->qn, curr_test->qc,
                                  curr_test->qt, flags, &suite_async_callback,
                                  acbd, &curr_test->as);
            if ((rc != VAL_NO_ERROR) || (!curr_test->as)) {
                val_log(context, LOG_ERR, "FAILED: error sending test %i: %s (%d)",
                         i, curr_test->desc, rc);
                ++sstats->failed;
                --sstats->remaining;
                continue;
            }
            gettimeofday(&curr_test->start, NULL);
            ++run;
            ++sstats->in_flight;
        }
        unsent = tce - i + 1;

        /** set up fdset/timeout for select */
        FD_ZERO(&activefds);
        nfds = 0;
        /** don't sleep too long if more queries are waiting to be sent */
        if (unsent && sstats->in_flight < max_in_flight && timeout.tv_sec > 0) {
            val_log(context, LOG_DEBUG,
                    "reducing timeout so we can send more requests");
            timeout.tv_sec = 0;
            timeout.tv_usec = 500;
        } else {
            timeout.tv_sec = 60; /* 1 min */
            timeout.tv_usec = 0;
        }
        val_log(context, LOG_INFO,
                "timeout %ld.%ld, %d in flight, %d unsent %d remain",
                timeout.tv_sec, timeout.tv_usec, sstats->in_flight, unsent,
                sstats->remaining);
        val_async_select_info(context, &activefds, &nfds, &timeout);
        if (0 == nfds) {
            val_log(context, LOG_DEBUG,
                    "no file descriptors set! (%d unsent, %d inflight, %d remain)",
                    unsent, sstats->in_flight, sstats->remaining);
            /*
             * maybe socket got closed & need to send next request,
             * or answer is in cache and needs to be processed.
             */
            rc = val_async_check(context, &activefds, &nfds, 0);
            if (0 == sstats->remaining)
                break; /* all callbacks called */
            val_log(context, LOG_DEBUG,
                    "after check (%d unsent, %d inflight, %d remain)",
                    unsent, sstats->in_flight, sstats->remaining);
            val_async_select_info(context, &activefds, &nfds, &timeout);
            if (0 == nfds) {
                if (unsent) {
                    if (sstats->in_flight < max_in_flight)
                        continue; /* submit more if we can */
                } else if (sstats->in_flight) {
                    /*
                     * all queries submitted, some in flight, but no fds
                     * waiting? after we've called val_async_check()?
                     * I don't think we can recover from that, but lets
                     * try just in case.
                     */
                    int prev_inflight = sstats->in_flight;
                    val_log(context, LOG_WARNING,
                            "xxx file descriptors set! (%d inflight)",
                            sstats->in_flight);
                    while (sstats->in_flight) {
                        /** try checking again */
                        rc = val_async_check(context, &activefds, &nfds, 0);
                        if (sstats->in_flight == prev_inflight)
                            break; /* no progress */
                        prev_inflight = sstats->in_flight;
                        val_log(context, LOG_INFO,
                                "xxx progress! (%d inflight)",
                                sstats->in_flight);
                    }
                    if (nfds == 0) {
                        sstats->failed += sstats->in_flight;
                        break;
                    }
                    val_log(context, LOG_INFO,
                            "xxx some file descriptors!" );
                }
            }
        }

        gettimeofday(&now, NULL);
        val_log(context, LOG_INFO,
                "select @ %d, max fd %d, timeout %ld.%ld, %d in flight, %d unsent",
                now.tv_sec, nfds, timeout.tv_sec, timeout.tv_usec,
                sstats->in_flight, unsent);
        if ((nfds > 0) && (val_log_debug_level() >= LOG_DEBUG))
            res_io_count_ready(&activefds, nfds); // debug

        fflush(stdout);
        ready = select(nfds, &activefds, NULL, NULL, &timeout);
        gettimeofday(&now, NULL);
        val_log(context, LOG_DEBUG, "%d fds ready @ %ld.%ld", ready,
                now.tv_sec, now.tv_usec);
        if ((ready > 0) && (val_log_debug_level() >= LOG_DEBUG))
            res_io_count_ready(&activefds, nfds); // debug
        if (ready < 0 && errno == EINTR)
            continue;

        /** no ready fd; check for timeouts/retries */
        if (ready == 0) {
            gettimeofday(&now, NULL);
            val_log(context, LOG_DEBUG, "timeout @ %ld.%ld", now.tv_sec,
                    now.tv_usec);
        }

        rc = val_async_check(context, &activefds, &nfds, 0);

    } /* while(remaining) */

    *failed = sstats->failed;

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
    testsuite *suite, *head;
    int rc;

    if (NULL == tests_file)
        tests_file = VALIDATOR_TESTCASES;
    read_val_testcase_file(tests_file, &head);

    suite = head;

    if (NULL == suites) {

        while(NULL != suite) {
            rc = run_test_suite(context, tcs, tce, flags, suite, doprint,
                                max_in_flight);
            if (rc)
                fprintf(stderr, "bad rc %d from run_test_suite\n", rc);
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


            suite = find_suite(head, name);
            if (NULL == suite)
                fprintf(stderr, "unknown suite %s\n", name);
            else {
                rc = run_test_suite(context, tcs, tce, flags, suite, doprint,
                                    max_in_flight);
                if (rc)
                    fprintf(stderr, "bad rc %d from run_test_suite %s\n",
                            rc, name);
                /** does rc mean anything? */
            }
            
            name = next;
        }
        free(name_save);
    }

    selftest_cleanup(head);

    return 0;
}
