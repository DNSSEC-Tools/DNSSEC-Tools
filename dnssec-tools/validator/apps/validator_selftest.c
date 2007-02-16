/*
// validator tests
//
// example file format:
//
// # a suite for nsec3
// nsec3:
// "Test Case 2" www.n0.n1u.ws.nsec3.org ns_c_in ns_t_a
//     VAL_PROVABLY_UNSECURE;
// "Test Case 3" www.n3.n1s.ws.nsec3.org ns_c_in ns_t_a,
//     VAL_SUCCESS;
*/

#include "validator-config.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <sys/file.h>

#include <arpa/inet.h>
#include <resolv.h>

#include <validator/resolver.h>
#include <validator/val_errors.h>
#include "validator_driver.h"

typedef struct testcase_st {
    char               *desc;
    char               *qn;
    u_int16_t           qc;
    u_int16_t           qt;
    int                 qr[MAX_TEST_RESULTS];
    struct testcase_st *next;
} testcase;

typedef struct testsuite_st {
    char                *name;
    testcase            *head;
    struct testsuite_st *next;
} testsuite;

static testsuite * testsuite_head = NULL;

extern int
val_get_token(FILE * conf_ptr,
          int *line_number,
          char *conf_token,
          int conf_limit, int *endst, char comment_c, char endstmt_c);


/*
 * parse dns class
 *
 * expects an integer or literal value, null terminated, with no
 * leading whitespace.
 *
 * returns dns class, or 0 on error.
 */
static u_int16_t
vtc_parse_class(const char *dns_class)
{
    u_int16_t rtn;
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
            rtn = (u_int16_t)rc;
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
static u_int16_t
vtc_parse_type(const char *dns_class)
{
    u_int16_t rtn;
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
            rtn = (u_int16_t)rc;
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
        {"INDETERMINATE", VAL_INDETERMINATE},
        {"INDETERMINATE_DS", VAL_INDETERMINATE},
        {"INDETERMINATE_PROOF",  VAL_INDETERMINATE},
        {"BOGUS", VAL_BOGUS},
        {"BOGUS_PROOF", VAL_BOGUS},
        {"INCOMPLETE_PROOF", VAL_BOGUS},
        {"IRRELEVANT_PROOF", VAL_BOGUS},
        {"BOGUS_UNPROVABLE", VAL_BOGUS},
        {"VERIFIED_CHAIN", VAL_VERIFIED_CHAIN},
        {"NOTRUST", VAL_VERIFIED_CHAIN},
        {"SUCCESS", (VAL_VERIFIED_CHAIN | VAL_FLAG_CHAIN_COMPLETE)},
        {"BOGUS_PROVABLE", (VAL_BOGUS | VAL_FLAG_CHAIN_COMPLETE)},
        {"PROVABLY_UNSECURE", ((VAL_ERROR+1) | VAL_FLAG_CHAIN_COMPLETE)},
        {"IGNORE_VALIDATION", ((VAL_ERROR+2) | VAL_FLAG_CHAIN_COMPLETE)},
        {"TRUSTED_ZONE",      ((VAL_ERROR+3) | VAL_FLAG_CHAIN_COMPLETE)},
        {"UNTRUSTED_ZONE",    ((VAL_ERROR+4) | VAL_FLAG_CHAIN_COMPLETE)},
        {"LOCAL_ANSWER",      ((VAL_ERROR+5) | VAL_FLAG_CHAIN_COMPLETE)},
        {"BARE_RRSIG",        ((VAL_ERROR+6) | VAL_FLAG_CHAIN_COMPLETE)},
        {"TRUSTED_ANSWER",    ((VAL_ERROR+7) | VAL_FLAG_CHAIN_COMPLETE)},
        {"VALIDATED_ANSWER",  ((VAL_ERROR+8) | VAL_FLAG_CHAIN_COMPLETE)},
        {"UNTRUSTED_ANSWER",  ((VAL_ERROR+9) | VAL_FLAG_CHAIN_COMPLETE)},
        {"NONEXISTENT_NAME",  ((VAL_ERROR+10) | VAL_FLAG_CHAIN_COMPLETE)},
        {"NONEXISTENT_TYPE",  ((VAL_ERROR+11) | VAL_FLAG_CHAIN_COMPLETE)},
        {"NONEXISTENT_NAME_NOCHAIN", ((VAL_ERROR+12) | VAL_FLAG_CHAIN_COMPLETE)},
        {"NONEXISTENT_TYPE_NOCHAIN", ((VAL_ERROR+13) | VAL_FLAG_CHAIN_COMPLETE)},
        {NULL, 0}
    };


    if (0 == strncasecmp(result, "VAL_", 4))
        result += 4;

    for (i = 0; rm[i].name; ++ i)
        if (0 == strcasecmp(result, rm[i].name))
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
    FILE           *fp;
    int             fd;
    struct flock    fl;
    int             retval = VAL_NO_ERROR, endst = 0;
    char            token[1025];
    int             line_number = 1;
    testsuite      *curr_suite = NULL;
    testcase       *tmp_case = NULL, *tail = NULL;
   
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        return VAL_CONF_NOT_FOUND;
    }
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_RDLCK;
    fcntl(fd, F_SETLKW, &fl);
    fl.l_type = F_UNLCK;

    fp = fdopen(fd, "r");
    if (fp == NULL) {
        fcntl(fd, F_SETLKW, &fl);
        close(fd);
        return VAL_INTERNAL_ERROR;
    }

    testsuite_head = calloc(1, sizeof(*curr_suite));
    if (NULL == testsuite_head) {
        fcntl(fd, F_SETLKW, &fl);
        fclose(fp);
        return VAL_OUT_OF_MEMORY;
    }
    testsuite_head->name = "";
    tail = testsuite_head->head;
    curr_suite = testsuite_head;

    for (; !feof(fp) && (VAL_NO_ERROR == retval); ++line_number) {
        char * pos;
        int i;

        retval = val_get_token(fp, &line_number, token, sizeof(token),
                           &endst, '#', ';');
        if ((VAL_NO_ERROR != retval) || feof(fp))
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

            retval = val_get_token(fp, &line_number, token, sizeof(token),
                                   &endst, '#', ';');
            if (VAL_NO_ERROR != retval)
                break;
            if (endst || feof(fp)) {
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
        
        retval = val_get_token(fp, &line_number, token, sizeof(token),
                           &endst, '#', ';');
        if (VAL_NO_ERROR != retval)
            break;
        if (endst || feof(fp)) {
            retval = VAL_CONF_PARSE_ERROR;
            break;
        }
        tmp_case->qn = strdup(token);
        if (NULL == tmp_case->qn) {
            retval = VAL_OUT_OF_MEMORY;
            break;
        }
        
        retval = val_get_token(fp, &line_number, token, sizeof(token),
                           &endst, '#', ';');
        if (VAL_NO_ERROR != retval)
            break;
        if (endst || feof(fp)) {
            retval = VAL_CONF_PARSE_ERROR;
            break;
        }
        tmp_case->qc = vtc_parse_class(token);
        if (0 == tmp_case->qc) {
            val_log(NULL, LOG_ERR, "invalid class %s", token);
            retval = VAL_CONF_PARSE_ERROR;
            break;
        }
        
        retval = val_get_token(fp, &line_number, token, sizeof(token),
                           &endst, '#', ';');
        if (VAL_NO_ERROR != retval)
            break;
        if (endst || feof(fp)) {
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
        while (!endst && !feof(fp) && (i<MAX_TEST_RESULTS)) {
            retval = val_get_token(fp, &line_number, token, sizeof(token),
                               &endst, '#', ';');
            if (VAL_NO_ERROR != retval)
                break;
            if (!feof(fp) || endst) {
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

    fcntl(fd, F_SETLKW, &fl);
    fclose(fp);

    if (retval != VAL_NO_ERROR) {
        val_log(NULL, LOG_ERR, "Error around line %d of %s", line_number-1,
            filename);
        exit(2);
    }

    return retval;
}

int
run_test_suite(val_context_t *context, int tcs, int tce, testsuite *suite,
               int doprint)
{
    int             rc, failed = 0, run_cnt = 0, i, tc_count;
    u_char          name_n[NS_MAXCDNAME];
    struct val_response *resp;
    testcase        *curr_test;

    if (NULL == suite)
        return 1;
    
    /*
     * Count the number of testcase entries 
     */
    tc_count = 0;
    curr_test = suite->head;
    for (i = 0; curr_test != NULL; i++, curr_test = curr_test->next)
        tc_count++;
    curr_test = suite->head;

    if (-1 == tce)
        tce = tc_count - 1;

    if ((tce >= tc_count) || (tcs >= tc_count)) {
        fprintf(stderr,
                "Invalid test case number (must be 0-%d)\n", tc_count);
        return 1;
    }

    fprintf(stderr, "Suite '%s': Running %d tests\n", suite->name, tc_count);
    resp = NULL;
    for (i = tcs;
         curr_test != NULL && curr_test->desc != NULL && i <= tce;
         curr_test = curr_test->next) {

        ++run_cnt;
        fprintf(stderr, "%d: ", ++i);
        if (ns_name_pton(curr_test->qn, name_n, NS_MAXCDNAME) == -1) {
            fprintf(stderr, "Cannot convert %s to wire format\n",
                    curr_test->qn);
            ++failed;
            continue;
        }
        rc = sendquery(context, curr_test->desc,
                       name_n, curr_test->qc,
                       curr_test->qt, curr_test->qr, 0, &resp);
        if (doprint) {
            fprintf(stderr, "%s: ****RESPONSE**** \n", curr_test->desc);
            print_val_response(resp);
        }

        if (resp) {
            val_free_response(resp);
            resp = NULL;
        }

        if (rc)
            ++failed;
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "Suite '%s': Final results: %d/%d tests failed\n",
            suite->name, failed, run_cnt);

    return 0;
}

int
self_test(val_context_t *context, int tcs, int tce, const char *suites,
          int doprint)
{
    testsuite *suite;
    int rc;

    if (NULL == testsuite_head)
        read_val_testcase_file(VALIDATOR_TESTCASES);

    suite = testsuite_head;

    if (NULL == suites) {

        while(NULL != suite) {
            rc = run_test_suite(context, tcs, tce, suite, doprint);
            /** does rc mean anything? */
            suite = suite->next;
        }
    }
    else {
        char *next, *name;
        name = strdup(suites);
        while(name && *name) {
            
            next = strchr(name, ':');
            if (NULL != next)
                *next++ = 0;


            suite = find_suite(name);
            if (NULL == suite)
                fprintf(stderr, "unknown suite %s\n", name);
            else {
                rc = run_test_suite(context, tcs, tce, suite, doprint);
                /** does rc mean anything? */
            }
            
            name = next;
        }
    }

    return 0;
}
