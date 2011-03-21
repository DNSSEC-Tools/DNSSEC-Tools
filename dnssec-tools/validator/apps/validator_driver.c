/*
 * Copyright 2005-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

/*
 * A command-line validator
 *
 * This program validates the <class, type, domain name> query given
 * on the command line, or runs a set of pre-defined test cases if
 * no command line parameters are given
 *
 * It generates an output suitable for consumption by the
 * drawvalmap.pl script.  This output is written to stderr.
 */
#include "validator-config.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <sys/types.h>

#include <sys/socket.h>
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#else
#include "arpa/header.h"
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <validator/resolver.h>
#include <validator/validator.h>
#include "validator_driver.h"

#define	NAME	"validate"
#define	VERS	"version: 1.0"
#define	DTVERS	 "DNSSEC-Tools Version: 1.8"


#define NO_OF_THREADS 0

#if NO_OF_THREADS
#include <pthread.h>
#endif

#define BUFLEN 16000

int             MAX_RESPCOUNT = 10;
int             MAX_RESPSIZE = 8192;

int             listen_fd = -1;
int             done = 0;


#ifdef HAVE_GETOPT_LONG

// Program options
static struct option prog_options[] = {
    {"help", 0, 0, 'h'},
    {"print", 0, 0, 'p'},
    {"selftest", 0, 0, 's'},
    {"test-suite", 1, 0, 'S'},
    {"class", 1, 0, 'c'},
    {"type", 1, 0, 't'},
    {"testcase", 1, 0, 'T'},
    {"testcase-conf", 1, 0, 'F'},
    {"label", 1, 0, 'l'},
    {"output", 1, 0, 'o'},
    {"resolv-conf", 1, 0, 'r'},
    {"dnsval-conf", 1, 0, 'v'},
    {"root-hints", 1, 0, 'i'},
    {"wait", 1, 0, 'w'},
    {"inflight", 1, 0, 'I'},
    {"Version", 1, 0, 'V'},
    {0, 0, 0, 0}
};
#endif

/*============================================================================
 *
 * SUPPORT FUNCTIONS BEGIN HERE
 *
 *===========================================================================*/

void
sig_shutdown(int a)
{
    done = 1;
}

int
check_results(val_context_t * context, const char *desc, char * name,
              const u_int16_t class, const u_int16_t type,
              const int *result_ar, struct val_result_chain *results,
              int trusted_only)
{
    int             result_array[MAX_TEST_RESULTS];
    int             err = 0, i;
    struct val_result_chain *res;

    if ((NULL == result_ar) || (NULL == results))
        return -1;

    /*
     * make a local copy of result array 
     */
    i = 0;
    while (result_ar[i] != 0) {
        result_array[i] = result_ar[i];
        i++;
    }
    result_array[i] = 0;

    for (res = results; res && (err == 0); res = res->val_rc_next) {
        for (i = 0; result_array[i] != 0; i++) {
            if (res->val_rc_status == result_array[i]) {
                result_array[i] = -1;   /* Mark this as done  */
                break;
            }
        }
        if (result_array[i] == 0) {
            if (trusted_only) {
                if (val_istrusted(res->val_rc_status)) {
                    continue;
                } else {
                    err = 1;
                }
            } else {
                fprintf(stderr, "%s: \t", desc);
                fprintf(stderr,
                        "FAILED: Remaining error values expected\n");
                for (i = 0; result_array[i] != 0; i++) {
                    if (result_array[i] != -1)
                        fprintf(stderr, "     %s(%d)\n",
                                p_val_error(result_array[i]),
                                result_array[i]);
                }
                fprintf(stderr, "\n");
                err = 1;
            }
        }
    }

    /*
     * All results were in the result array 
     */
    if (!err) {
        /*
         * Check if all error values were marked 
         */
        for (i = 0; result_array[i] != 0; i++) {
            if (result_array[i] != -1) {
                fprintf(stderr, "%s: \t", desc);
                fprintf(stderr,
                        "FAILED: Some results were not received \n");
                err = 1;
                break;
            }
        }

        if (!err) {
            fprintf(stderr, "%s: \t", desc);
            fprintf(stderr, "OK\n");
        }
    } else if (trusted_only) {
        fprintf(stderr, "%s: \t", desc);
        fprintf(stderr,
                "FAILED: Some results were not validated successfully \n");
    }

    return err;
}

void
print_val_response(struct val_response *resp)
{
    if (resp == NULL) {
        printf("No answers returned. \n");
        return;
    }

    printf("DNSSEC status: %s [%d]\n",
           p_val_error(resp->vr_val_status), resp->vr_val_status);
    if (val_istrusted(resp->vr_val_status)) {
        printf("Trusted response:\n");
    } else {
        printf("Untrusted response:\n");
    }
    print_response(resp->vr_response, resp->vr_length);
    printf("\n");
}

// A wrapper function to send a query and print the output onto stderr
//
int
sendquery(val_context_t * context, const char *desc, char * name,
          int class, int type, u_int32_t flags,
          const int *result_ar, int trusted_only,
          struct val_response *resp)
{
    int             ret_val;
    struct val_result_chain *results = NULL;
    int             err = 0;

    if ((NULL == desc) || (NULL == name) || (NULL == result_ar) )
        return -1;

    fprintf(stderr, "%s: ****START**** \n", desc);
    
    ret_val =
        val_resolve_and_check(context, name, class, type, flags, &results);

    if (ret_val == VAL_NO_ERROR) {

        if (resp)
            ret_val = compose_answer(name, type, class, results, resp);

        if (result_ar)
            err =
                check_results(context, desc, name, class, type,
                              result_ar, results, trusted_only);

        val_free_result_chain(results);
    } else {
        fprintf(stderr, "%s: \t", desc);
        fprintf(stderr, "FAILED: Error in val_resolve_and_check(): %s\n",
                p_val_err(ret_val));
    }

    results = NULL;
    fprintf(stderr, "%s: ****END**** \n", desc);

    return (err != 0);          /* 0 success, 1 error */
}

// Usage
void
usage(char *progname)
{
    /* *INDENT-OFF* */
    printf("Usage: validate [options] [DOMAIN_NAME]\n");
    printf("Resolve and validate a DNS query.\n");
    printf("Primary Options:\n");
    printf("        -h, --help             Display this help and exit\n");
    printf("        -p, --print            Print the answer and validation result\n");
    printf("        -s, --selftest         Run all internal selftest suite(s)\n");
    printf("        -S, --test-suite=<suite>[:<suite>] Run specified internal sefltest suite(s)\n");
    printf("        -T, --testcase=<number>[:<number>\n");
    printf("                               Specifies the test case number/range \n");
    printf("        -F, --testcase-conf=<file> Specifies the file containing the test cases\n");
    printf("        -c, --class=<CLASS>    Specifies the class (default IN)\n");
    printf("        -t, --type=<TYPE>      Specifies the type (default A)\n");
    printf("        -v, --dnsval-conf=<file> Specifies a dnsval.conf\n");
    printf("        -r, --resolv-conf=<file> Specifies a resolv.conf to search for nameservers\n");
    printf("        -i, --root-hints=<file> Specifies a root.hints to search for root nameservers\n");
    printf("        -I, --inflight=<number> Maximum number of simultaneous queries\n");
    printf("        -w, --wait=<secs> Run tests in a loop, sleeping for specifed seconds between runs\n");
    printf("        -l, --label=<label-string> Specifies the policy to use during validation\n");
    printf("        -o, --output=<debug-level>:<dest-type>[:<dest-options>]\n");
    printf("              <debug-level> is 1-7, corresponding to syslog levels ALERT-DEBUG\n");
    printf("              <dest-type> is one of file, net, syslog, stderr, stdout\n");
    printf("              <dest-options> depends on <dest-type>\n");
    printf("                  file:<file-name>   (opened in append mode)\n");
    printf("                  net[:<host-name>:<host-port>] (127.0.0.1:1053\n");
    printf("                  syslog[:facility] (0-23 (default 1 USER))\n");
    printf("        -V, --Version          Display version and exit\n");
    printf("Advanced Options:\n");
    printf("\nThe DOMAIN_NAME parameter is not required for the -h option.\n");
    printf("The DOMAIN_NAME parameter is required if one of -p, -c or -t options is given.\n");
    printf("If no arguments are given, this program runs a set of predefined test queries.\n");
    /* *INDENT-ON* */
}

void
version(void)
{
    fprintf(stderr, "%s: %s\n",NAME,VERS);
    fprintf(stderr, "%s\n",DTVERS);
}

/*============================================================================
 *
 * DAEMON MODE SUPPORT FUNCTIONS BEGIN HERE
 *
 *===========================================================================*/

static int
port_setup(u_short port)
{
    int             rc;
    struct sockaddr_in addr;

    if (listen_fd > 0)
        return listen_fd;

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_fd < 0)
        return listen_fd;

    rc = bind(listen_fd, (struct sockaddr *) &addr,
              sizeof(struct sockaddr));
    if (0 != rc) {
        /** xxx-rks: log err message */
        close(listen_fd);
        listen_fd = -1;
        return -1;
    }

    return listen_fd;
}

static int
wait_for_packet(void)
{
    fd_set          read_fds;
    int             rc;

    /*
     * wait for data
     */
    do {
        FD_ZERO(&read_fds);
        FD_SET(listen_fd, &read_fds);
        rc = select(listen_fd + 1, &read_fds, NULL, NULL, NULL);
        if (rc < 0 && errno != EINTR) {
            break;              /* xxx-rks: more robust error handling */
        }
    } while (rc < 0);

    return rc;
}

static int
get_results(val_context_t * context, const char *desc, char *name,
            int class_h, int type_h, u_char *response,
            int *response_size, int trusted_only)
{
    int             response_size_max, ret_val, err = 0;
    struct val_result_chain *results = NULL;
    struct val_response resp;

    if ((NULL == desc) || (NULL == name) || (NULL == response) ||
        (NULL == response_size))
        return -1;

    response_size_max = *response_size;
    *response_size = 0;

    fprintf(stderr, "%s: ****START**** \n", desc);

    /*
     * Query the validator
     */
    ret_val = val_resolve_and_check(context, name, class_h, type_h, 
                                VAL_QUERY_NO_AC_DETAIL, &results);

    if (ret_val == VAL_NO_ERROR) {

        ret_val = compose_answer(name, type_h, class_h, results, &resp);
        val_free_result_chain(results);

        if (VAL_NO_ERROR != ret_val) {
            fprintf(stderr, "%s: \t", desc);
            fprintf(stderr, "FAILED: Error in compose_answer(): %d\n",
                    ret_val);
        }
        else {
            if (resp.vr_response == NULL) {
                fprintf(stderr, "FAILED: No response\n");
            } else {
                printf("DNSSEC status: %s [%d]\n",
                       p_val_error(resp.vr_val_status), resp.vr_val_status);
                if (val_isvalidated(resp.vr_val_status)) {
                    printf("Validated response:\n");
                } else if (val_istrusted(resp.vr_val_status)) {
                    printf("Trusted but not validated response:\n");
                } else {
                    printf("Non-validated response:\n");
                }
                if (resp.vr_length > response_size_max) {
                    err = 1;
                }
                else {
                    print_response(resp.vr_response, resp.vr_length);
                    memcpy(response, resp.vr_response, resp.vr_length);
                    *response_size = resp.vr_length;
                }

                FREE(resp.vr_response);
            }
        }

    } else {
        fprintf(stderr, "%s: \t", desc);
        fprintf(stderr, "FAILED: Error in val_resolve_and_check(): %d, %s\n",
                ret_val, p_val_err(ret_val));
    }

    fprintf(stderr, "%s: ****END**** \n", desc);

    return (err != 0);          /* 0 success, 1 error */
}

static int
process_packet(val_context_t *context)
{
    HEADER         *query_header, *response_header;
    u_char         *pos;
    int             q_name_len, rc;
    u_int16_t       q_type, q_class;

    struct sockaddr from;
    socklen_t       from_len;

    u_char          query[4096], response[4096];
    int             query_size, response_size;

    /*
     * get a packet
     */
    from_len = sizeof(from);
    memset(&from, 0x0, sizeof(from));
    do {
        rc = recvfrom(listen_fd, query, sizeof(query), 0, &from,
                      &from_len);
        if (rc < 0 && errno != EINTR) {
            // xxx-rks: log err msg
            break;
        }
    } while (rc < 0);
    if (rc < 0)
        return rc;

    query_size = rc;
    if (query_size < (sizeof(HEADER) + 1))
        return -1;

    query_header = (HEADER *) query;

    /*
     * get query name
     */
    pos = &query[sizeof(HEADER)];
    q_name_len = wire_name_length(pos);
    pos += q_name_len;

    /*
     * get class and type
     */
    VAL_GET16(q_type, pos);
    VAL_GET16(q_class, pos);

    response_size = sizeof(response);
    
    get_results(context, "test", (char *)&query[sizeof(HEADER)], (int)q_class,
                (int)q_type, response, &response_size, 0);

    /*
     * check to see if we need a dummy response
     */
    val_log(NULL, LOG_DEBUG, "XXX-RKS: handle no response");
    if (0 == response_size) {
        // no response; generate dummy/nxdomain response?
        return 1;
    }

    response_header = (HEADER*)response;
    response_header->id = query_header->id;

    /*
     * send response
     */
    do {
        rc = sendto(listen_fd, response, response_size, 0, &from,
                    sizeof(from));
        if (rc < 0 && errno != EINTR) {
            // xxx-rks: log err msg
            break;
        }
    } while (rc < 0);
    if (rc > 0) {
        val_log(NULL, LOG_DEBUG, "sent %d bytes", rc);
    }

    return 0;                   /* no error */
}

static void
endless_loop(void)
{
    val_context_t *context;

    /*
     * signal handlers to exit gracefully
     */
#ifdef SIGTERM
    signal(SIGTERM, sig_shutdown);
#endif
#ifdef SIGINT
    signal(SIGINT, sig_shutdown);
#endif

    /*
     * open a port and process incoming packets
     */
    port_setup(1153);
    if (VAL_NO_ERROR != val_create_context(NULL, &context)) {
        val_log(NULL, LOG_ERR, "Cannot create validator context. Exiting.");
        return;
    }

    while (!done) {
        wait_for_packet();
        process_packet(context);
    }

    val_free_context(context);

    val_free_validator_state();
}

void 
one_test(val_context_t *context, char *name, int class_h, 
        int type_h, u_int32_t flags, int retvals[], int doprint)
{
    struct val_response resp;
    memset(&resp, 0, sizeof(struct val_response));
    sendquery(context, "Result", name, class_h, type_h, flags, retvals, 1, &resp);
    fprintf(stderr, "\n");

    // If the print option is present, perform query and validation
    // again for printing the result
    if (doprint) {
        print_val_response(&resp);
    }

    if (resp.vr_response)
        FREE(resp.vr_response);
}

#if NO_OF_THREADS
struct thread_params_st {
    val_context_t *context;
    int tcs;
    int tce;
    u_int32_t flags;
    char *testcase_config;
    char *suite;
    int doprint;
    int wait;
    int max_in_flight;
};

struct thread_params_ot {
    val_context_t *context;
    char *name;
    int class_h;
    int type_h;
    u_int32_t flags;
    int *retvals;
    int doprint;
    int wait;
};

void *firethread_st(void *param) {
    struct thread_params_st *threadparams = (struct thread_params_st *)param;
    /*child process*/
    fprintf(stderr, "Start of thread %u\n context=%u\n", 
            (unsigned int)pthread_self(), 
            (unsigned int)threadparams->context);
    do {
        self_test(threadparams->context, threadparams->tcs, threadparams->tce, threadparams->flags, 
                  threadparams->testcase_config, threadparams->suite, threadparams->doprint, threadparams->max_in_flight);
        if (threadparams->wait)
            sleep(threadparams->wait);
    }while (threadparams->wait);
    
    fprintf(stderr, "End of thread %u\n", 
            (unsigned int)pthread_self());

    return NULL;
}

void *firethread_ot(void *param) {
    struct thread_params_ot *threadparams = (struct thread_params_ot *)param;
    /*child process*/
    fprintf(stderr, "Start of thread %u\n context=%u\n", 
            (unsigned int)pthread_self(), 
            (unsigned int)threadparams->context);
    do {
        one_test(threadparams->context, threadparams->name, threadparams->class_h, 
                  threadparams->type_h, threadparams->flags, 
                  threadparams->retvals, threadparams->doprint);
        if (threadparams->wait)
            sleep(threadparams->wait);
    }while (threadparams->wait);

    fprintf(stderr, "End of thread %u\n", 
            (unsigned int)pthread_self());
    
    return NULL;
}
#endif



/*============================================================================
 *
 * main() BEGINS HERE
 *
 *===========================================================================*/
int
main(int argc, char *argv[])
{
    val_context_t  *context = NULL;

    // Parse the command line for a query and resolve+validate it
    int             c;
    char           *domain_name = NULL;
    const char     *args = "c:dF:hi:I:l:w:o:pr:S:st:T:v:V";
    int            class_h = ns_c_in;
    int            type_h = ns_t_a;
    int             success = 0;
    int             doprint = 0;
    int             selftest = 0;
    int             max_in_flight = 1;
    int             daemon = 0;
    u_int32_t       flags = 0;
    int             retvals[] = { 0 };
    int             tcs = 0, tce = -1;
    int             wait = 0;
    char           *label_str = NULL, *nextarg = NULL;
    char           *suite = NULL, *testcase_config = NULL;
    val_log_t      *logp;
    int             rc;

    if (argc == 1)
        return 0;

    while (1) {
#ifdef HAVE_GETOPT_LONG
        int             opt_index = 0;
#ifdef HAVE_GETOPT_LONG_ONLY
        c = getopt_long_only(argc, argv, args, prog_options, &opt_index);
#else
        c = getopt_long(argc, argv, args, prog_options, &opt_index);
#endif
#else                           /* only have getopt */
        c = getopt(argc, argv, args);
#endif

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage(argv[0]);
            return (-1);

        case 'F':
            testcase_config = optarg;
            break;

        case 'd':
            daemon = 1;
            break;

        case 's':
            selftest = 1;
            if (NULL != suite) {
                fprintf(stderr,
                        "Warning: -s runs all tests.\n"
                        "         ignoring previous suite(s).\n");
                suite = NULL; /* == all suites */
            }
            break;

        case 'S':
            if (selftest) {
                if (NULL == suite)
                    fprintf(stderr,
                            "Warning: -s runs all tests.\n"
                            "         ignoring specified suite.\n");
                else {
                    fprintf(stderr,
                            "Warning: -S may only be specified once.\n"
                            "         ignoring previous suite.\n");
                    suite = optarg;
                }
            }
            else {
                selftest = 1;
                suite = optarg;
            }
            break;

        case 'p':
            doprint = 1;
            break;

        case 'c':
            // optarg is a global variable.  See man page for getopt_long(3).
            class_h = res_nametoclass(optarg, &success);
            if (!success) {
                fprintf(stderr, "Cannot parse class %s\n", optarg);
                usage(argv[0]);
                return -1;
            }
            break;

        case 'o':
            logp = val_log_add_optarg(optarg, 1);
            if (NULL == logp) { /* err msg already logged */
                usage(argv[0]);
                return -1;
            }
            break;


        case 'I':
            max_in_flight = strtol(optarg, &nextarg, 10);
            break;

        case 'v':
            dnsval_conf_set(optarg);
            break;

        case 'i':
            root_hints_set(optarg);
            break;

        case 'r':
            resolv_conf_set(optarg);
            break;

        case 'w':
            wait = strtol(optarg, &nextarg, 10);
            break; 

        case 't':
            type_h = res_nametotype(optarg, &success);
            if (!success) {
                fprintf(stderr, "Cannot parse type %s\n", optarg);
                usage(argv[0]);
                return -1;
            }
            break;

        case 'T':
            tcs = strtol(optarg, &nextarg, 10) - 1;
            if (*nextarg == '\0')
                tce = tcs;
            else
                tce = atoi(++nextarg) - 1;
            break;

        case 'l':
            label_str = optarg;
            break;

        case 'V':
            version();
            return 0;

        default:
            fprintf(stderr, "Unknown option %s (c = %d [%c])\n",
                    argv[optind - 1], c, (char) c);
            usage(argv[0]);
            return -1;

        }                       // end switch
    }

    if (daemon) {
        endless_loop();
        return 0;
    }

#ifndef TEST_NULL_CTX_CREATION
    if (VAL_NO_ERROR !=
        (rc = val_create_context(label_str, &context))) {
        fprintf(stderr, "Cannot create context: %d\n", rc);
        return -1;
    }
#else
    context = NULL;
#endif

    /* returned level is 0 based;, > 6 means 8 or higher; e.g. -o 8:stdout */
    if (val_log_highest_debug_level() > 6)
        res_io_set_debug(1);

    rc = 0;

    // optind is a global variable.  See man page for getopt_long(3)
    if (optind >= argc) {
        if (!selftest && (tcs == -1)) {
            fprintf(stderr, "Please specify domain name\n");
            usage(argv[0]);
            rc = -1;
            goto done;
        } else {

#if NO_OF_THREADS
            pthread_t tids[NO_OF_THREADS];
            struct thread_params_st 
                threadparams = {context, tcs, tce, flags, testcase_config, suite, doprint, wait};
            int j;
                
            for (j=0; j < NO_OF_THREADS; j++) {
                pthread_create(&tids[j], NULL, firethread_st, (void *)&threadparams);
            }
                
            for (j=0; j < NO_OF_THREADS; j++) {
                pthread_join(tids[j], NULL);
            }
            fprintf(stderr, "Parent exiting\n");
#else
            do { /* endless loop */ 
                rc = self_test(context, tcs, tce, flags, testcase_config, suite,
                               doprint, max_in_flight);
                if (wait)
                    sleep(wait);
            } while (wait && !rc);
#endif

        }

        goto done;
    }

    domain_name = argv[optind++];

#if NO_OF_THREADS
    pthread_t tids[NO_OF_THREADS];
    struct thread_params_ot 
                threadparams = {context, domain_name, class_h, type_h, flags, retvals, doprint, wait};
    int j;
                
    for (j=0; j < NO_OF_THREADS; j++) {
        pthread_create(&tids[j], NULL, firethread_ot, (void *)&threadparams);
    }
    
    for (j=0; j < NO_OF_THREADS; j++) {
        pthread_join(tids[j], NULL);
    }
    fprintf(stderr, "Parent exiting\n");
#else
    do { /* endless loop */
        one_test(context, domain_name, class_h, type_h, flags, retvals, doprint);

        if (wait)
            sleep(wait);
    } while (wait);
#endif

done:
    if (context)
        val_free_context(context);
    val_free_validator_state();

    return rc;
}
