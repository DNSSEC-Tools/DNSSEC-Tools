/*
 * Copyright 2005-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * A command-line tool for testing the val_get_rrset() function.
 */
#include "validator-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <arpa/nameser.h>
#include <validator/resolver.h>
#include <validator/validator.h>

#define	NAME	"getrrset"
#define	VERS	"version: 1.0"
#define	DTVERS	"DNSSEC-Tools Version: 1.8"

#ifdef HAVE_GETOPT_LONG
// Program options
static struct option prog_options[] = {
    {"help", 0, 0, 'h'},
    {"type", 0, 0, 't'},
    {"output", 0, 0, 'o'},
    {"Version", 0, 0, 'V'},
    {0, 0, 0, 0}
};
#endif

void
usage(char *progname)
{
    fprintf(stderr,
            "Usage: %s [options] hostname\n",
            progname);
    fprintf(stderr, "Options:\n");
    fprintf(stderr,
            "\t-h, --help          display usage and exit\n");
    fprintf(stderr,
            "\t-t, --type=<type>   record type. Defaults to A record.\n");
    fprintf(stderr,
            "\t-o, --output=<debug-level>:<dest-type>[:<dest-options>]\n"
            "\t          <debug-level> is 1-7, corresponding to syslog levels\n"
            "\t          <dest-type> is one of file, net, syslog, stderr, stdout\n"
            "\t          <dest-options> depends on <dest-type>\n"
            "\t              file:<file-name>   (opened in append mode)\n" 
            "\t              net[:<host-name>:<host-port>] (127.0.0.1:1053\n" 
            "\t              syslog[:facility] (0-23 (default 1 USER))\n" );
    fprintf(stderr,
            "\t-V, --Version       display version and exit\n");
}

void
version(void)
{
    fprintf(stderr, "%s: %s\n", NAME, VERS);
    fprintf(stderr, "%s\n", DTVERS);
}


void 
print_results(struct val_answer_chain *results) 
{
    struct val_answer_chain *res;
    int count = 0;
    int i = 0;
    int j = 0;
    struct rr_rec *rr;
    
    if (!results) {
        fprintf(stderr, "results is NULL\n");
        return;
    }

    /* count number of answers */
    for (res=results; res; res=res->val_ans_next) {
        count++;
    }

    for (res=results; res; res=res->val_ans_next) {
        i++;
        if (count > 1) {
            fprintf(stderr, "**** Answer %d of %d **** \n", i, count);
        } 
        fprintf(stderr, "Validation status: %s[%d]\n", 
                p_val_status(res->val_ans_status), res->val_ans_status); 
        fprintf(stderr, "  => val_isvalidated() : %d\n", 
                val_isvalidated(res->val_ans_status));
        fprintf(stderr, "  => val_istrusted() : %d\n", 
                val_istrusted(res->val_ans_status));
        fprintf(stderr, "  => val_does_not_exist() : %d\n", 
                val_does_not_exist(res->val_ans_status));
        fprintf(stderr, "Actual name found: %s\n", 
                res->val_ans_name);
        fprintf(stderr, "Actual type found: %d\n", 
                res->val_ans_type);

        if (!res->val_ans) {
            fprintf(stderr, "RR data was NULL\n");
        }
        
        for (j=1, rr = res->val_ans; rr; rr=rr->rr_next) {
            char            buf[1028];
            int          buflen = 1024;
            
            get_hex_string(rr->rr_data, rr->rr_length, buf, buflen);
            fprintf(stderr, "RR %d : %s\n", j++, buf); 
        }
        
        if (i < count) {
            fprintf(stderr, "\n");
        } 
    }
}

int
main(int argc, char *argv[])
{
    char           *node = NULL;
    int             retval;
    val_log_t      *logp;
    int      type_h = ns_t_a;
    struct val_answer_chain *results = NULL;
    int success = 0;

    while (1) {
        int             c;
#ifdef HAVE_GETOPT_LONG
        int             opt_index = 0;
#ifdef HAVE_GETOPT_LONG_ONLY
        c = getopt_long_only(argc, argv, "ho:t:V",
                             prog_options, &opt_index);
#else
        c = getopt_long(argc, argv, "ho:t:V", prog_options, &opt_index);
#endif
#else                           /* only have getopt */
        c = getopt(argc, argv, "ho:t:V");
#endif

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage(argv[0]);
            return -1;
        case 'o':
            logp = val_log_add_optarg(optarg, 1);
            if (NULL == logp) { /* err msg already logged */
                usage(argv[0]);
                return -1;
            }
            break;

        case 't':
            type_h = (int)res_nametotype(optarg, &success);
            if (!success) {
                fprintf(stderr, "Unrecognized type %s\n", optarg);
                usage (argv[0]);
                return -1;
            }
            break;
        case 'V':
            version();
            return 0;

        default:
            fprintf(stderr, "Invalid option %s\n", argv[optind - 1]);
            usage(argv[0]);
            return -1;
        }
    }

    if (optind < argc) {
        node = argv[optind++];
    } else {
        fprintf(stderr, "Error: node name not specified\n");
        usage(argv[0]);
        return -1;
    }

    retval = val_get_rrset(NULL, node, ns_c_in, type_h, 0, &results);
    if (retval != VAL_NO_ERROR) {
        fprintf(stderr, "val_get_rrset() returned error %s[%d]\n", p_val_err(retval), retval); 
        return -1; 
    }

    print_results(results);
    val_free_answer_chain(results);
        
    return 0;
}
