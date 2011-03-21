/*
 * Copyright 2005-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * A command-line tool for testing the val_res_query() function.
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

#define	NAME	"getquery"
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
    fprintf(stderr, "%s: %s\n", NAME,VERS);
    fprintf(stderr, "%s\n", DTVERS);
}

int
main(int argc, char *argv[])
{
    char           *node = NULL;
    val_log_t      *logp;
    u_int16_t      type_h = ns_t_a;
    int success = 0;
    int ret;
    val_status_t status;
    u_char buf[1024];

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
            type_h = res_nametotype(optarg, &success);
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

    //ret = val_res_query(NULL, "mail.marzot.net", 1, 15, buf, 1024, &status);
    //ret = val_res_query(NULL, "nosig-A.test.dnssec-tools.org.", 1, 1, buf, 1024, &status);
    //ret = val_res_query(NULL, "good-A.test.dnssec-tools.org", 1, 28, buf, 1024, &status);
    //ret = val_res_query(NULL, "vb.futz.org", 1, 1, buf, 1024, &status);
    
    ret = val_res_query(NULL, node, ns_c_in, type_h, buf, 1024, &status);
    printf("Return value %d\n", ret);
    printf("herrno value %d\n", h_errno);
    printf("Validation Status %s\n", p_val_status(status));
    if (ret > 0) {
        print_response(buf, ret);
    }

    if (val_isvalidated(status))
        return 2;
    else if (val_istrusted(status))
        return 1;
    return 0;
}
