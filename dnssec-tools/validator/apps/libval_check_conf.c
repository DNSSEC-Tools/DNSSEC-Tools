/*
 * Copyright 2005-2007 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

/*
 * Program to check if the provided dnsval.conf file is valid 
 *
 */
#include "validator-config.h"

#include <stdio.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <libgen.h>

#include <validator/resolver.h>
#include <validator/validator.h>

#ifdef HAVE_GETOPT_LONG
static struct option prog_options[] = {
    {"help", 0, 0, 'h'},
    {"resolv-conf", 1, 0, 'r'},
    {"root-hints", 1, 0, 'i'},
    {"verbose", 0, 0, 'v'},
    {0, 0, 0, 0}
};
#endif

void usage(char *progname)
{
    printf("Usage: %s [options] location/to/dnsval.conf\n", progname);
    printf("Check if the provided dnsval.conf file is syntactically valid.\n");
    printf("Primary Options:\n");
    printf("        -h, --help                        Display this help and exit\n");
    printf("        -r, --resolv-conf=<resolv.conf>   Specify the resolv.conf file\n");
    printf("        -i, --root_h-nts=<root.hints>     Specify the root.hints file\n");
    printf("        -v, --verbose                     Enable verbose mode\n");
}

int main(int argc, char *argv[])
{
    int             retval;
    int             c;
    const char     *args = "hvr:i:";
    char           *progname;
    val_log_t      *logp;
    val_context_t *context = NULL;
    char           *dnsval_conf = NULL;
    char           *resolv_conf = NULL;
    char           *root_hints = NULL;
    int            debug = 0;

    progname = basename(argv[0]);

    if (argc == 1) {
        fprintf(stdout, "Nothing to check. Exiting.\n");
        usage(progname);
        return 0;
    }

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
                usage(progname);
                return (0);

            case 'v':
                debug=1;
                logp = val_log_add_optarg("7:stdout", 1);
                if (NULL == logp) { /* err msg already logged */
                    usage(progname);
                    return (-1);
                }
                break;

            case 'r':
                resolv_conf = optarg;
                break;

            case 'i':
                root_hints = optarg;
                break;

            default: 
                fprintf(stderr, "Unknown option %s (c = %d [%c])\n",
                        argv[optind - 1], c, (char) c);
                usage(progname);
                return (-1);
        }
    }

    dnsval_conf = argv[optind++];

    if (root_hints == NULL && debug) {
        fprintf(stdout, "root.hints is not specified. Using system defined root-hints for libval.\n");
    }
    if (resolv_conf == NULL && debug) {
        fprintf(stdout, "resolv.conf is not specified. Using system defined resolv.conf for libval.\n");
    }
    
    retval = val_create_context_with_conf(NULL, dnsval_conf, resolv_conf, root_hints, &context);

    if (retval != VAL_NO_ERROR) {
        fprintf(stdout, "Checking %s : FAILED. \n", dnsval_conf); 
        return (-1);
    }

    fprintf(stdout, "Checking %s : OK. \n", dnsval_conf);
    val_free_context(context);
    return 0;
}
