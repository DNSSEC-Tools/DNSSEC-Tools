/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

/*
 * Program to check if the provided dnsval.conf file is valid 
 *
 */
#include "validator/validator-config.h"
#include <validator/validator.h>

#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_GETOPT_LONG
static struct option prog_options[] = {
    {"help", 0, 0, 'h'},
    {"dnsval-conf", 1, 0, 'd'},
    {"resolv-conf", 1, 0, 'r'},
    {"root-hints", 1, 0, 'i'},
    {"verbose", 0, 0, 'v'},
    {0, 0, 0, 0}
};
#endif

void usage(char *progname)
{
    printf("Usage: %s [options] \n", progname);
    printf("Check if the provided dnsval.conf file is syntactically valid.\n");
    printf("Primary Options:\n");
    printf("        -h, --help                        Display this help and exit\n");
    printf("        -d, --dnsval-conf=<dnsval.conf>   Specify the dnsval.conf file\n");
    printf("        -r, --resolv-conf=<resolv.conf>   Specify the resolv.conf file\n");
    printf("        -i, --root-hints=<root.hints>     Specify the root.hints file\n");
    printf("        -v, --verbose                     Enable verbose mode\n");
}

int main(int argc, char *argv[])
{
    int             retval;
    int             c;
    const char     *args = "hvd:r:i:";
    char           *progname;
    val_log_t      *logp;
    val_context_t *context = NULL;
    char           *dnsval_conf = NULL;
    char           *resolv_conf = NULL;
    char           *root_hints = NULL;
    int            debug = 0;

    progname = basename(argv[0]);

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

            case 'd':
                dnsval_conf = optarg;
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

    if (debug == 0) {
        logp = val_log_add_optarg("5:stdout", 1);
    }

    if (dnsval_conf == NULL && debug) {
        fprintf(stdout, "dnsval.conf is not specified. Using system defined dnsval.conf for libval.\n");
    }
    
    if (resolv_conf == NULL && debug) {
        fprintf(stdout, "resolv.conf is not specified. Using system defined resolv.conf for libval.\n");
    }
    
    if (root_hints == NULL && debug) {
        fprintf(stdout, "root.hints is not specified. Using system defined root-hints for libval.\n");
    }
    retval = val_create_context_with_conf(NULL, dnsval_conf, resolv_conf, root_hints, &context);

    if (retval != VAL_NO_ERROR) {
        fprintf(stdout, "Result: FAILED. %s \n", p_val_err(retval)); 
        return (-1);
    }

    fprintf(stdout, "Result : OK. \n");
    val_free_context(context);
    return 0;
}
