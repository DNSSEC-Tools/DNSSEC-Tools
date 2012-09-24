/*
 * Copyright 2005-2012 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * A command-line tool for testing the val_get_dane() function.
 */
#include "validator/validator-config.h"
#include <validator/validator.h>
#include <validator/val_dane.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#define	NAME	"dane_check"
#define	VERS	"version: 1.0"
#define	DTVERS	"DNSSEC-Tools version: 1.8"

#ifdef HAVE_GETOPT_LONG
static struct option prog_options[] = {
    {"help", 0, 0, 'h'},
    {"label", 1, 0, 'l'},
    {"proto", 1, 0, 'x'},
    {"port", 1, 0, 'p'},
    {"output", 1, 0, 'o'},
    {"sync", 0, 0, 's'},
    {"Version", 0, 0, 'V'},
    {0, 0, 0, 0}
};
#endif

void
usage(char *progname)
{
    fprintf(stderr,
            "Usage: %s [options] <hostname|IPv4 address|IPv6 address>\n",
            progname);
    fprintf(stderr, "Options:\n");
    fprintf(stderr,
            "\t-h, --help                      display usage and exit\n");
    fprintf(stderr, 
            "\t-l, --label=<label-string>      validation policy label\n");
    fprintf(stderr,
            "\t-x, --proto=<tcp|udp|sctp>      TLSA protocol\n");
    fprintf(stderr,
            "\t-p, --port=<port number>        TLSA port\n");
    fprintf(stderr,
            "\t-o, --output=<debug-level>:<dest-type>[:<dest-options>]\n"
            "\t          <debug-level> is 1-7, corresponding to syslog levels\n"
            "\t          <dest-type> is one of file, net, syslog, stderr, stdout\n"
            "\t          <dest-options> depends on <dest-type>\n"
            "\t              file:<file-name>   (opened in append mode)\n" 
            "\t              net[:<host-name>:<host-port>] (127.0.0.1:1053\n" 
            "\t              syslog[:facility] (0-23 (default 1 USER))\n" );
    fprintf(stderr,
            "\t-s, --sync                      perform synchronous lookup\n");
    fprintf(stderr,
            "\t-V, --Version                   display version and exit\n");

}

void
version(void)
{
     fprintf(stderr, "%s %s\n", NAME, VERS);
     fprintf(stderr, "%s\n", DTVERS);
}



#ifndef VAL_NO_ASYNC
struct dane_cb {
    int *retval;
    struct val_danestatus **danestatus;
    int done;
};

static int 
_callback(void *callback_data, 
          int dane_rc, 
          struct val_danestatus **res)
{
    struct dane_cb *dcb = (struct dane_cb *)callback_data;

    *dcb->retval = dane_rc;
    if (res != NULL)
        *dcb->danestatus = *res;
    else
        *dcb->danestatus = NULL;
    dcb->done = 1;

    val_log(NULL, LOG_DEBUG, "_callback %p %d %p\n", 
            callback_data, dane_rc, res);

    return 0; /* OK */
}
#endif

int
main(int argc, char *argv[])
{
    const char     *allowed_args = "sl:o:Vv:r:i:nx:p:";
    char           *node = NULL;
    int             retval;
    int             dane_retval;
    int             async = 1;
    val_log_t      *logp;
    char           *label_str = NULL;
    struct val_daneparams daneparams;
    struct val_danestatus *danestatus = NULL;
    int port = 443;
    int proto = DANE_PARAM_PROTO_TCP;
    val_context_t *context = NULL;

    /* Parse the command line */
    while (1) {
        int             c;
#ifdef HAVE_GETOPT_LONG
        int             opt_index = 0;
#ifdef HAVE_GETOPT_LONG_ONLY
        c = getopt_long_only(argc, argv, allowed_args,
                             prog_options, &opt_index);
#else
        c = getopt_long(argc, argv, allowed_args, prog_options, &opt_index);
#endif
#else                           /* only have getopt */
        c = getopt(argc, argv, allowed_args);
#endif

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage(argv[0]);
            return -1;
        case 'l':
            label_str = optarg;
            break;
        case 'o':
            logp = val_log_add_optarg(optarg, 1);
            if (NULL == logp) { /* err msg already logged */
                usage(argv[0]);
                return -1;
            }
            break;

        case 's':
            async = 0;
            break;

        case 'p':
            port = atoi(optarg);
            break;

        case 'x':
            if(strncmp(optarg, DANE_PARAM_PROTO_STR_TCP,
                       strlen(DANE_PARAM_PROTO_STR_TCP)))
                proto = DANE_PARAM_PROTO_TCP;
            else if (strncmp(optarg, DANE_PARAM_PROTO_STR_UDP,
                        strlen(DANE_PARAM_PROTO_STR_UDP)))
                proto = DANE_PARAM_PROTO_UDP;
            else if (strncmp(optarg, DANE_PARAM_PROTO_STR_SCTP, 
                        strlen(DANE_PARAM_PROTO_STR_SCTP)))
                proto = DANE_PARAM_PROTO_SCTP;
            else {
                usage(argv[0]);
                return -1;
            }
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

    if (val_log_highest_debug_level() > 6)
        res_set_debug_level(val_log_highest_debug_level());

    if (label_str != NULL && 
            VAL_NO_ERROR != (retval = val_create_context(label_str, 
                    &context))) {
        fprintf(stderr, "Cannot create context %s(%d)\n", 
                p_val_error(retval), retval);
        return -1;
    }

    daneparams.port = port;
    daneparams.proto = proto;

    if (!async) {

        /* synchronous lookup and validation */
        dane_retval = val_getdaneinfo(context, node, &daneparams, &danestatus); 
        if (VAL_NO_ERROR != retval) {
            dane_retval = VAL_DANE_INTERNAL_ERROR; 
            goto done;
        }
    }
    else {
#ifdef VAL_NO_ASYNC
        fprintf(stderr, "async support not available\n");
#else
        struct dane_cb cb_data = { &dane_retval, &danestatus, 0 };
        val_dane_callback my_cb = &_callback;
        struct timeval tv;
        val_async_status *das = NULL; /* helps us cancel the lookup if we need to */

        /*
         * submit request
         */
        retval = val_dane_submit(context, node, &daneparams,
                                 my_cb, &cb_data, &das);

        if (VAL_NO_ERROR != retval) {
            dane_retval = VAL_DANE_INTERNAL_ERROR; 
            goto done;
        }
        /*
         * wait for it to complete
         */
        while(0 == cb_data.done) {
            tv.tv_sec = 4;
            tv.tv_usec = 567;
            val_async_check_wait(context, NULL, NULL, &tv, 0);
        }
#endif
    }

    // XXX Print DANE information

done:
    printf("Return code = %s(%d)\n", 
            p_dane_error(dane_retval), dane_retval);

    if (danestatus != NULL)
        val_free_dane(danestatus);

    if (context)
        val_free_context(context);
    val_free_validator_state();

    if (dane_retval != VAL_DANE_NOERROR) {
        return -1;
    }

    return 0;
}
