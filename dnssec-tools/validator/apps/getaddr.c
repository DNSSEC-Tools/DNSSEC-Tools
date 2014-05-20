/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * A command-line tool for testing the val_getaddrinfo() function.
 */
#include "validator/validator-config.h"
#include <validator/validator.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#define	NAME	"getaddr"
#define	VERS	"version: 1.0"
#define	DTVERS	"DNSSEC-Tools version: 1.8"

#ifdef HAVE_GETOPT_LONG
// Program options
static struct option prog_options[] = {
    {"help", 0, 0, 'h'},
    {"canonname", 0, 0, 'c'},
    {"nodnssec", 0, 0, 'n'},
    {"service", 0, 0, 's'},
    {"Version", 0, 0, 'V'},
#ifndef VAL_NO_ASYNC
    {"async", 0, 0, 'a'},
#endif
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
            "\t-c, --canonname                 use the AI_CANONNAME flag\n");
    fprintf(stderr,
            "\t-n, --nodnssec                  no DNSSEC validation\n");
    fprintf(stderr,
            "\t-s, --service=<PORT|SERVICE>    transport-layer port or service name\n");
    fprintf(stderr,
            "\t-o, --output=<debug-level>:<dest-type>[:<dest-options>]\n"
            "\t          <debug-level> is 1-7, corresponding to syslog levels\n"
            "\t          <dest-type> is one of file, net, syslog, stderr, stdout\n"
            "\t          <dest-options> depends on <dest-type>\n"
            "\t              file:<file-name>   (opened in append mode)\n" 
            "\t              net[:<host-name>:<host-port>] (127.0.0.1:1053\n" 
            "\t              syslog[:facility] (0-23 (default 1 USER))\n" );
#ifndef VAL_NO_ASYNC
    fprintf(stderr,
            "\t-a, --async                     exercise async code(deubg)\n");
#endif
    fprintf(stderr,
            "\t-V, --Version                   display version and exit\n");

}

void
version(void)
{
     fprintf(stderr, "%s %s\n", NAME, VERS);
     fprintf(stderr, "%s\n", DTVERS);
}

#define ADDRINFO_TYPE     0
#define VAL_ADDRINFO_TYPE 1

static void
print_addrinfo(int type, void *ainfo)
{
    struct sockaddr_in *s_inaddr = NULL;
    struct sockaddr_in6 *s_in6addr = NULL;
    struct addrinfo *a = (struct addrinfo *) ainfo;
    char            buf[INET6_ADDRSTRLEN];
    size_t          buflen = INET6_ADDRSTRLEN;

    while (a != NULL) {
        printf("{\n");
        printf("\tFlags:     %d [", a->ai_flags);
        if (a->ai_flags & AI_PASSIVE)
            printf("AI_PASSIVE ");
        if (a->ai_flags & AI_CANONNAME)
            printf("AI_CANONNAME ");
        if (a->ai_flags & AI_NUMERICHOST)
            printf("AI_NUMERICHOST ");
#ifdef AI_V4MAPPED
        if (a->ai_flags & AI_V4MAPPED)
            printf("AI_V4MAPPED ");
#endif
#ifdef AI_ALL
        if (a->ai_flags & AI_ALL)
            printf("AI_ALL ");
#endif
#ifdef AI_ADDRCONFIG
        if (a->ai_flags & AI_ADDRCONFIG)
            printf("AI_ADDRCONFIG ");
#endif
        //              if (a->ai_flags & AI_NUMERICSERV) printf("AI_NUMERICSERV ");
        printf("]\n");
        printf("\tFamily:    %d [%s]\n", a->ai_family,
               (a->ai_family == AF_UNSPEC) ? "AF_UNSPEC" :
               (a->ai_family == AF_INET) ? "AF_INET" :
               (a->ai_family == AF_INET6) ? "AF_INET6" : "Unknown");
        printf("\tSockType:  %d [%s]\n", a->ai_socktype,
               (a->ai_socktype == SOCK_STREAM) ? "SOCK_STREAM" :
               (a->ai_socktype == SOCK_DGRAM) ? "SOCK_DGRAM" :
               (a->ai_socktype == SOCK_RAW) ? "SOCK_RAW" : "Unknown");
        printf("\tProtocol:  %d [%s]\n", a->ai_protocol,
               (a->ai_protocol == IPPROTO_IP) ? "IPPROTO_IP" :
               (a->ai_protocol == IPPROTO_TCP) ? "IPPROTO_TCP" :
               (a->ai_protocol == IPPROTO_UDP) ? "IPPROTO_UDP" :
               "Unknown");
        printf("\tAddrLen:   %d\n", a->ai_addrlen);

        if (a->ai_addr != NULL) {
            const char *addr = NULL;
            printf("\tAddrPtr:   %p\n", a->ai_addr);
            if (a->ai_family == AF_INET) {
                s_inaddr = (struct sockaddr_in *) (a->ai_addr);
                INET_NTOP(AF_INET, ((struct sockaddr *)s_inaddr), sizeof(s_inaddr),
                          buf, buflen, addr);
                printf("\tAddr:      %s\n", addr);
            } else if (a->ai_family == AF_INET6) {
                s_in6addr = (struct sockaddr_in6 *) (a->ai_addr);
                INET_NTOP(AF_INET6, ((struct sockaddr *)s_in6addr), sizeof(s_in6addr),
                          buf, buflen, addr);
                printf("\tAddr:      %s\n", addr);
            } else
                printf
                    ("\tAddr:      Cannot parse address. Unknown protocol family\n");
        } else
            printf("\tAddr:      (null)\n");

        if (a->ai_canonname)
            printf("\tCanonName: %s\n", a->ai_canonname);
        else
            printf("\tCanonName: (null)\n");

        printf("}\n");

        a = (struct addrinfo *) (a->ai_next);
    }
}

#ifndef VAL_NO_ASYNC

struct getaddr_s {
    int              *retval;
    struct addrinfo **ainfo;
    val_status_t     *vstatus;
    int               done;
};

static int 
_callback(void *callback_data, int eai_retval, struct addrinfo *res,
          val_status_t val_status)
{
    struct getaddr_s *gas = (struct getaddr_s*)callback_data;

    *gas->retval = eai_retval;
    *gas->ainfo = res;
    *gas->vstatus = val_status;
    gas->done = 1;

    val_log(NULL, LOG_DEBUG, "_callback %p %d %p %d\n", callback_data, eai_retval, res,
           val_status);

    return 0; /* OK */
}
#endif

int
main(int argc, char *argv[])
{
    const char     *allowed_args =
#ifndef VAL_NO_ASYNC
        "a"
#endif
        "hco:s:Vv:r:i:n";
    char           *node = NULL;
    char           *service = NULL;
    struct addrinfo hints;
    struct addrinfo *val_ainfo = NULL;
    int             retval;
    int             getcanonname = 0;
    int             async = 0;
    int             nodnssec_flag = 0;
    val_log_t      *logp;
    val_status_t val_status;

    // Parse the command line
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
        case 'o':
            logp = val_log_add_optarg(optarg, 1);
            if (NULL == logp) { /* err msg already logged */
                usage(argv[0]);
                return -1;
            }
            break;

        case 's':
            service = optarg;
            break;
        case 'c':
            getcanonname = 1;
            break;

#ifndef VAL_NO_ASYNC
        case 'a':
            async = 1;
            break;
#endif

        case 'n':
            nodnssec_flag = 1;
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

    memset(&hints, 0, sizeof(struct addrinfo));
#ifdef AI_ADDRCONFIG
    hints.ai_flags = AI_ADDRCONFIG;
#endif
    if (getcanonname) {
        hints.ai_flags |= AI_CANONNAME;
    }

    if (nodnssec_flag) {
        val_context_setqflags(NULL, VAL_CTX_FLAG_SET,
                              VAL_QUERY_DONT_VALIDATE);
    }

    if (!async) {
        retval = val_getaddrinfo(NULL, node, service, &hints, &val_ainfo, &val_status);
    }
    else {
#ifdef VAL_NO_ASYNC
        fprintf(stderr, "async support not available\n");
#else
        struct getaddr_s cb_data = { &retval, &val_ainfo, &val_status, 0 };
        val_gai_callback my_cb = &_callback;
        val_gai_status *status = NULL;
        struct timeval tv;
        val_context_t *context;
        /*
         * create a new context
         */
        val_create_context("getaddr", &context);
        if (context == NULL)
            return -1;
        /*
         * submit request
         */
        retval = val_getaddrinfo_submit(context, node, service, &hints,
                                        my_cb, &cb_data, 0, &status);
        /*
         * wait for it to complete
         */
        while(0 == cb_data.done) {
            tv.tv_sec = 4;
            tv.tv_usec = 567;
            val_async_check_wait(context, NULL, NULL, &tv, 0);
        }
        val_free_context(context);
#endif
    }

    printf("Return code = %d\n", retval);
    printf("Validator status code = %d (%s)\n", val_status,
           p_val_status(val_status));

    if (retval != 0) {
#ifdef HAVE_GAI_STRERROR
        printf("Error in val_getaddrinfo(): %s\n", gai_strerror(retval));
#else
        printf("Error in val_getaddrinfo(): %d\n", retval);
#endif
        return -1;
    }

    print_addrinfo(VAL_ADDRINFO_TYPE, val_ainfo);

    /*
     * cleanup 
     */
    val_freeaddrinfo(val_ainfo);
    if (val_isvalidated(val_status)) {
        return 2; 
    } 
    if (val_istrusted(val_status)) {
        return 1; 
    } 

    return 0;
}
