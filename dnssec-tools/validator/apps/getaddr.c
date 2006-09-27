/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * A command-line tool for testing the val_getaddrinfo() function.
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

#include <resolver.h>
#include <validator.h>

#include "val_log.h"

#ifdef HAVE_GETOPT_LONG
// Program options
static struct option prog_options[] = {
    {"help", 0, 0, 'h'},
    {"novalidate", 0, 0, 'n'},
    {"canonname", 0, 0, 'c'},
    {"service", 0, 0, 's'},
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
            "\t-n, --novalidate                do not use the validator\n");
    fprintf(stderr,
            "\t-c, --canonname                 use the AI_CANONNAME flag\n");
    fprintf(stderr,
            "\t-s, --service=<PORT|SERVICE>    transport-layer port or service name\n");
}

static int      validate = 0;

#define ADDRINFO_TYPE     0
#define VAL_ADDRINFO_TYPE 1

static void
print_addrinfo(int type, void *ainfo)
{
    struct sockaddr_in *s_inaddr = NULL;
    struct sockaddr_in6 *s_in6addr = NULL;
    struct addrinfo *a = (struct addrinfo *) ainfo;
    char            buf[INET6_ADDRSTRLEN];

    while (a != NULL) {
        printf("{\n");
        printf("\tFlags:     %d [", a->ai_flags);
        if (a->ai_flags & AI_PASSIVE)
            printf("AI_PASSIVE ");
        if (a->ai_flags & AI_CANONNAME)
            printf("AI_CANONNAME ");
        if (a->ai_flags & AI_NUMERICHOST)
            printf("AI_NUMERICHOST ");
        if (a->ai_flags & AI_V4MAPPED)
            printf("AI_V4MAPPED ");
        if (a->ai_flags & AI_ALL)
            printf("AI_ALL ");
        if (a->ai_flags & AI_ADDRCONFIG)
            printf("AI_ADDRCONFIG ");
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
            printf("\tAddrPtr:   %p\n", a->ai_addr);
            if (a->ai_family == AF_INET) {
                s_inaddr = (struct sockaddr_in *) (a->ai_addr);
                printf("\tAddr:      %s\n",
                       inet_ntop(AF_INET,
                                 &(s_inaddr->sin_addr),
                                 buf, INET6_ADDRSTRLEN));
            } else if (a->ai_family == AF_INET6) {
                s_in6addr = (struct sockaddr_in6 *) (a->ai_addr);
                printf("\tAddr:      %s\n",
                       inet_ntop(AF_INET6,
                                 &(s_in6addr->sin6_addr),
                                 buf, INET6_ADDRSTRLEN));
            } else
                printf
                    ("\tAddr:      Cannot parse address. Unknown protocol family\n");
        } else
            printf("\tAddr:      (null)\n");

        if (a->ai_canonname)
            printf("\tCanonName: %s\n", a->ai_canonname);
        else
            printf("\tCanonName: (null)\n");

        if (type == VAL_ADDRINFO_TYPE) {
            printf("\tValStatus: %s\n",
                   p_val_error(((struct val_addrinfo *) a)->
                               ai_val_status));
        }
        printf("}\n");

        a = (struct addrinfo *) (a->ai_next);
    }
}


int
main(int argc, char *argv[])
{
    char           *node = NULL;
    char           *service = NULL;
    struct addrinfo hints;
    struct val_addrinfo *val_ainfo = NULL;
    struct addrinfo *ainfo = NULL;
    int             retval;
    int             getcanonname = 0;
    int             portspecified = 0;
    val_log_t      *logp;

    // Parse the command line
    validate = 1;
    while (1) {
        int             c;
#ifdef HAVE_GETOPT_LONG
        int             opt_index = 0;
#ifdef HAVE_GETOPT_LONG_ONLY
        c = getopt_long_only(argc, argv, "hcno:s:",
                             prog_options, &opt_index);
#else
        c = getopt_long(argc, argv, "hcno:s:", prog_options, &opt_index);
#endif
#else                           /* only have getopt */
        c = getopt(argc, argv, "hcno:s:");
#endif

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage(argv[0]);
            return 0;
        case 'n':
            validate = 0;
            break;
        case 'o':
            logp = val_log_add_optarg(optarg, 1);
            if (NULL == logp) { /* err msg already logged */
                usage(argv[0]);
                return 1;
            }
            break;

        case 's':
            portspecified = 1;
            service = optarg;
            break;
        case 'c':
            getcanonname = 1;
            break;
        default:
            fprintf(stderr, "Invalid option %s\n", argv[optind - 1]);
            usage(argv[0]);
            return 1;
        }
    }

    if (optind < argc) {
        node = argv[optind++];
    } else {
        fprintf(stderr, "Error: node name not specified\n");
        usage(argv[0]);
        return 1;
    }

    bzero(&hints, sizeof(struct addrinfo));
    if (getcanonname) {
        hints.ai_flags |= AI_CANONNAME;
    }

    if (validate) {
        retval = val_getaddrinfo(NULL, node, service, &hints, &val_ainfo);

        if (retval != 0) {
            printf("Error in val_getaddrinfo(): %s\n",
                   gai_strerror(retval));
            exit(1);
        } else {
            print_addrinfo(VAL_ADDRINFO_TYPE, val_ainfo);
        }

        /*
         * cleanup 
         */
        free_val_addrinfo(val_ainfo);
    } else {
        retval = getaddrinfo(node, service, &hints, &ainfo);
        if (retval != 0) {
            printf("Error in getaddrinfo(): %s\n", gai_strerror(retval));
            exit(1);
        } else {
            print_addrinfo(ADDRINFO_TYPE, ainfo);
        }
    }
    return 0;
}
