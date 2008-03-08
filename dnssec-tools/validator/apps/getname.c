/*
 * Copyright 2005-2007 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * A command-line tool for testing the val_getnameinfo() function.
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

#ifdef HAVE_GETOPT_LONG
// Program options
static struct option prog_options[] = {
    {"help", 0, 0, 'h'},
    {"novalidate", 0, 0, 'n'},
    {"port", 0, 0, 'p'},
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
            "\t-p, --service=<PORT|SERVICE>    transport-layer port or service name\n");
}

static int      validate = 1;
static int      flags = 0;
static int      portspecified = 0;

#define STRLEN 64
int
main(int argc, char *argv[])
{
    char           *node = NULL;
    char           *service = NULL;
    char           host_str[STRLEN];
    char           serv_str[STRLEN];
    char           *host = host_str;
    char           *serv = serv_str;
    size_t            hostlen = STRLEN;
    size_t            servlen = STRLEN;
    int             retval;
    int            port = 0;
    val_log_t      *logp;
    val_status_t val_status;
    struct sockaddr_in saddr;
    // Parse the command line
    while (1) {
        int             c;
#ifdef HAVE_GETOPT_LONG
        int             opt_index = 0;
#ifdef HAVE_GETOPT_LONG_ONLY
        c = getopt_long_only(argc, argv, "hno:p:FHNSD",
                             prog_options, &opt_index);
#else
        c = getopt_long(argc, argv, "hno:p:FHNSD", prog_options, &opt_index);
#endif
#else                           /* only have getopt */
        c = getopt(argc, argv, "hno:p:FHNSD");
#endif

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage(argv[0]);
            return -1;
        case 'n':
            validate = 0;
            break;
        case 'o':
            logp = val_log_add_optarg(optarg, 1);
            if (NULL == logp) { /* err msg already logged */
                usage(argv[0]);
                return -1;
            }
            break;
        case 'p':
            portspecified = 1;
            service = optarg;
	    sscanf(service, "%d", &port);
            break;
	case 'F':
	  flags |= NI_NOFQDN;
	  break;
	case 'H':
	  flags |= NI_NUMERICHOST;
	  break;
	case 'N':
	  flags |= NI_NAMEREQD;
	  break;
	case 'S':
	  flags |= NI_NUMERICSERV;
	  break;
	case 'D':
	  flags |= NI_DGRAM;
	  break;
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

    saddr.sin_family = PF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = inet_addr(node);

    if (portspecified != 1) {
      serv = NULL;
      servlen = 0;
    }

    if (validate) {

      retval = val_getnameinfo(NULL, 
			       (struct sockaddr*)&saddr, 
			       sizeof(struct sockaddr_in), 
			       host, hostlen, serv, servlen, 
			       flags, &val_status);

        printf("Return code = %d\n", retval);
        printf("Validator status code = %d (%s)\n", val_status, p_val_status(val_status));
	printf("Host: %s\nServ: %s\n", host, serv);

        if (retval != 0) {
            printf("Error in val_getnameinfo(): %s\n",
                   gai_strerror(retval));
            return -1;
        } 

        /*
         * cleanup 
         */
        if (val_isvalidated(val_status)) {
            return 2; 
        } 
        if (val_istrusted(val_status)) {
            return 1; 
        }
        
    } else {
        retval = getnameinfo((struct sockaddr*)&saddr, 
			     sizeof(struct sockaddr_in), 
			       host, (size_t)STRLEN, 
			       serv, (size_t)STRLEN, 
			       flags);
        printf("Return code = %d\n", retval);
        if (retval != 0) {
            printf("Error in getaddrinfo(): %s\n", gai_strerror(retval));
            return -1;
        } else {	  
	  printf("Host: %s\nServ: %s\n", host, serv);
        }
    }
    return 0;
}
