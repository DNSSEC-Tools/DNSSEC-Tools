/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * A command-line tool for testing the val_getnameinfo() function.
 */
#include "validator/validator-config.h"
#include <validator/validator.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#define	NAME	"getname"
#define	VERS	"version: 1.0"
#define	DTVERS	"DNSSEC-Tools Version: 1.8"

#ifdef HAVE_GETOPT_LONG
// Program options
static struct option prog_options[] = {
    {"help", 0, 0, 'h'},
    {"port", 0, 0, 'p'},
    {"output", 0, 0, 'o'},
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
            "\t-p, --service=<PORT|SERVICE>    transport-layer port or service name\n");
    fprintf(stderr, 
            "\t-F                              add the NI_NOFQDN flag\n"
            "\t-H                              add the NI_NUMERICHOST flag\n"
            "\t-N                              add the NI_NAMEREQD flag\n"
            "\t-S                              add the NI_NUMERICSERV flag\n"
            "\t-D                              add the NI_DGRAM flag\n");
    fprintf(stderr,
            "\t-o, --output=<debug-level>:<dest-type>[:<dest-options>]\n"
            "\t          <debug-level> is 1-7, corresponding to syslog levels\n"
            "\t          <dest-type> is one of file, net, syslog, stderr, stdout\n"
            "\t          <dest-options> depends on <dest-type>\n"
            "\t              file:<file-name>   (opened in append mode)\n" 
            "\t              net[:<host-name>:<host-port>] (127.0.0.1:1053\n" 
            "\t              syslog[:facility] (0-23 (default 1 USER))\n" );
    fprintf(stderr,
            "\t-V, --Version                   display version and exit\n");

}

void
version(void)
{
    fprintf(stderr, "%s: %s\n",NAME,VERS);
    fprintf(stderr, "%s\n",DTVERS);
}

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
    struct sockaddr_storage saddr;
    size_t sock_size;
    // Parse the command line
    while (1) {
        int             c;
#ifdef HAVE_GETOPT_LONG
        int             opt_index = 0;
#ifdef HAVE_GETOPT_LONG_ONLY
        c = getopt_long_only(argc, argv, "ho:p:FHNSDV",
                             prog_options, &opt_index);
#else
        c = getopt_long(argc, argv, "ho:p:FHNSDV", prog_options, &opt_index);
#endif
#else                           /* only have getopt */
        c = getopt(argc, argv, "ho:p:FHNSDV");
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

    if (!strchr(node,':'))  {
       struct sockaddr_in *sa = (struct sockaddr_in *)&saddr;
       sa->sin_port = htons(port);
       sa->sin_family = AF_INET;
       sock_size = sizeof(struct sockaddr_in);
       INET_PTON(AF_INET, node, ((struct sockaddr *)sa), &sock_size);
    } 
#ifdef VAL_IPV6
    else {
       struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&saddr;
       sock_size = sizeof(struct sockaddr_in6);
       sa6->sin6_port = htons(port);
       sa6->sin6_family = AF_INET6;
       INET_PTON(AF_INET6, node, ((struct sockaddr *)sa6), &sock_size);
    }
#endif

    if (portspecified != 1) {
      serv = NULL;
      servlen = 0;
    }

    {

      retval = val_getnameinfo(NULL, 
			       (struct sockaddr*)&saddr, 
			       sock_size,
			       host, hostlen, serv, servlen, 
			       flags, &val_status);

        printf("Return code = %d\n", retval);
        printf("Validator status code = %d (%s)\n", val_status, p_val_status(val_status));
	printf("Host: %s\nServ: %s\n", host, serv);

        if (retval != 0) {
#ifdef HAVE_GAI_STRERROR
            printf("Error in val_getnameinfo(): %s\n",
                   gai_strerror(retval));
#else
            printf("Error in val_getnameinfo(): %d\n", retval);
#endif
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
        
    } 
    return 0;
}
