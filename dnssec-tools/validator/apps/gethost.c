/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * A command-line tool for testing the val_gethostbyname*() functions.
 */

#include "validator/validator-config.h"
#include <validator/validator.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#define	NAME	"gethost"
#define	VERS	"version: 1.0"
#define	DTVERS	"DNSSEC-Tools Version: 1.8"

#ifdef HAVE_GETOPT_LONG
// Program options
static struct option prog_options[] = {
    {"help", 0, 0, 'h'},
    {"family", 0, 0, 'f'},
    {"reentrant", 0, 0, 'r'},
    {"output", 0, 0, 'o'},
    {"Version", 0, 0, 'V'},
    {0, 0, 0, 0}
};
#endif

#define AUX_BUFLEN 16000

void
usage(char *progname)
{
    /* *INDENT-OFF* */
    fprintf(stderr, "Usage: %s [options] name\n", progname);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "\t-h, --help                      display usage and exit\n");
    fprintf(stderr, "\t-r, --reentrant                 use reentrant versions of functions\n");
    fprintf(stderr, "\t-f, --family=[AF_INET|AF_INET6] address family\n");
    fprintf(stderr, "\t                                AF_INET for IPv4 addresses,\n");
    fprintf(stderr, "\t                                and AF_INET6 for IPv6 addresses\n");
    fprintf(stderr,
            "\t-o, --output=<debug-level>:<dest-type>[:<dest-options>]\n"
            "\t          <debug-level> is 1-7, corresponding to syslog levels\n"
            "\t          <dest-type> is one of file, net, syslog, stderr, stdout\n"
            "\t          <dest-options> depends on <dest-type>\n"
            "\t              file:<file-name>   (opened in append mode)\n" 
            "\t              net[:<host-name>:<host-port>] (127.0.0.1:1053\n" 
            "\t              syslog[:facility] (0-23 (default 1 USER))\n" );
    /* *INDENT-ON* */
    fprintf(stderr, "\t-V, --Version                   display version and exit\n");
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
    struct hostent  hentry;
    char            auxbuf[AUX_BUFLEN];
    struct hostent *result = NULL;

    int             i;
    val_status_t    val_status;
    int             herrno = 0;
    int             familyspecified = 0;
    int             usereentrant = 0;
    char           *name;
    int             af = AF_INET;
    char            buf[INET6_ADDRSTRLEN];
    size_t          buflen = INET6_ADDRSTRLEN;
    val_log_t  *logp;

    memset(&hentry, 0, sizeof(struct hostent));
    memset(auxbuf, 0, AUX_BUFLEN);

    // Parse the command line

    while (1) {
        int             c;
#ifdef HAVE_GETOPT_LONG
        int             opt_index = 0;
#ifdef HAVE_GETOPT_LONG_ONLY
        c = getopt_long_only(argc, argv, "hrf:o:V",
                             prog_options, &opt_index);
#else
        c = getopt_long(argc, argv, "hrf:o:V", prog_options, &opt_index);
#endif
#else                           /* only have getopt */
        c = getopt(argc, argv, "hrf:o:V");
#endif

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage(argv[0]);
            return -1;
        case 'f':
            familyspecified = 1;
            if (strncasecmp(optarg, "AF_INET", strlen("AF_INET")) == 0) {
                af = AF_INET;
            } else if (strncasecmp(optarg, "AF_INET6", strlen("AF_INET6")) == 0) {
                af = AF_INET6;
            } else {
                fprintf(stderr, "Invalid family %s\n", optarg);
                usage(argv[0]);
                return -1;
            }
            break;
        case 'r':
            usereentrant = 1;
            break;
        case 'o':
            logp = val_log_add_optarg(optarg, 1);
            if (NULL == logp) { /* err msg already logged */
                usage(argv[0]);
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
        name = argv[optind++];
    } else {
        fprintf(stderr, "Error: name not specified\n");
        usage(argv[0]);
        return -1;
    }

    if (usereentrant) {
#ifdef HAVE_GETHOSTBYNAME2
            if (familyspecified)
                (void)
                    val_gethostbyname2_r(NULL, name, af, &hentry, auxbuf,
                                         AUX_BUFLEN, &result, &herrno,
                                         &val_status);
            else
#endif
                (void)
                    val_gethostbyname_r(NULL, name, &hentry, auxbuf,
                                        AUX_BUFLEN, &result, &herrno,
                                        &val_status);
    } else {
            if (familyspecified)
                result = val_gethostbyname2(NULL, name, af, &val_status);
            else
                result = val_gethostbyname(NULL, name, &val_status);
    }

    if (result != NULL) {
        const char *addr = NULL;

        printf("\n\th_name = %s\n", result->h_name);
        if (result->h_aliases) {
            printf("\th_aliases = \n");
            for (i = 0; result->h_aliases[i] != 0; i++) {
                printf("\t\t[%d] = %s\n", i, result->h_aliases[i]);
            }
        } else
            printf("\th_aliases = NULL\n");
        printf("\th_length = %d\n", result->h_length);
        printf("\th_addr_list = \n");
        if (result->h_addrtype == AF_INET) {
            struct sockaddr_in sa;
            printf("\th_addrtype = AF_INET\n");
            for (i = 0; result->h_addr_list[i] != 0; i++) {
                memset(buf, 0, buflen);
                memset(&sa, 0, sizeof(sa));
                memcpy(&sa.sin_addr, result->h_addr_list[i],
                       sizeof(sa.sin_addr));
                INET_NTOP(AF_INET, ((struct sockaddr *)&sa), sizeof(sa), 
                    buf, buflen, addr);
                printf("\t\t[%d] = %s\n", i, addr);
            }
        } 
#ifdef VAL_IPV6
        else if (result->h_addrtype == AF_INET6) {
            struct sockaddr_in6 sa6;
            printf("\th_addrtype = AF_INET6\n");
            for (i = 0; result->h_addr_list[i] != 0; i++) {
                memset(buf, 0, buflen);
                memset(&sa6, 0, sizeof(sa6));
                memcpy(&sa6.sin6_addr, result->h_addr_list[i],
                       sizeof(sa6.sin6_addr));
                INET_NTOP(AF_INET6, ((struct sockaddr *)&sa6), sizeof(sa6), 
                    buf, buflen, addr);
                printf("\t\t[%d] = %s\n", i, addr);
            }
        } 
#endif
        else {
            printf("\th_addrtype = %d\n", result->h_addrtype);
        }
    } else {
        printf("result is NULL\n");
    }
    printf("Validation status = %s\n", p_val_error(val_status));
    if (usereentrant) {
#ifdef HAVE_HSTRERROR
        printf("h_errno = %s\n", hstrerror(herrno));
#else
        printf("h_errno = %d\n", herrno);
#endif
    } else {
#ifdef HAVE_HSTRERROR
        printf("h_errno = %s\n", hstrerror(h_errno));
#else
        printf("h_errno = %d\n", h_errno);
#endif
    }

    if (val_isvalidated(val_status))
        return 2;
    if (val_istrusted(val_status))
        return 1;

    return 0;
}
