/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * A command-line validator
 */

#include <stdio.h>
#include <strings.h>
#include <errno.h>

#include <arpa/nameser.h>
#include <validat.h>
#include <resolv.h>
#include "val_internal.h"

#define ns_t_ds     43
#define ns_t_rrsig  46
#define ns_t_nsec   47
#define ns_t_dnskey 48

#define BUFLEN 8096

void usage() {
    printf("Usage: validate [[CLASS] TYPE] DOMAIN_NAME\n");
    printf("     If CLASS is not provided, it is assumed to be IN\n");
    printf("     If TYPE is not provided, it is assumed to be A\n");
}

/*
 * A command-line validator
 */
int main(int argc, char *argv[])
{
    int class = ns_c_in;
    int type = ns_t_a;
    char *classstr = NULL;
    char *typestr = NULL;
    char *domain_name = NULL;
    unsigned char *buf;
    val_result_t dnssec_status = -1;

    /* Parse input */
    if ((argc < 2) || (argc > 4)){
	usage();
	exit(1);
    }

    if (argc == 2) {
	domain_name = argv[1];
    }
	
    if (argc == 3) {
	typestr = argv[1];
	domain_name = argv[2];
    }

    if (argc == 4) {
	classstr = argv[1];
	typestr = argv[2];
	domain_name = argv[3];
    }

    printf("domain_name = %s\n", domain_name);

    if (classstr) {
	if (strncasecmp(classstr, "IN", 2) != 0) {
	    printf("Class %s not supported by validate.\n", classstr);
	    exit(1);
	}
	else {
	    printf("class = ns_c_in\n");
	}
    }


    if (typestr) {
	if (strncasecmp(typestr, "DNSKEY", 6) == 0) {
	    type = ns_t_dnskey;
	    printf("type = ns_t_dnskey\n");
	}
	else if (strncasecmp(typestr, "RRSIG", 5) == 0) {
	    type = ns_t_rrsig;
	    printf("type = ns_t_rrsig\n");
	}
	else if (strncasecmp(typestr, "CNAME", 5) == 0) {
	    type = ns_t_cname;
	    printf("type = ns_t_cname\n");
	}
	else if (strncasecmp(typestr, "AAAA", 4) == 0) {
	    type = ns_t_aaaa;
	    printf("type = ns_t_aaaa\n");
	}
	else if (strncasecmp(typestr, "NSEC", 4) == 0) {
	    type = ns_t_nsec;
	    printf("type = ns_t_nsec\n");
	}
	else if (strncasecmp(typestr, "ANY", 3) == 0) {
	    type = ns_t_any;
	    printf("type = ns_t_any\n");
	}
	else if (strncasecmp(typestr, "TXT", 3) == 0) {
	    type = ns_t_txt;
	    printf("type = ns_t_txt\n");
	}
	else if (strncasecmp(typestr, "PTR", 3) == 0) {
	    type = ns_t_ptr;
	    printf("type = ns_t_ptr\n");
	}
	else if (strncasecmp(typestr, "SOA", 3) == 0) {
	    type = ns_t_soa;
	    printf("type = ns_t_soa\n");
	}
	else if (strncasecmp(typestr, "MX", 2) == 0) {
	    type = ns_t_mx;
	    printf("type = ns_t_mx\n");
	}
	else if (strncasecmp(typestr, "DS", 2) == 0) {
	    type = ns_t_dnskey;
	    printf("type = ns_t_ds\n");
	}
	else if (strncasecmp(typestr, "NS", 2) == 0) {
	    type = ns_t_ns;
	    printf("type = ns_t_ns\n");
	}
	else if (strncasecmp(typestr, "A", 1) == 0) {
	    type = ns_t_a;
	    printf("type = ns_t_a\n");
	}
	else {
	    printf("Type %s not supported by validate.\n", typestr);
	    exit(1);
	}
    }
    else {
	    printf("type = ns_t_a\n");
    }

    /* Perform validation */
    buf = (unsigned char *) malloc (BUFLEN * sizeof (unsigned char));
    bzero(buf, BUFLEN);
    printf("initializing validator\n");
    val_init();
    printf("calling val_query()\n");
    if (val_query(domain_name, class, type, buf, BUFLEN, &dnssec_status) < 0) {
	exit(1);
    }
    printf("answer = ");
    val_print_buf(buf, BUFLEN);

    printf("\ndnssec status = ");
    switch (dnssec_status) {
    case VAL_SUCCESS    : printf("VAL_SUCCESS\n");     break;
    case VAL_FAILURE    : printf("VAL_FAILURE\n");     break;
    case VAL_NOT_INIT   : printf("VAL_NOT_INIT\n");    break;
    case VAL_NO_RESOLVER: printf("VAL_NO_RESOLVER\n"); break;
    default: printf("Unknown [%d]\n", dnssec_status);
    }

    if (buf) free(buf);

    return 0;
}
