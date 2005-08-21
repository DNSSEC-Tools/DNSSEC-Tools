/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * A command-line validator.  At present, it's just a verifier.
 */

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <resolver.h> /* for ns_t_dnskey */

#include "val_log.h"
#include "val_api.h"

#define BUFLEN 8096

void usage(char *progname) {
	printf("Usage: %s [[CLASS] TYPE] DOMAIN_NAME\n", progname);
	printf("     If CLASS is not provided, it is assumed to be IN\n");
	printf("     If TYPE is not provided, it is assumed to be A\n");
}

/*
 * A command-line validator
 */
int main(int argc, char *argv[])
{
	int ret_val;
	int class = ns_c_in;
	int type = ns_t_a;
	char *classstr = NULL;
	char *typestr = NULL;
	char *domain_name = NULL;
	unsigned char buf[BUFLEN];
	int dnssec_status = -1;
	int anslen = 0;
	
	/* Parse input */
	if ((argc < 2) || (argc > 4)){
		usage(argv[0]);
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
	
	if (classstr) {
		if (atoi(classstr)) {
			class = atoi(classstr);
		}
		else if (strncasecmp(classstr, "IN", 2) != 0) {
			printf("Class %s not supported.\n", classstr);
			exit(1);
		}
	}
	
	if (typestr) {
		if (strncasecmp(typestr, "DNSKEY", 6) == 0) {
			type = ns_t_dnskey;
		}
		else if (strncasecmp(typestr, "RRSIG", 5) == 0) {
			type = ns_t_rrsig;
		}
		else if (strncasecmp(typestr, "CNAME", 5) == 0) {
			type = ns_t_cname;
		}
		else if (strncasecmp(typestr, "AAAA", 4) == 0) {
			type = ns_t_aaaa;
		}
		else if (strncasecmp(typestr, "NSEC", 4) == 0) {
			type = ns_t_nsec;
		}
		else if (strncasecmp(typestr, "ANY", 3) == 0) {
			type = ns_t_any;
		}
		else if (strncasecmp(typestr, "TXT", 3) == 0) {
			type = ns_t_txt;
		}
		else if (strncasecmp(typestr, "PTR", 3) == 0) {
			type = ns_t_ptr;
		}
		else if (strncasecmp(typestr, "SOA", 3) == 0) {
			type = ns_t_soa;
		}
		else if (strncasecmp(typestr, "MX", 2) == 0) {
			type = ns_t_mx;
		}
		else if (strncasecmp(typestr, "DS", 2) == 0) {
			type = ns_t_dnskey;
		}
		else if (strncasecmp(typestr, "NS", 2) == 0) {
			type = ns_t_ns;
		}
		else if (strncasecmp(typestr, "A", 1) == 0) {
			type = ns_t_a;
		}
		else {
			printf("Type %s not supported.\n", typestr);
			exit(1);
		}
	}
	
	/* Perform query and validation */
	bzero(buf, BUFLEN);
	
	anslen = val_query(domain_name, class, type, buf, BUFLEN, 0, &dnssec_status);
	
	printf("val_query() returned %d\n", anslen);
	printf("DNSSEC status: %d [%s]\n", dnssec_status, p_val_error(dnssec_status));
	
	if (anslen > 0) {
		if (dnssec_status == VALIDATE_SUCCESS) {
			printf("Verified response: \n");
		}
		else {
			printf("Non-verified response: \n");
		}
		print_response(buf, anslen);
	}
	
	return ret_val;
}
