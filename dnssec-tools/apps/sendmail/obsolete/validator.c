/*
 * Copyright 2004 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "validator.h"

#define BUFLEN  4096
#define T_RRSIG 46 /* not defined in arpa/nameser.h yet */

void errlog(const char *msg) {
        fprintf(stderr, msg);
}

/*
 * A very simple validator ... just checks for RRSIG records
 */
int dnssec_validate (char *domain_name) {
        char buf[BUFLEN];

	bzero(buf, BUFLEN);

	if (res_init() < 0) {
	        errlog("Validator: Error -- could not initialize resolver.\n");
		return DNSSEC_FAILURE;
	}

	if (res_query(domain_name, C_IN, T_RRSIG, buf, BUFLEN) < 0) {
	        return DNSSEC_FAILURE;
	}
	
	return DNSSEC_SUCCESS;
}
