/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the implementation file for a wrapper function around the
 * secure resolver.  Applications should be able to use this with
 * minimal change.
 */

#include <stdio.h>
#include <stdlib.h>
#include <resolv.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <resolver.h>
#include <validator.h>

#include "val_log.h"

/*
 * A validating DNS query interface.  Returns the length of the
 * answer if successful, or -1 on error.  If successful, the
 * dnssec_status return value will contain the DNSSEC validation status.
 * For an ANY query, this function cannot return multiple RRSETs. It
 * returns -1 instead.
 * For now, the flags parameter is reserved for future use, and should
 * be set to 0.
 */
int val_query ( const char *dname, int class, int type,
		unsigned char *ans, int anslen, int flags,
		int *dnssec_status )
{
    struct response_t resp[1];
    int respcount = 1;
    int ret_val = INTERNAL_ERROR;

    val_log("val_query called with dname=%s, class=%s, type=%s\n",
	   dname, p_class(class), p_type(type));

    resp[0].response = (u_int8_t *) ans;
    resp[0].response_length = anslen;

    if (dnssec_status == NULL)
	    return BAD_ARGUMENT;

    ret_val = val_x_query (NULL, dname, class, type, flags, resp, &respcount);

    val_log("val_x_query returned %d, validation_result = %d [%s]\n",
	    ret_val, resp[0].validation_result, p_val_error(resp[0].validation_result));

    if ((ret_val == NO_ERROR) && (respcount > 0)) {
	    *dnssec_status = resp[0].validation_result;
	    return resp[0].response_length;
    }
    else {
	    *dnssec_status = ERROR;
	    return -1; /* or ret_val since it is < 0 */
    }
}
