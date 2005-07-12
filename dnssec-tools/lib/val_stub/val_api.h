/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the header file for the validator API.  Applications should
 * include this header file to make use of the validator API.
 */

#ifndef VAL_API_H
#define VAL_API_H

#include <netdb.h>       /* for struct hostent */

#include "val_errors.h"
#include "val_gethostbyname.h"
#include "val_getaddrinfo.h"

/*
 * Returns the length (in bytes) of the answer on success, and -1 on
 * failure.  If DNSSEC validation is successful, *dnssec_status will
 * contain VALIDATE_SUCCESS
 * If there is a failure, *dnssec_status will contain the validator
 * error code.
 */
int val_query ( const char *domain_name, int class, int type,
		unsigned char *answer, int anslen,
		int *dnssec_status );

#endif
