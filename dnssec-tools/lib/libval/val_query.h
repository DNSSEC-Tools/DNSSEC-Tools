/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the header file for a wrapper function around the
 * secure resolver and the verifier.  Applications should be able to
 * use this with minimal change.
 */

#ifndef VAL_QUERY_H
#define VAL_QUERY_H

/*
 * Returns the length (in bytes) of the answer on success, and -1 on
 * failure.  If DNSSEC validation is successful, *dnssec_status will
 * contain VALIDATE_SUCCESS
 * If there is a failure, *dnssec_status will contain the validator
 * error code.
 */
int val_query ( const char *domain_name, int class, int type,
		unsigned char *answer, int anslen, int flags,
		int *dnssec_status );

#endif
