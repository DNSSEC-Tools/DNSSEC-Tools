/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the header file for the validator API.
 */

#ifndef VALIDAT_H
#define VALIDAT_H

/*
 * Result status codes returned by the validator functions.
 */

typedef int val_result_t;

#define VAL_SUCCESS     0   /* DNSSEC validation successful            */
#define VAL_FAILURE     1   /* DNSSEC validation failed                */
#define VAL_NOT_INIT    2   /* libvalidat not initialized successfully */
#define VAL_NO_RESOLVER 3   /* Could not find or initialize a
			     * DNSSEC-aware resolver
			     */

/*
 * A function to initialize the library.  This performs functions
 * such as reading configuration files and initializing trust anchors.
 * Returns 0 on success and -1 on error.
 */
int val_init(void);

/*
 * The Validator Function.
 *
 * Returns VAL_SUCCESS if DNSSEC validation succeeds,
 *         VAL_FAILURE if DNSSEC validation fails
 *         and other values as given above.
 */
val_result_t val_check ( const char *domain_name, int class, int type,
			 const char *rdata );

/*
 * The Resolver-and-Validator Function.
 *
 * Returns the rdata in the 'answer' buffer, and the DNSSEC validation
 * status (VAL_SUCCESS, VAL_FAILURE or other values as given above) in the
 * dnssec_status variable.
 *
 * Returns 0 on success and -1 if an error occurs in the DNS query.
 *
 * The values in 'answer' and 'dnssec_status' are valid only if the
 * return value is 0 (i.e. success).
 */
int val_query ( const char *domain_name, int class, int type,
		unsigned char *answer, int anslen,
		val_result_t *dnssec_status );

#endif
