/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the header file for a validating gethostbyname function.
 * Applications should be able to use this with minimal change.
 */

#ifndef VAL_GETHOSTBYNAME_H
#define VAL_GETHOSTBYNAME_H

#include <netdb.h>

/**
 * A function to extract DNSSEC-validation status information from a
 * (struct hostent *) variable.  Note: This variable must be returned
 * from the val_gethostbyname() function.
 */
int val_get_hostent_dnssec_status ( const struct hostent *hentry );

/* A function to free memory allocated by val_gethostbyname() and
 * val_duphostent()
 */
void val_freehostent ( struct hostent *hentry );

/* A function to duplicate a hostent structure.  Performs a
 * deep-copy of the hostent structure.  The returned value
 * must be freed using the val_freehostent() function.
 */
struct hostent* val_duphostent ( const struct hostent *hentry );

/*
 * Returns the entry from the hosts file and DNS for host with name.
 * If DNSSEC validation is successful, *dnssec_status will contain
 * VALIDATE_SUCCESS
 * If there is a failure, *dnssec_status will contain the validator
 * error code.  Applications can use the FREE_HOSTENT() macro given
 * above to free the returned hostent structure.
 */
struct hostent *val_gethostbyname ( const char *name, int *h_errnop );
struct hostent *val_x_gethostbyname ( val_context_t *ctx, const char *name,
				      int *h_errnop );

#endif
