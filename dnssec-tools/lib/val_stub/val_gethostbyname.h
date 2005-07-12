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

/* A macro to free memory allocated by val_gethostbyname */
#define FREE_HOSTENT(hentry) do { \
	if (hentry) { \
	    int i = 0; \
	    if (hentry->h_name) free (hentry->h_name); \
	    if (hentry->h_aliases) { \
                i = 0; \
		for (i=0; hentry->h_aliases[i] != 0; i++) { \
		    if (hentry->h_aliases[i]) free (hentry->h_aliases[i]); \
		} \
		if (hentry->h_aliases[i]) free (hentry->h_aliases[i]); \
		free (hentry->h_aliases); \
	    } \
	    if (hentry->h_addr_list) { \
                i = 0; \
		for (i=0; hentry->h_addr_list[i] != 0; i++) { \
		    if (hentry->h_addr_list[i]) free (hentry->h_addr_list[i]); \
		} \
		if (hentry->h_addr_list[i]) free (hentry->h_addr_list[i]); \
		free (hentry->h_addr_list); \
	    } \
	    free (hentry); \
	} \
} while (0);

/* Possible values for val_h_errno are similar to those of
 * h_errno in netdb.h */
int val_h_errno;

/*
 * Returns the entry from the hosts file and DNS for host with name.
 * If DNSSEC validation is successful, *dnssec_status will contain
 * VALIDATE_SUCCESS
 * If there is a failure, *dnssec_status will contain the validator
 * error code.  Applications can use the FREE_HOSTENT() macro given above
 * to free the returned hostent structure.
 */
struct hostent *val_gethostbyname ( const char *name, int *dnssec_status );
struct hostent *val_x_gethostbyname ( const char *name, int *dnssec_status );

#endif
