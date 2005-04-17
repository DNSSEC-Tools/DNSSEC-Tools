/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
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

#include "val_api.h"

/* Returns 0 on success, -1 on failure */
int _val_query ( const char *domain_name, int class, int type,
		struct domain_info *response,
		int *dnssec_status );

#endif
