/*
 * Copyright 2004 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

#ifndef DNSSEC_VALIDATOR_API
#define DNSSEC_VALIDATOR_API

#define DNSSEC_FAILURE 0
#define DNSSEC_SUCCESS 1

/*
 * Returns DNSSEC_SUCCESS if validation succeeds, and
 * DNSSEC_FAILURE if validation fails.
 */
int dnssec_validate(char *domain_name);

#endif
