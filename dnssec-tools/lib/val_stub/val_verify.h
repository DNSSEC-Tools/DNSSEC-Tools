/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the header file for the verifier.
 */

#ifndef VAL_VERIFY_H
#define VAL_VERIFY_H

#include <resolver.h>
#include "validator.h"
#include "val_errors.h"
/*
 * Result status codes returned by the validator functions.
 */

typedef int val_result_t;

/*
 * The Verifier Function.
 *
 * Returns VALIDATE_SUCCESS if DNSSEC validation succeeds,
 *         other error codes DNSSEC validation fails
 *         and other values as given above.
 * It takes in a domain_info struct, and does not make any resolver queries itself.
 * It's just a passive verifier.
 */
val_result_t val_verify (struct val_context *context, struct domain_info *response);
void verify_next_assertion(struct assertion_chain *as);

#endif
