/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the header file for the verifier.
 */

#ifndef VAL_VERIFY_H
#define VAL_VERIFY_H

/*
 * Result status codes returned by the validator functions.
 */

typedef int     val_result_t;

/*
 * The Verifier Function.
 */
void            verify_next_assertion(val_context_t * ctx,
                                      struct val_digested_auth_chain *as);

#endif
