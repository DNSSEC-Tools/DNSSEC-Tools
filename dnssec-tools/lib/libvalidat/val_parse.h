/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is a header file for functions for parsing certain Resource Records
 */

#ifndef VAL_PARSE_H
#define VAL_PARSE_H

#include <arpa/nameser.h>
#include "val_internal.h"

/* Parse a generic resource record */
int val_parse_rr (unsigned char *buf, int buflen, int offset, ns_rr *rr);

/* Parse the rdata portion of an RRSIG resource record */
int val_parse_rrsig_rdata (const unsigned char *buf, int buflen,
			   val_rrsig_rdata_t *rdata);

#endif
