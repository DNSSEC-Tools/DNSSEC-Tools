/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is header file for printing debugging information from the validator
 */

#ifndef VAL_PRINT_H
#define VAL_PRINT_H

#include <arpa/nameser.h>
#include "val_internal.h"

void val_print_header (unsigned char *buf, int buflen);
void val_print_buf(unsigned char *buf, int buflen);
void val_print_rr (const char *prefix, ns_rr *rr);
void val_print_rrsig_rdata (const char *prefix, val_rrsig_rdata_t *rdata);

#endif
