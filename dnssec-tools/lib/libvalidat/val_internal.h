/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the header file for the internal data structures and
 * functions of the validator.
 */

#ifndef VAL_INTERNAL_H
#define VAL_INTERNAL_H

typedef struct val_rrsig_rdata {
    u_int16_t        type_covered;
    u_int8_t         algorithm;
    u_int8_t         labels;
    u_int32_t        orig_ttl;
    u_int32_t        sig_expr;
    u_int32_t        sig_incp;
    u_int16_t        key_tag;
    u_char           signer_name[256]; /* null terminated */
    u_int32_t        signature_len;    /* in bytes */
    u_char *         signature;
} val_rrsig_rdata_t;

#endif

