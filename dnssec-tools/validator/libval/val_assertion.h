/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_ASSERTION_H
#define VAL_ASSERTION_H

int add_to_query_chain(struct val_query_chain **queries, u_char *name_n,
                       const u_int16_t type_h, const u_int16_t class_h);
void free_assertion_chain(struct val_assertion_chain *assertions);
void free_query_chain(struct val_query_chain *queries);

#endif

