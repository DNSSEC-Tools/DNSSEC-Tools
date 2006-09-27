/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_ASSERTION_H
#define VAL_ASSERTION_H

int             add_to_query_chain(struct val_query_chain **queries,
                                   u_char * name_n, const u_int16_t type_h,
                                   const u_int16_t class_h);
void            free_authentication_chain(struct _val_authentication_chain
                                          *assertions);
void            free_query_chain(struct val_query_chain *queries);
int             val_isauthentic(val_status_t val_status);
int             val_istrusted(val_status_t val_status);
void            val_free_result_chain(struct val_result_chain *results);
int             val_resolve_and_check(val_context_t * context,
                                      u_char * domain_name,
                                      const u_int16_t class,
                                      const u_int16_t type,
                                      const u_int8_t flags,
                                      struct val_result_chain **results);

#endif
