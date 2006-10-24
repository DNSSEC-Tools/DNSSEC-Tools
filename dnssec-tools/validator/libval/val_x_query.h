/*
 * Copyright 2006 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_X_QUERY_H
#define VAL_X_QUERY_H

int             val_query(val_context_t * ctx,
                          const char *domain_name,
                          const u_int16_t class,
                          const u_int16_t type,
                          const u_int8_t flags,
                          struct val_response **resp);

int             val_free_response(struct val_response *resp);

int             compose_answer(const u_char * name_n,
                               const u_int16_t type_h,
                               const u_int16_t class_h,
                               struct val_result_chain *results,
                               struct val_response **f_resp, u_int8_t flags);

#endif
