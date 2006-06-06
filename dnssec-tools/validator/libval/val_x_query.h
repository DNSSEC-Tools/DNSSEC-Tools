/*
 * Copyright 2006 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_X_QUERY_H
#define VAL_X_QUERY_H

int val_query(const val_context_t *ctx,
          const char *domain_name,
          const u_int16_t class,
          const u_int16_t type,
          const u_int8_t flags,
          struct val_response *resp,
          int *resp_count);

#endif
