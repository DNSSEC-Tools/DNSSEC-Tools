
/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 */

#ifndef RES_QUERY_H
#define RES_QUERY_H

int get (   const char      *name_n,
            const u_int16_t     type_h,
            const u_int16_t     class_h,
            struct res_policy   *respol,
            struct name_server  **server,
            u_int8_t            **response,
            u_int32_t           *response_length,
            char                **error_msg);

#endif
