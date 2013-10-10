/*
 * Copyright (c) 1995, 1996, 1997 by Trusted Information Systems, Inc.
 *
 * Permission to use, copy modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND TRUSTED INFORMATION SYSTEMS
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
 * TRUSTED INFORMATION SYSTEMS BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THE SOFTWARE.
 */
#include "validator-internal.h"

#include "res_tsig.h"
#include "res_support.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

int
res_tsig_sign(u_char * query,
              size_t query_length,
              struct name_server *ns,
              u_char ** signed_query, 
              size_t *signed_length)
{
    if (!signed_query || !signed_length)
        return SR_TS_FAIL;
    *signed_query = NULL;
    *signed_length = 0;

    if (query && query_length) {
        if (!(ns->ns_security_options & ZONE_USE_TSIG)) {
            *signed_query = (u_char *) MALLOC(query_length * sizeof(u_char));
            if (*signed_query == NULL) 
                return SR_TS_FAIL;
            memcpy(*signed_query, query, query_length * sizeof(u_char));
            *signed_length = query_length;
            return SR_TS_OK;
        }
        return SR_TS_FAIL;
    } else
        return SR_TS_CALL_ERROR;
}

int
res_tsig_verifies(struct name_server *respondent,
                  u_char * answer, size_t answer_length)
{
    if (!(respondent->ns_security_options & ZONE_USE_TSIG))
        return SR_TS_OK;
    else {
        res_log(NULL, LOG_ERR, "libsres: ""tsig failure!");
        return SR_TS_FAIL;
    }
}
