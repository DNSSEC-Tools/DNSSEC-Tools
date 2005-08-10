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
#include <stdlib.h>
#include <string.h>
#include "res_tsig.h"
#include "res_support.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

int res_tsig_sign(
			u_int8_t *query,
			int query_length,
			struct name_server *ns,
			u_int8_t **signed_query,
			int *signed_length)
{
	if (query && query_length)
	{
		if (!(ns->ns_security_options & ZONE_USE_TSIG))
		{
			*signed_query = (u_int8_t *) MALLOC (query_length);
			memcpy (*signed_query, query, query_length);
			*signed_length = query_length;
			return SR_TS_OK;
		}
		return SR_TS_FAIL;
	}
	else
		return SR_TS_CALL_ERROR;
}

int res_tsig_verifies(
			struct name_server *respondent,
			u_int8_t *answer,
			int answer_length)
{
	if (!(respondent->ns_security_options & ZONE_USE_TSIG))
		return SR_TS_OK;
	else
		return SR_TS_FAIL;
}
