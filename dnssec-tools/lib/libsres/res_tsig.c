
/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 */

#include <stdlib.h>
#include <string.h>
#include "res_tsig.h"
#include "support.h"

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
			u_int8_t *signed_query,
			int signed_length,
			struct name_server *respondent,
			u_int8_t *answer,
			int answer_length)
{
	if (!(respondent->ns_security_options & ZONE_USE_TSIG))
		return SR_TS_OK;
	else
		return SR_TS_FAIL;
}
