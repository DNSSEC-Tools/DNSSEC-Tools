
/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 */

#ifndef __RES_TSIG_H__
#define __RES_TSIG_H__

#include <sys/types.h>
#include "resolver.h"

#define SR_TS_UNSET		0
#define SR_TS_OK		1
#define SR_TS_FAIL		-2
#define SR_TS_CALL_ERROR	-3

int res_tsig_sign (
			u_int8_t *query,
			int query_length,
			struct name_server *ns,
			u_int8_t **signed_query,
			int *signed_length);

int res_tsig_verifies (
			u_int8_t *signed_query,
			int signed_length,
			struct name_server *respondent,
			u_int8_t *answer,
			int answer_length);

#endif
