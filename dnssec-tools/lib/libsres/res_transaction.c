
/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 */
#include <stdlib.h>
#include "res_transaction.h"
#include "res_tsig.h"
#include "res_io_manager.h"

#ifndef NULL
#define NULL (void*)0
#endif

int	res_transaction (	u_int8_t *query,
						int query_length,
						struct name_server *destinations,
						u_int8_t **answer,
						int *answer_length,
						struct name_server **respondent)
{
	struct name_server	*ns;
	u_int8_t			*signed_query;
	int					signed_length;
	int					trans_id = -1;
	int					ret_val;

	/* if anything is null, return SR_TR_CALL_ERROR */
	if (query==NULL || destinations==NULL || answer==NULL ||
			answer_length==NULL || respondent==NULL )
		return SR_TR_CALL_ERROR;

	/* Prepare the default response */
	*answer=NULL;
	*answer_length=0;
	*respondent=NULL;

	/*res_io_stall();*/

	/* Loop through the list of destinations */
	for (ns = destinations; ns; ns = ns->ns_next)
	{
		if ((ret_val = res_tsig_sign(query,query_length,ns,
					&signed_query,&signed_length)) != SR_TS_OK)
		{
			if (ret_val == SR_TS_FAIL)
				continue;
			else /* SR_TS_CALL_ERROR */
			{
				res_io_cancel (&trans_id);
				return SR_TR_INTERNAL_ERROR;
			}
		}

		if ((ret_val = res_io_deliver(&trans_id, signed_query,
						signed_length, ns)) <= 0)
		{

			if (ret_val == 0) continue;

			res_io_cancel(&trans_id);

			if (ret_val == SR_IO_MEMORY_ERROR)
				return SR_TR_MEMORY_ERROR;

			else if (ret_val == SR_IO_TOO_MANY_TRANS)
				return SR_TR_TOO_BUSY;
			else
				return SR_TR_INTERNAL_ERROR;
		}

		ret_val = res_io_accept(trans_id, answer, answer_length, respondent);

		if (ret_val != SR_IO_NO_ANSWER && ret_val != SR_IO_NO_ANSWER_YET)
		{
			res_io_cancel(&trans_id);

			if (ret_val == SR_IO_INTERNAL_ERROR) return SR_TR_INTERNAL_ERROR;
			if (ret_val == SR_IO_SOCKET_ERROR) return SR_TR_IO_ERROR;

			/* ret_val is SR_IO_GOT_ANSWER */

			if ((ret_val = res_tsig_verifies (signed_query, signed_length,
					*respondent, *answer, *answer_length))==SR_TS_OK)
				return SR_TR_RESPONSE;
			else if (ret_val == SR_TS_FAIL)
				return SR_TR_TSIG_FAILURE;
			else
				return SR_TR_INTERNAL_ERROR;
		}
	}

	/*
		We've run out of sources to ask but still may have
		some pending requests.  Until we have an answer or
		all our requests time out, we try to accept a
		response.
	*/

	do
	{
		if ((ret_val=res_io_accept(trans_id,answer,answer_length,respondent))
				!= SR_IO_NO_ANSWER_YET)
		{
			res_io_cancel (&trans_id);

			if (ret_val == SR_IO_INTERNAL_ERROR) return SR_TR_INTERNAL_ERROR;
			if (ret_val == SR_IO_SOCKET_ERROR) return SR_TR_IO_ERROR;
			if (ret_val == SR_IO_NO_ANSWER) return SR_TR_NO_ANSWER;

			/* ret_val is SR_IO_GOT_ANSWER */

			if ((ret_val = res_tsig_verifies (signed_query, signed_length,
					*respondent, *answer, *answer_length))==SR_TS_OK)
				return SR_TR_RESPONSE;
			else if (ret_val == SR_TS_FAIL)
				return SR_TR_TSIG_FAILURE;
			else
				return SR_TR_INTERNAL_ERROR;
		}

	} while (ret_val == SR_IO_NO_ANSWER_YET);

	/* Control should never get here */
	return SR_TR_INTERNAL_ERROR;
}
