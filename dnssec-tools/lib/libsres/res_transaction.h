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
#ifndef __RES_TRANSACTION_H__
#define __RES_TRANSACTION_H__

#include "resolver.h"

/*
	res_transaction

	This routine takes a query and fires it off to the list
	of nameservers (in order) given.  On return, the response
	first obtained is returned, alone with the identity of the
	respondent.

	Parameters
	query		: A DNS ready-to-send query
	query_length	: The used portion of the query (i.e., the
			  value returned by res_mkquery)
	destinations	: List of destinations as defined in res_zone_info.h
			  (see below)
	answer		: A pointer that is malloc'd and filled in with the
			  answer
	answer_length	: A pointer to an integer where the length of the
			  previous parameter is left
	respondent	: A pointer to the element of the list begun by
			  destinations, corresponding to the responding NS.

	Return value
	SR_TR_RESPONSE		: Good response obtained, ans & resp filled
	SR_TR_NO_ANSWER		: All sources timed out
	SR_TR_TSIG_FAILURE	: A TSIG signing or verification failed
	SR_TR_IO_ERROR		: A socket level I/O error occured (select call)
	SR_TR_CALL_ERROR	: A param error occured in call
	SR_TR_MEMORY_ERROR	: Ran out of memory at some point
	SR_TR_TOO_BUSY		: Too many transactions are in progress already
	SR_TR_INTERNAL_ERROR	: A programming error occurred, should not
				  remain after successful porting and testing

	Name Server destinations:

	struct name_server (in res_zone_info.h):
		struct sockaddr		ns_address -> address of NS
		struct generic_key	ns_tsig_key -> NULL
		u_int32_t		ns_security_options -> 0x00000000
		struct name_server	ns_next -> next in the list
*/

#define SR_TR_RESPONSE		1
#define SR_TR_NO_ANSWER		0
#define SR_TR_MEMORY_ERROR	-1
#define SR_TR_CALL_ERROR	-2
#define SR_TR_TSIG_FAILURE	-3
#define SR_TR_IO_ERROR		-4
#define SR_TR_TOO_BUSY		-5
#define SR_TR_INTERNAL_ERROR	-10

int	res_transaction (	u_int8_t *query,
				int query_length,
				struct name_server *destinations,
				u_int8_t **answer,
				int *answer_length,
				struct name_server **respondent);
#endif
