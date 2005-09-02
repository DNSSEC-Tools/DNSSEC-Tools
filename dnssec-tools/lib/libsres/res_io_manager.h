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
#ifndef __RES_IO_MANAGER_H__
#define __RES_IO_MANAGER_H__

#define SR_IO_GOT_ANSWER	1
#define SR_IO_UNSET		0
#define SR_IO_NO_ANSWER_YET -1 
#define SR_IO_MEMORY_ERROR	-2
#define SR_IO_TOO_MANY_TRANS	-3
#define SR_IO_SOCKET_ERROR	-4
#define SR_IO_NO_ANSWER		-5
#define SR_IO_INTERNAL_ERROR	-10

/*
	res_io_deliver

	Enters a query for submission.  After entering the query,
	a routine is called to check the outgoing data needs which
	may result in some network traffic being generated.

	Parameters

	transaction_id is initialized to -1 by caller, then unchanged
	for the rest of the transaction.

	signed_query is a pointer to a query which becomes "owned" by the
	io manger. signed_length is the length of the query.  The
	query is sent as it is passed, i.e., it should be TSIG'd
	before hand.

	ns is a structure indicating which name server to use.

	Return values

	>= 0			Number of remaining sources pending
	SR_IO_MEMORY_ERROR	Not enough memory
	SR_IO_TOO_MANY_TRANS	Too many current requests
*/
int res_io_deliver (int *transaction_id, u_int8_t *signed_query,
			int signed_length, struct name_server *ns);

/*
	res_io_accept

	Requests a response for the indicated transaction.  If there
	is a response for the transaction, then the first one found is
	returned.  Responses for other transactions are also handled, as
	well as a check of the outgoing needs.  Only responses for the
	indicated transaction are returned though.

	Parameters

	transaction_id is the number assigned in the first delivery call.

	answer and answer length refer to the response, answer is malloced
	memory given to the caller for management, answer_length is the
	response length in bytes

	respondent is a pointer to the nameserver from which the answer came

	Return values

	SR_IO_GOT_ANSWER	An answer is being returned
	SR_IO_NO_ANSWER		No answer is returned, and there are no more
				sources (the caller may be adding more)
	SR_IO_NO_ANSWER_YET	No answer, but there are sources still pending
	SR_IO_SOCKET_ERROR	An unrecoverable (socket()) error in the
				communications interface.  This should be
				treated as an internal error, it should not
				happen after success full porting and testing.
	SR_IO_INTERNAL_ERROR	A null pointer happened where it should not
				after success porting and compilation.
*/
int res_io_accept (int transaction_id, u_int8_t **answer, int *answer_length,
				struct name_server **respondent);

/*
	res_io_cancel

	Cancels all outstanding requests remaining for a transaction.

	Parameters

	transaction_id is the number of the transaction to be deleted, as
	assigned in the first delivery call.  On exit it is set to -1 to
	remind the caller that the transaction is dead.
*/
void res_io_cancel (int *transaction_id);

/*
	res_io_cancel_all

	Cancels all outstanding requests remaining for all transactions.
*/
void res_io_cancel_all ();

			/* Debugging routines */
/*
	res_io_view

	Prints the status of the res_io_mamager
*/
void res_io_view();

/*
	res_io_stall

	Stalls the test so it begins on a second since epoch divisible by
	zero.  Helpfull for tracing the action of the IO manager (time is
	printed in res_io_view).  This is an obtuse function, but when used
	in debugging, its value is obvious.
*/
void res_io_stall();

#endif
