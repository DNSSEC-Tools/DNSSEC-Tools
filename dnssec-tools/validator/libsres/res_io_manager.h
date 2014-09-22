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

#define SR_IO_GOT_ANSWER        1
#define SR_IO_UNSET             0
#define SR_IO_NO_ANSWER_YET     -1
#define SR_IO_MEMORY_ERROR      -2
#define SR_IO_TOO_MANY_TRANS    -3
#define SR_IO_SOCKET_ERROR      -4
#define SR_IO_NO_ANSWER         -5
#define SR_IO_INTERNAL_ERROR    -10

/*
 * we limit the number of open sockets, using getrlimit to find the
 * system max and subtracting a few to allow for other occasional uses.
 * If getrlimit fails, we need some reasonable default.
 */
#define SR_IO_NOFILE_RESERVED       10
#define SR_IO_NOFILE_UNKNOWN_SIZE  256

/*
 * res_io_deliver
 * 
 * Enters a query for submission.  After entering the query,
 * a routine is called to check the outgoing data needs which
 * may result in some network traffic being generated.
 *
 * See Also res_io_queue
 * 
 * Parameters
 * 
 * transaction_id is either the id for an existing transaction to which the
 * query should be added, or -1 to begin a new transaction. The new
 * transaction id will be set before returning.
 * 
 * signed_query is a pointer to a query which becomes "owned" by the
 * io manger. signed_length is the length of the query.  The
 * query is sent as it is passed, i.e., it should be TSIG'd
 * before hand.
 * 
 * ns is a structure indicating which name server(s) to use.
 * 
 * Return values
 * 
 * >= 0                 Number of remaining sources pending
 * SR_IO_MEMORY_ERROR   Not enough memory
 * SR_IO_TOO_MANY_TRANS Too many current requests
 */
int             res_io_deliver(int *transaction_id,
                               u_char * signed_query, size_t signed_length,
                               struct name_server *ns, long delay);

/*
 * res_io_queue
 * 
 *   Enters a query for submission, like res_io_deliver, but does not
 *   immediately send them. After queueing queries, call res_io_check
 *   to send them.
 * 
 * Parameters
 * 
 * transaction_id is either the id for an existing transaction to which the
 * query should be added, or -1 to begin a new transaction. The new
 * transaction id will be set before returning.
 * 
 * signed_query is a pointer to a query which becomes "owned" by the
 * io manger. signed_length is the length of the query.  The
 * query is sent as it is passed, i.e., it should be TSIG'd
 * before hand.
 * 
 * ns is a structure indicating which name server(s) to use.
 * 
 * Return values
 * 
 * >= 0                 Number of remaining sources pending
 * SR_IO_MEMORY_ERROR   Not enough memory
 * SR_IO_TOO_MANY_TRANS Too many current requests
 */
int             res_io_queue(int *transaction_id, u_char * signed_query,
                             size_t signed_length, struct name_server *ns,
                             long delay);

/*
 * res_io_queue_ea
 * 
 *   Enters an existing query for submission
 * 
 * Parameters
 * 
 * transaction_id is either the id for an existing transaction to which the
 * query should be added, or -1 to begin a new transaction. The new
 * transaction id will be set before returning.
 * 
 * new_ea is a pointer to an existing query which becomes "owned" by the
 * io manger. 
 * 
 * Return values
 * 
 * >= 0                 Number of remaining sources pending
 * SR_IO_MEMORY_ERROR   Not enough memory
 * SR_IO_TOO_MANY_TRANS Too many current requests
 */
int             res_io_queue_ea(int *transaction_id,
                                struct expected_arrival *new_ea);


/*
 * res_io_accept
 * 
 * Requests a response for the indicated transaction.  If there
 * is a response for the transaction, then the first one found is
 * returned.  Responses for other transactions are also handled, as
 * well as a check of the outgoing needs.  Only responses for the
 * indicated transaction are returned though.
 * 
 * Parameters
 * 
 * transaction_id is the number assigned in the first delivery call.
 * 
 * answer and answer length refer to the response, answer is malloced
 * memory given to the caller for management, answer_length is the
 * response length in bytes
 * 
 * respondent is a pointer to the nameserver from which the answer came
 * 
 * Return values
 * 
 * SR_IO_GOT_ANSWER     An answer is being returned
 * SR_IO_NO_ANSWER              No answer is returned, and there are no more
 * sources (the caller may be adding more)
 * SR_IO_NO_ANSWER_YET  No answer, but there are sources still pending
 * SR_IO_SOCKET_ERROR   An unrecoverable (socket()) error in the
 * communications interface.  This should be
 * treated as an internal error, it should not
 * happen after success full porting and testing.
 * SR_IO_INTERNAL_ERROR A null pointer happened where it should not
 * after success porting and compilation.
 */
int             res_io_accept(int transaction_id, 
                              fd_set *pending_desc,
                              struct timeval *closest_event,
                              u_char ** answer,
                              size_t * answer_length,
                              struct name_server **respondent);

/*
 * res_io_check
 *
 *  Checks all transactions for sends, resends, timeouts and cancellations.
 *
 * Parameters
 *
 *  transaction_id is checked last, and the return code specifies whether
 *  or not this transaction has any queries with remaining attempts.
 *
 *  next_evt is cleared and then set to the earliest retry/cancellation time.
 *
 * Return value
 *
 *   1 if there are still queries with remaining attempts for transaction_id
 *   0 if all queries have timed out or been canceled for transaction_id
 */
int             res_io_check(int transaction_id, struct timeval *next_evt);

/*
 * res_io_check_one
 *
 *  Checks one expected arrival for sends, resends, timeouts and cancellations.
 *
 * Parameters
 *
 *  ea is the expected arrival list for the query.
 *
 *  next_evt is updated with any event time that is earlier than the current
 *  value. Caller is responsible for setting an appropriate value for
 *  next_evt, as this function does not clear it as some other functions do.
 *
 *  now is an (optional) pointer to the current time. If not supplied,
 *  gettimeofday will be used as needed.  If you are calling this function
 *  in a loop, you should probably pass a now pointer.
 *
 * Return value
 *
 *  returns the change in the number of active sockets. A negative value means
 *  more sockets were closed than opened. A zero value can mean no change, or
 *  an equal number of sockets were opened as were closed.
 */
int             res_io_check_one(struct expected_arrival *ea,
                                 struct timeval *next_evt,
                                 struct timeval *now);

/*
 * res_io_check_ea_list
 *
 *  Checks one transaction for sends, resends, timeouts and cancellations.
 *
 * Parameters
 *
 *  ea is the expected arrival list for the query.
 *
 *  next_evt is updated with any event time that is earlier than the current
 *  value. Caller is responsible for setting an appropriate value for
 *  next_evt, as this function does not clear it as some other functions do.
 *
 *  now is an (optional) pointer to the current time. If not supplied,
 *  gettimeofday will be used as needed.  If you are calling this function
 *  in a loop, you should probably pass a now pointer.
 *
 *  net_change, if provided, will be set to the change in the number of
 *  active entries. A negative number means that more were closed than
 *  opened, a positive number means more were opened than closed and 0
 *  means there was no change or and equal number were open as closed.
 *
 *  active, if provided, will be set to the number of active expected
 *  arrivals in the list.
 *
 * Return value
 *
 *  returns 1 if there are still queries with remaining attempts.
 *  returns 0 if all queries have timed out or been canceled.
 */
int             res_io_check_ea_list(struct expected_arrival *ea,
                                     struct timeval *next_evt,
                                     struct timeval *now, int *net_change,
                                     int *active);

/*
 * res_io_check_one_tid
 *
 *  Checks one transaction for sends, resends, timeouts and cancellations.
 *
 * Parameters
 *
 *  see res_io_check_one()
 *
 * Return value
 *
 *  returns 1 if there are still queries with remaining attempts.
 *  returns 0 if all queries have timed out or been canceled.
 */
int             res_io_check_one_tid(int tid, struct timeval *next_evt,
                                     struct timeval *now);

/*
 * switch a newly created/queued es chain to default to TCP
 */
void            res_switch_all_to_tcp(struct expected_arrival *ea);
void            res_switch_all_to_tcp_tid(int tid);

/*
 * res_cancel
 * 
 * Cancels all outstanding requests remaining for a transaction.
 * 
 * Parameters
 * 
 * transaction_id is the number of the transaction to be deleted, as
 * assigned in the first delivery call.  On exit it is set to -1 to
 * remind the caller that the transaction is dead.
 */
void            res_cancel(int *transaction_id);

/*
 * res_io_cancel_all
 * 
 * Cancels all outstanding requests remaining for all transactions.
 */
void            res_io_cancel_all(void);

                        /*
                         * Debugging routines 
                         */
/*
 * res_io_view
 * 
 * Prints the status of the res_io_mamager
 */
void            res_io_view(void);

/*
 * res_io_stall
 * 
 * Stalls the test so it begins on a second since epoch divisible by
 * zero.  Helpfull for tracing the action of the IO manager (time is
 * printed in res_io_view).  This is an obtuse function, but when used
 * in debugging, its value is obvious.
 */
void            res_io_stall(void);

/*
 * res_timeout
 */
long            res_timeout(struct name_server *ns);

/*
 * Early abort of a query attempt. Perform additional retries if desired
 */
int             res_nsfallback(int transaction_id,
                               struct timeval *closest_event,
                               struct name_server *server);
int             res_nsfallback_ea(struct expected_arrival *,
                                  struct timeval *closest_event, 
                                  struct name_server *server);

/*
 * for a given ea, update data structures needed by select
 */
void
res_io_select_info(struct expected_arrival *ea_list, int *nfds,
                   fd_set * read_descriptors, struct timeval *timeout);

/*
 * count the number of descriptors set in the given fdset.
 *
 * the max_fd argument is optional and specifies the highest number fd that
 * may be set (i.e. like the nfds param to select()). If it is less than or
 * equal to zero, every fd is checked.
 */
int
res_io_count_ready(fd_set *read_desc, int max_fd);

/**
 * return the maximum number of sockets io manager will open
 */
long
res_io_get_max_fd(void);

/**
 * return the current number of sockets io manager has open
 */
long
res_io_get_open_sockets(void);

#endif
