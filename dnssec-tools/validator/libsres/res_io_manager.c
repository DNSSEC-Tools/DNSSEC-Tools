
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
#include "validator-config.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <arpa/nameser.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#include <errno.h>
#include <pthread.h>
#include "resolver.h"
#include "res_support.h"
#include "res_io_manager.h"

#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#else
#include "arpa/header.h"
#endif

#ifndef NULL
#define NULL (void*)0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

static const int res_io_debug = FALSE;

/*
 * Less than or equal comparison for timeval structures, ignoring
 * microseconds, just like res_send().
 */
#define LTEQ(a,b)           (a.tv_sec<=b.tv_sec)
#define MAX_TRANSACTIONS    128
#define UPDATE(a,b) \
        if (a->tv_sec==0 || !LTEQ((*a),b)) memcpy (a, &b, sizeof(struct timeval))

#define MOVE_TO_NEXT_ADDRESS(t) \
    if (t->ea_socket != -1) close (t->ea_socket); \
    t->ea_socket = -1; \
    t->ea_which_address++; \
    t->ea_remaining_attempts = t->ea_ns->ns_retry; \
    set_alarm(&(t->ea_next_try), 0); \
    set_alarm(&(t->ea_cancel_time),res_timeout(t->ea_ns));

#define MORE_ADDRESSES(ea) \
    ea->ea_which_address < (ea->ea_ns->ns_number_of_addresses-1)

struct expected_arrival {
    int             ea_socket;
    struct name_server *ea_ns;
    int             ea_which_address;
    int             ea_using_stream;
    u_int8_t       *ea_signed;
    int             ea_signed_length;
    u_int8_t       *ea_response;
    int             ea_response_length;
    int             ea_remaining_attempts;
    struct timeval  ea_next_try;
    struct timeval  ea_cancel_time;
    struct expected_arrival *ea_next;
};

static struct expected_arrival *transactions[MAX_TRANSACTIONS] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static int      next_transaction = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

long
res_timeout(struct name_server *ns)
{
    int             i;
    long            cancel_delay = 0;

    for (i = 0; i < ns->ns_retry; i++)
        cancel_delay += ns->ns_retrans << i;

    return cancel_delay;
}

void            res_print_ea(struct expected_arrival *ea);
int             res_quecmp(u_int8_t * query, u_int8_t * response);

void
res_sq_free_expected_arrival(struct expected_arrival **ea)
{
    if (ea == NULL)
        return;
    if (*ea == NULL)
        return;
    if ((*ea)->ea_ns != NULL)
        free_name_server(&((*ea)->ea_ns));
    if ((*ea)->ea_socket != -1)
        close((*ea)->ea_socket);
    if ((*ea)->ea_signed)
        FREE((*ea)->ea_signed);
    if ((*ea)->ea_response)
        FREE((*ea)->ea_response);
    FREE(*ea);

    *ea = NULL;
}

void
set_alarm(struct timeval *tv, long delay)
{
    gettimeofday(tv, NULL);
    tv->tv_sec += delay;
    tv->tv_usec = 0;
}

struct expected_arrival *
res_ea_init(u_int8_t * signed_query, int signed_length,
            struct name_server *ns, long delay)
{
    struct expected_arrival *temp;

    temp = (struct expected_arrival *)
        MALLOC(sizeof(struct expected_arrival));

    if (temp == NULL)
        /** We're out of memory */
        return NULL;

    temp->ea_socket = -1;
    temp->ea_ns = ns;
    temp->ea_which_address = 0;
    temp->ea_using_stream = FALSE;
    temp->ea_signed = signed_query;
    temp->ea_signed_length = signed_length;
    temp->ea_response = NULL;
    temp->ea_response_length = 0;
    temp->ea_remaining_attempts = ns->ns_retry;
    set_alarm(&temp->ea_next_try, delay);
    set_alarm(&temp->ea_cancel_time, delay + res_timeout(ns));
    temp->ea_next = NULL;

    return temp;
}

int
res_io_send(struct expected_arrival *shipit)
{
    /*
     * Choose between TCP and UDP, only differences are the type of
     * socket and whether or not the length of the query is sent first.
     */
    int             socket_type;
    int             bytes_sent;

    if (shipit == NULL)
        return SR_IO_INTERNAL_ERROR;

    socket_type = shipit->ea_using_stream ? SOCK_STREAM : SOCK_DGRAM;

    /*
     * If no socket exists for the transfer, create and connect it (TCP
     * or UDP).  If for some reason this fails, return a -1 which causes
     * the source to be cancelled next go-round.
     */
    if (shipit->ea_socket == -1) {
        int             i = shipit->ea_which_address;
        if ((shipit->ea_socket = socket(PF_INET, socket_type, 0)) == -1)
            return SR_IO_SOCKET_ERROR;

        if (connect(shipit->ea_socket, (struct sockaddr *)&shipit->ea_ns->ns_address[i],
                    sizeof(struct sockaddr)) == -1) {
            close(shipit->ea_socket);
            shipit->ea_socket = -1;
            return SR_IO_SOCKET_ERROR;
        }
    }

    /*
     * We must have a valid socket to use now, so we just need to send the
     * query (but first the length if via TCP).  Again, errors return -1,
     * cause the source to be cancelled.
     */
    if (shipit->ea_using_stream) {
        u_int16_t       length_n =
            htons((u_int16_t) (shipit->ea_signed_length));

        if ((bytes_sent =
             send(shipit->ea_socket, &length_n, sizeof(u_int16_t), 0))
            == -1) {
            close(shipit->ea_socket);
            shipit->ea_socket = -1;
            return SR_IO_SOCKET_ERROR;
        }

        if (bytes_sent != sizeof(u_int16_t)) {
            close(shipit->ea_socket);
            shipit->ea_socket = -1;
            return SR_IO_SOCKET_ERROR;
        }
    }

    if ((bytes_sent = send(shipit->ea_socket, shipit->ea_signed,
                           shipit->ea_signed_length, 0)) == -1) {
        close(shipit->ea_socket);
        shipit->ea_socket = -1;
        return SR_IO_SOCKET_ERROR;
    }

    if (bytes_sent != shipit->ea_signed_length) {
        close(shipit->ea_socket);
        shipit->ea_socket = -1;
        return SR_IO_SOCKET_ERROR;
    }

    return SR_IO_UNSET;
}

static int
res_io_check(int transaction_id, struct timeval *next_evt)
{
    int             i;
    int             total = 0;
    struct timeval  tv;
    struct expected_arrival *temp1;
    struct expected_arrival *temp2;
    long            delay;

    gettimeofday(&tv, NULL);
    tv.tv_usec = 0;

    if (res_io_debug)
        printf("Checking at %ld\n", tv.tv_sec);

    /*
     * Start "next event" at 0.0 seconds 
     */
    memset(next_evt, 0, sizeof(struct timeval));

    pthread_mutex_lock(&mutex);

    for (i = 0; i < MAX_TRANSACTIONS; i++) {
        while (transactions[i]
               && LTEQ(transactions[i]->ea_cancel_time, tv)) {
            /*
             * If there is another address, move to it else cancel it 
             */
            if (MORE_ADDRESSES(transactions[i])) {
                /*
                 * Start over with new address 
                 */
                MOVE_TO_NEXT_ADDRESS(transactions[i]);
                if (res_io_debug) {
                    printf("TIMEOUTS - SWITCHING TO NEW ADDRESS (*)\n");
                    res_print_ea(transactions[i]);
                }
            } else {
                /*
                 * Retire this source 
                 */
                temp1 = transactions[i];
                transactions[i] = transactions[i]->ea_next;
                if (res_io_debug) {
                    printf("TIMEOUT - CANCELING (*)\n");
                    res_print_ea(temp1);
                }
                res_sq_free_expected_arrival(&temp1);
            }
        }

        if (transactions[i]) {
            temp1 = transactions[i];

            do {
                if (LTEQ(temp1->ea_next_try, tv)
                    && temp1->ea_remaining_attempts) {
                    if (res_io_debug)
                        printf("SENDING\n");
                    if (res_io_send(temp1) == SR_IO_SOCKET_ERROR) {
                        /*
                         * If there is another address, move to it
                         * else cancel it 
                         */
                        if (MORE_ADDRESSES(temp1)) {
                            /*
                             * Start over with new address 
                             */
                            MOVE_TO_NEXT_ADDRESS(temp1);
                            if (res_io_debug) {
                                printf
                                    ("ERROR - SWITCHING TO NEW ADDRESS\n");
                                res_print_ea(temp1);
                            }
                        } else {
                            if (res_io_debug) {
                                res_print_ea(temp1);
                                printf("CANCELING DUE TO SENDING ERROR\n");
                            }
                            /*
                             * Cancel this particular source 
                             */
                            temp1->ea_remaining_attempts = 0;
                            gettimeofday(&temp1->ea_cancel_time, NULL);
                            if (res_io_debug)
                                res_print_ea(temp1);
                        }
                    } else {
                        if (i == transaction_id)
                            total++;
                        delay = temp1->ea_ns->ns_retrans
                            << (temp1->ea_ns->ns_retry -
                                temp1->ea_remaining_attempts--);
                        set_alarm(&temp1->ea_next_try, delay);
                        if (res_io_debug)
                            res_print_ea(temp1);
                    }
                } else if (i == transaction_id)
                    total++;

                UPDATE(next_evt, temp1->ea_cancel_time);
                UPDATE(next_evt, temp1->ea_next_try);

                while (temp1->ea_next &&
                       LTEQ(temp1->ea_next->ea_cancel_time, tv)) {
                    /*
                     * Same logic as before, if there are more
                     * addresses for this source try them, else
                     * cancel the source.
                     */
                    if (MORE_ADDRESSES(temp1->ea_next)) {
                        /*
                         * Start over with new address 
                         */
                        MOVE_TO_NEXT_ADDRESS(temp1->ea_next);
                        if (res_io_debug) {
                            printf("TIMEOUT - SWITCHING TO NEW ADDRESS\n");
                            res_print_ea(temp1->ea_next);
                        }
                    } else {
                        if (res_io_debug) {
                            printf("TIMEOUT - CANCELING\n");
                            res_print_ea(temp1->ea_next);
                        }
                        temp2 = temp1->ea_next;
                        temp1->ea_next = temp1->ea_next->ea_next;
                        res_sq_free_expected_arrival(&temp2);
                    }
                }

                temp1 = temp1->ea_next;
            } while (temp1);
        }
    }

    pthread_mutex_unlock(&mutex);

    if (res_io_debug)
        printf("Next event is at %ld\n", next_evt->tv_sec);
    return total;
}

int
res_io_deliver(int *transaction_id, u_int8_t * signed_query,
               int signed_length, struct name_server *ns, long delay)
{
    int             try_index;
    struct expected_arrival *temp;
    struct timeval  next_event;

    /*
     * Determine (new) transaction location 
     */
    pthread_mutex_lock(&mutex);
    if (*transaction_id == -1) {
        /*
         * Find a place to hold this transaction 
         */
        try_index = next_transaction;
        do {
            if (transactions[try_index] == NULL)
                break;
            try_index = (try_index + 1) % MAX_TRANSACTIONS;
        } while (try_index != next_transaction);

        if (try_index == next_transaction
            && transactions[try_index] != NULL) {
            /*
             * We've run out of places to hold transactions 
             */
            pthread_mutex_unlock(&mutex);
            return SR_IO_TOO_MANY_TRANS;
        }

        *transaction_id = try_index;
        next_transaction = (try_index + 1) % MAX_TRANSACTIONS;
    }

    /*
     * Register this request 
     */
    if (transactions[*transaction_id] == NULL) {
        /*
         * Add this as the first request 
         */
        if ((transactions[*transaction_id] =
             res_ea_init(signed_query, signed_length, ns,
                         delay)) == NULL) {
            /** We can't add this */
            pthread_mutex_unlock(&mutex);
            return SR_IO_MEMORY_ERROR;
        }
    } else {
        /*
         * Retaining order is important 
         */
        temp = transactions[*transaction_id];
        while (temp->ea_next)
            temp = temp->ea_next;
        if ((temp->ea_next =
             res_ea_init(signed_query, signed_length, ns,
                         delay)) == NULL) {
            pthread_mutex_unlock(&mutex);
            return SR_IO_MEMORY_ERROR;
        }
    }

    pthread_mutex_unlock(&mutex);

    /*
     * Call the res_io_check routine 
     */
    if (res_io_debug)
        printf("\nCalling io_deliver\n");

    return res_io_check(*transaction_id, &next_event);
}

void
res_io_set_timeout(struct timeval *timeout, struct timeval *next_event)
{
    gettimeofday(timeout, NULL);
    timeout->tv_usec = 0;

    if (LTEQ((*timeout), (*next_event)))
        timeout->tv_sec = next_event->tv_sec - timeout->tv_sec;
    else
        memset(timeout, 0, sizeof(struct timeval));
}

void
res_io_collect_sockets(fd_set * read_descriptors,
                       struct expected_arrival *ea_list)
{
    /*
     * Find all sockets in use for a particular transaction chain of
     * expected arrivals
     */
    FD_ZERO(read_descriptors);

    while (ea_list) {
        if (ea_list->ea_socket != -1)
            FD_SET(ea_list->ea_socket, read_descriptors);

        ea_list = ea_list->ea_next;
    }
}

int
res_io_select_sockets(fd_set * read_descriptors, struct timeval *timeout)
{
    /*
     * Perform the select call 
     */
    int             i, max_sock;

    if (read_descriptors == NULL)
        return SR_IO_INTERNAL_ERROR;

    for (i = 0; i < getdtablesize(); i++)
        if (FD_ISSET(i, read_descriptors))
            max_sock = i;

    return select(max_sock + 1, read_descriptors, NULL, NULL, timeout);
}

int
res_io_get_a_response(struct expected_arrival *ea_list, u_int8_t ** answer,
                      u_int * answer_length,
                      struct name_server **respondent)
{
    int retval;

    while (ea_list) {
        if (ea_list->ea_response) {
            *answer = ea_list->ea_response;
            *answer_length = ea_list->ea_response_length;
            if (SR_UNSET != (retval = clone_ns(respondent, ea_list->ea_ns))) 
                return retval; 
            /* fix the actual server */
            (*respondent)->ns_number_of_addresses = 1;
            memcpy((*respondent)->ns_address,
                   &ea_list->ea_ns->ns_address[ea_list->ea_which_address], 
                   sizeof (struct sockaddr_storage));             
            ea_list->ea_response = NULL;
            ea_list->ea_response_length = 0;
            return SR_IO_GOT_ANSWER;
        }
        ea_list = ea_list->ea_next;
    }
    return SR_IO_UNSET;
}

int
res_io_read_tcp(struct expected_arrival *arrival)
{
    u_int16_t       len_h, len_n;

    /*
     * Read length 
     */
    if (complete_read(arrival->ea_socket, &len_n, sizeof(u_int16_t))
        != sizeof(u_int16_t)) {
        close(arrival->ea_socket);
        arrival->ea_socket = -1;
        return SR_IO_SOCKET_ERROR;
    }

    len_h = ntohs(len_n);

    /*
     * read() message 
     */
    arrival->ea_response = (u_int8_t *) MALLOC(len_h);

    /*
     * Check for out of memory ! 
     */
    arrival->ea_response_length = (int) len_h;

    if (complete_read(arrival->ea_socket, arrival->ea_response, len_h) !=
        len_h) {
        close(arrival->ea_socket);
        arrival->ea_socket = -1;
        FREE(arrival->ea_response);
        arrival->ea_response = NULL;
        arrival->ea_response_length = 0;
        /*
         * Cancel this source 
         */
        arrival->ea_remaining_attempts = 0;
        gettimeofday(&arrival->ea_cancel_time, NULL);
        return SR_IO_SOCKET_ERROR;
    }
    return SR_IO_UNSET;
}

int
res_io_read_udp(struct expected_arrival *arrival)
{
    int             bytes_waiting;
    struct sockaddr from;
    socklen_t       from_length = sizeof(struct sockaddr);
    int             ret_val;

    /*
     * These two make the source comparison if statement easier to read.
     * All these do is cast the address into an inet address (and
     * shorten the name of the address held deep within arrival).
     */
    struct sockaddr_in *from_in = (struct sockaddr_in *) &from;
    struct sockaddr_in *arr_in;

    if (NULL == arrival)
        return SR_IO_INTERNAL_ERROR;

    arr_in = (struct sockaddr_in *)
        &arrival->ea_ns->ns_address[arrival->ea_which_address];

    if (ioctl(arrival->ea_socket, FIONREAD, &bytes_waiting) == -1) {
        close(arrival->ea_socket);
        arrival->ea_socket = -1;
        return SR_IO_SOCKET_ERROR;
    }

    arrival->ea_response = (u_int8_t *) MALLOC(bytes_waiting);
    if (NULL == arrival->ea_response)
        return SR_IO_MEMORY_ERROR;

    ret_val =
        recvfrom(arrival->ea_socket, arrival->ea_response, bytes_waiting,
                 0, &from, &from_length);

    if (ret_val == -1 ||
        memcmp(&from_in->sin_addr, &arr_in->sin_addr,
               sizeof(struct in_addr))
        || from_in->sin_port != arr_in->sin_port) {
        close(arrival->ea_socket);
        arrival->ea_socket = -1;
        FREE(arrival->ea_response);
        arrival->ea_response = NULL;
        arrival->ea_response_length = 0;
        /*
         * Cancel this source 
         */
        arrival->ea_remaining_attempts = 0;
        gettimeofday(&arrival->ea_cancel_time, NULL);
        return SR_IO_SOCKET_ERROR;
    }

    arrival->ea_response_length = ret_val;
    return SR_IO_UNSET;
}


void
res_switch_to_tcp(struct expected_arrival *ea)
{
    if (res_io_debug)
        printf("Switching to TCP\n");

    if (NULL == ea)
        return;

    FREE(ea->ea_response);
    ea->ea_response = NULL;
    ea->ea_response_length = 0;

    /*
     * Use the same "ea_which_address," since it already got a rise. 
     */
    ea->ea_using_stream = TRUE;
    ea->ea_socket = -1;
    ea->ea_remaining_attempts = ea->ea_ns->ns_retry;
    set_alarm(&ea->ea_next_try, 0);

    set_alarm(&ea->ea_cancel_time, res_timeout(ea->ea_ns));
}

void
res_io_read(fd_set * read_descriptors, struct expected_arrival *ea_list)
{
    int             sock;
    struct expected_arrival *arrival;

    for (sock = 0; sock < getdtablesize(); sock++)
        if (FD_ISSET(sock, read_descriptors)) {
            if (res_io_debug)
                printf("ACTIVITY\n");
            /*
             * This socket is ready for reading 
             */
            arrival = ea_list;
            while (arrival && arrival->ea_socket != sock)
                arrival = arrival->ea_next;

            if (arrival == NULL) {
                if (res_io_debug)
                    printf
                        ("Ummm, we lost the record that this socket belongs to.\nSorry.\n");
                close(sock);
                continue;
            }
            if (res_io_debug)
                res_print_ea(arrival);

            if (arrival->ea_using_stream) {
                /** Use TCP */
                if (res_io_read_tcp(arrival) == SR_IO_SOCKET_ERROR)
                    continue;

                if (res_io_debug)
                    printf("Read via TCP\n");
            } else {
                /** Use UDP */
                if (res_io_read_udp(arrival) == SR_IO_SOCKET_ERROR)
                    continue;

                if (res_io_debug)
                    printf("Read via UDP\n");
            }

            /*
             * Make sure this is the query we want (buffer id's match).
             * Check the query line to make sure it's right.
             *
             * I'm not sure this should be done at this level - but
             * res_send does it.  It could be a sign of an attack,
             * but I'll leave it to a network sniffer to figure it
             * out for the time being.
             */
            if (memcmp
                (arrival->ea_signed, arrival->ea_response,
                 sizeof(u_int16_t))
                || res_quecmp(arrival->ea_signed, arrival->ea_response)) {
                /*
                 * The the query and response ID's/query lines don't match 
                 */
                if (res_io_debug)
                    printf
                        ("The the query and response ID's or q_fields don't match\n");
                FREE(arrival->ea_response);
                arrival->ea_response = NULL;
                arrival->ea_response_length = 0;
                continue;
            }

            /*
             * See if the message was truncated
             * switch to TCP
             * reinitialize source (just like we're beginning UDP)
             */
            if (!arrival->ea_using_stream
                && ((HEADER *) arrival->ea_response)->tc)
                res_switch_to_tcp(arrival);
        }
    return;
}

int
res_io_accept(int transaction_id, u_int8_t ** answer,
              u_int * answer_length, struct name_server **respondent)
{
    int             ret_val;
    struct timeval  next_event;
    struct timeval  timeout;
    fd_set          read_descriptors;

    if (res_io_debug)
        printf("\nCalling io_accept\n");

    /*
     * See what needs to be sent.  A return code of 0 means that there
     * is nothing more to be sent and there is also nothing to wait for.
     * 
     * All is not hopeless though - more sources may still waiting to be
     * added via ree_io_deliver().
     */
    if (res_io_check(transaction_id, &next_event) == 0)
        return SR_IO_NO_ANSWER;

    /*
     * See if there is a response waiting that we simply need to pluck.
     */
    pthread_mutex_lock(&mutex);
    if (res_io_get_a_response(transactions[transaction_id],
                              answer, answer_length,
                              respondent) == SR_IO_GOT_ANSWER) {

        pthread_mutex_unlock(&mutex);
        return SR_IO_GOT_ANSWER;
    }
    pthread_mutex_unlock(&mutex);

    /*
     * Set the timeout in case nothing arrives.  The timeout will expire
     * prior to the next event that res_io_check needs to initiate.  If
     * something arrives before that time, fine, we handle it.  Otherwise,
     * return and the check routine will be called again when the next
     * level up decides it is time.
     * 
     * next_event.tv_sec is always set to something (ie, not left at the
     * default) if res_io_check returns a non-0 number.
     */
    res_io_set_timeout(&timeout, &next_event);

    /*
     * Decision time: does this call only look at the sockets used by
     * its transaction id, or does it look at all?
     * 
     * Answer for now -> just the sockets we are interested in.
     */
    pthread_mutex_lock(&mutex);
    res_io_collect_sockets(&read_descriptors,
                           transactions[transaction_id]);
    pthread_mutex_unlock(&mutex);

    ret_val = res_io_select_sockets(&read_descriptors, &timeout);

    if (ret_val == -1)
        /** select call failed */
        return SR_IO_SOCKET_ERROR;

    if (ret_val == SR_IO_INTERNAL_ERROR)
        /** read_descriptors is NULL - impossible case */
        return SR_IO_INTERNAL_ERROR;

    if (ret_val == 0)
        /** There are sources, but none are talking (yet) */
        return SR_IO_NO_ANSWER_YET;

    /*
     * React to the active desciptors.
     */
    pthread_mutex_lock(&mutex);
    res_io_read(&read_descriptors, transactions[transaction_id]);
    pthread_mutex_unlock(&mutex);

    /*
     * Pluck the answer and return it to the caller.
     */
    pthread_mutex_lock(&mutex);
    ret_val = res_io_get_a_response(transactions[transaction_id],
                                    answer, answer_length, respondent);
    pthread_mutex_unlock(&mutex);

    if (ret_val == SR_IO_UNSET)
        return SR_IO_NO_ANSWER_YET;
    else
        return SR_IO_GOT_ANSWER;
}

void
res_io_cancel(int *transaction_id)
{
    struct expected_arrival *ea;

    if (*transaction_id == -1)
        return;

    pthread_mutex_lock(&mutex);
    while (transactions[*transaction_id]) {
        ea = transactions[*transaction_id];
        transactions[*transaction_id] =
            transactions[*transaction_id]->ea_next;
        res_sq_free_expected_arrival(&ea);
    }
    pthread_mutex_unlock(&mutex);

    *transaction_id = -1;
}

void
res_io_cancel_all(void)
{
    int             i, j;
    for (i = 0; i < MAX_TRANSACTIONS; i++) {
        j = i;
        res_io_cancel(&j);
    }
}

void
res_print_ea(struct expected_arrival *ea)
{
    int             i = ea->ea_which_address;
    struct sockaddr_in *s =
        (struct sockaddr_in *) (&(ea->ea_ns->ns_address[i]));

    if (res_io_debug) {
        printf("Socket: %d ", ea->ea_socket);
        printf("Stream: %d ", ea->ea_using_stream);
        printf("Nameserver: %s/(%d)\n", inet_ntoa(s->sin_addr),
               ntohs(s->sin_port));

        printf("Remaining retries: %d ", ea->ea_remaining_attempts);
        printf("Next try %ld, Cancel at %ld\n", ea->ea_next_try.tv_sec,
               ea->ea_cancel_time.tv_sec);
    }
}

void
res_io_view(void)
{
    int             i;
    int             j;
    struct expected_arrival *ea;
    struct timeval  tv;

    gettimeofday(&tv, NULL);
    tv.tv_usec = 0;
    if (res_io_debug)
        printf("Current time is %ld\n", tv.tv_sec);

    pthread_mutex_lock(&mutex);
    for (i = 0; i < MAX_TRANSACTIONS; i++)
        if (transactions[i]) {
            printf("Transaction id: %3d\n", i);
            for (ea = transactions[i], j = 0; ea; ea = ea->ea_next, j++) {
                printf("Source #%d\n", j);
                res_print_ea(ea);
            }
        }
    pthread_mutex_unlock(&mutex);
}

void
res_io_stall(void)
{
    /*
     * Used to cause pretty printing in debug mode 
     */
    struct timeval  tv;

    gettimeofday(&tv, NULL);

    sleep(100 - (tv.tv_sec % 100));
}
