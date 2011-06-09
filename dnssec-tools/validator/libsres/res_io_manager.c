
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
#include "validator-internal.h"

#include "res_support.h"
#include "res_mkquery.h"
#include "res_io_manager.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

static int res_io_debug = FALSE;
int res_io_count_ready(fd_set *read_desc);

void
res_io_set_debug(int val)
{
    res_io_debug = val;
}

int
res_io_get_debug(void)
{
    return res_io_debug;
}

/*
 * Less than or equal comparison for timeval structures, ignoring
 * microseconds, just like res_send().
 */
#define LTEQ(a,b)           (a.tv_sec<=b.tv_sec)
#define UPDATE(a,b) do {                                                \
    if (a->tv_sec==0 || !LTEQ((*a),b))                                  \
        memcpy (a, &b, sizeof(struct timeval));                         \
    } while(0)


#define MAX_TRANSACTIONS    128
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
#ifdef VAL_NO_THREADS
#define pthread_mutex_lock(x)
#define pthread_mutex_unlock(x)
#else
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/*
 * Find a port in the range 1024 - 65535 
 */
static int
bind_to_random_source(SOCKET s)
{   
    /* XXX This is not IPv6 ready yet. Probably need to have
     * XXX a config statement in dnsval.conf that allows the
     * XXX user to specify the preferred source IP
     */
    struct sockaddr_storage ea_source;
    struct sockaddr_in *sa = (struct sockaddr_in *) &ea_source;
    u_int16_t next_port, start_port;

    memset(sa, 0, sizeof(ea_source));
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = htonl(INADDR_ANY);

    start_port = (libsres_random() % 64512) + 1024;
    next_port = start_port;

    do {
        sa->sin_port = htons(next_port);
        if (0 == bind(s, (const struct sockaddr *)sa, 
                    sizeof(struct sockaddr_in))) {
            return 0; /* success */
        } else  {
            /* error */
            if (next_port == 65535)
                next_port = 1024;
            else
                next_port++;
        }
    } while (next_port != start_port);

    /* wrapped around and still no ports found */

    return 1; /* failure */
}

long
res_get_timeout(struct name_server *ns)
{
    int             i;
    long            cancel_delay = 0;

    for (i = 0; i <= ns->ns_retry; i++)
        cancel_delay += ns->ns_retrans << i;

    return cancel_delay;
}

void            res_print_ea(struct expected_arrival *ea);
int             res_quecmp(u_char * query, u_char * response);

void
res_sq_free_expected_arrival(struct expected_arrival **ea)
{
    if (ea == NULL)
        return;
    if (*ea == NULL)
        return;
    if ((*ea)->ea_ns != NULL)
        free_name_server(&((*ea)->ea_ns));
    if ((*ea)->ea_socket != INVALID_SOCKET)
        CLOSESOCK((*ea)->ea_socket);
    if ((*ea)->ea_signed)
        FREE((*ea)->ea_signed);
    if ((*ea)->ea_response)
        FREE((*ea)->ea_response);
    FREE(*ea);

    *ea = NULL;
}

void
res_free_ea_list(struct expected_arrival *head)
{
    struct expected_arrival *ea;

    while (head) {
        ea = head;
        head = head->ea_next;
        res_sq_free_expected_arrival(&ea);
    }
}

void
set_alarm(struct timeval *tv, long delay)
{
    gettimeofday(tv, NULL);
    tv->tv_sec += delay;
    tv->tv_usec = 0;
}

struct expected_arrival *
res_ea_init(u_char * signed_query, size_t signed_length,
            struct name_server *ns, long delay)
{
    struct expected_arrival *temp;

    temp = (struct expected_arrival *)
        MALLOC(sizeof(struct expected_arrival));

    if (temp == NULL)
        /** We're out of memory */
        return NULL;

    memset(temp, 0x0, sizeof(struct expected_arrival));
    temp->ea_socket = INVALID_SOCKET;
    temp->ea_ns = ns;
    temp->ea_which_address = 0;
    temp->ea_using_stream = FALSE;
    temp->ea_signed = signed_query;
    temp->ea_signed_length = signed_length;
    temp->ea_response = NULL;
    temp->ea_response_length = 0;
    temp->ea_remaining_attempts = ns->ns_retry+1;
    set_alarm(&temp->ea_next_try, delay);
    set_alarm(&temp->ea_cancel_time, delay + res_get_timeout(ns));
    temp->ea_next = NULL;

    return temp;
}

void
res_io_cancel_remaining_attempts(struct expected_arrival *ea)
{
    if (ea->ea_socket != INVALID_SOCKET) {
        CLOSESOCK(ea->ea_socket);
        ea->ea_socket = INVALID_SOCKET;
    }
    ea->ea_remaining_attempts = -1;
}

void
res_io_cancel_source(struct expected_arrival *ea)
{
    /* close socket */
    if (ea->ea_socket != -1) {
        close(ea->ea_socket);
        ea->ea_socket = -1;
    }

    /* no more retries */
    ea->ea_remaining_attempts = 0;

    /* bump cancel time to current time */
    gettimeofday(&ea->ea_cancel_time, NULL);
}

void
res_io_cancel_all_remaining_attempts(struct expected_arrival *ea)
{
    for ( ; ea; ea = ea->ea_next) {
        if (ea->ea_socket != INVALID_SOCKET) {
            CLOSESOCK(ea->ea_socket);
            ea->ea_socket = INVALID_SOCKET;
        }
        ea->ea_remaining_attempts = -1;
    }
}

int
res_io_is_finished(struct expected_arrival *ea)
{
    return ea->ea_remaining_attempts == -1;
}

int
res_io_are_all_finished(struct expected_arrival *ea)
{
    for ( ; ea; ea = ea->ea_next) 
        if (ea->ea_remaining_attempts != -1)
            return FALSE;
    return TRUE;
}

int
res_io_send(struct expected_arrival *shipit)
{
    /*
     * Choose between TCP and UDP, only differences are the type of
     * socket and whether or not the length of the query is sent first.
     */
    int             socket_type;
    int             socket_proto;
    size_t          socket_size;
    size_t          bytes_sent;
    long            delay;

    if (shipit == NULL)
        return SR_IO_INTERNAL_ERROR;

    socket_type = (shipit->ea_using_stream == 1) ? SOCK_STREAM : SOCK_DGRAM;
    socket_proto = (socket_type == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
    val_log(NULL, LOG_DEBUG, "libsres: ""ea %p SENDING", shipit);

    /*
     * If no socket exists for the transfer, create and connect it (TCP
     * or UDP).  If for some reason this fails, return a INVALID_SOCKET 
     * which causes the source to be cancelled next go-round.
     */
    if (shipit->ea_socket == INVALID_SOCKET) {
        int             i = shipit->ea_which_address;

        if ((shipit->ea_socket = socket( shipit->ea_ns->ns_address[i]->ss_family,
                                        socket_type, socket_proto)) == INVALID_SOCKET)
            return SR_IO_SOCKET_ERROR;

        /* Set the source port */
        if (0 != bind_to_random_source(shipit->ea_socket)) {
            /* error */
            CLOSESOCK(shipit->ea_socket);
            return SR_IO_SOCKET_ERROR;
        }
         
        /*
         * OS X wants the socket size to be sockaddr_in for INET,
         * while Linux is happy with sockaddr_storage. Might need
         * to fix this for sockaddr_in6 too...
         */
        socket_size = shipit->ea_ns->ns_address[i]->ss_family == AF_INET ?
                      sizeof(struct sockaddr_in) : sizeof(struct sockaddr_storage);
        if (connect
            (shipit->ea_socket,
             (struct sockaddr *) shipit->ea_ns->ns_address[i],
             socket_size) == SOCKET_ERROR) {
            val_log(NULL, LOG_ERR,
                    "libsres: ""Closing socket %d, connect errno = %d",
                    shipit->ea_socket, errno);
            CLOSESOCK(shipit->ea_socket);
            shipit->ea_socket = INVALID_SOCKET;
            return SR_IO_SOCKET_ERROR;
        }
    }

    /*
     * We must have a valid socket to use now, so we just need to send the
     * query (but first the length if via TCP).  Again, errors return -1,
     * cause the source to be cancelled.
     */
    if (shipit->ea_using_stream) {

        u_int16_t length_n;
        length_n = htons(shipit->ea_signed_length);


        if ((bytes_sent =
             send(shipit->ea_socket, (const char *)&length_n, sizeof(length_n), 0))
            == SOCKET_ERROR) {
            CLOSESOCK(shipit->ea_socket);
            shipit->ea_socket = INVALID_SOCKET;
            return SR_IO_SOCKET_ERROR;
        }


        if (bytes_sent != sizeof(length_n)) {
            CLOSESOCK(shipit->ea_socket);
            shipit->ea_socket = INVALID_SOCKET;
            return SR_IO_SOCKET_ERROR;
        }
    }

    bytes_sent = send(shipit->ea_socket, (const char*)shipit->ea_signed,
                      shipit->ea_signed_length, 0);
    if (bytes_sent != shipit->ea_signed_length) {
        val_log(NULL, LOG_ERR, "libsres: "
                "Closing socket %d, sending %d bytes failed (rc %d)",
                shipit->ea_socket, shipit->ea_signed_length, bytes_sent);
        CLOSESOCK(shipit->ea_socket);
        shipit->ea_socket = INVALID_SOCKET;
        return SR_IO_SOCKET_ERROR;
    }

    delay = shipit->ea_ns->ns_retrans
        << (shipit->ea_ns->ns_retry + 1 - shipit->ea_remaining_attempts--);
    val_log(NULL, LOG_ERR, "libsres: ""next try delay %d", delay);
    set_alarm(&shipit->ea_next_try, delay);
    res_print_ea(shipit);

    return SR_IO_UNSET;
}

int 
res_nsfallback(int transaction_id, struct timeval *closest_event, 
               const char *name, const u_int16_t class_h, 
               const u_int16_t type_h, int *edns0)
{
    struct expected_arrival *temp;
    int ret_val = -1;

    if (transaction_id == -1 )
        return -1;  

    pthread_mutex_lock(&mutex);
    for (temp = transactions[transaction_id];
         temp && temp->ea_remaining_attempts == -1;
         temp = temp->ea_next)
         ;
    if (temp != NULL) {
        val_log(NULL, LOG_ERR, "libsres: ""Aborting current attempt for transaction %d",
                transaction_id);
        ret_val = res_nsfallback_ea(temp, closest_event, name, class_h, type_h,
                                    edns0);
    }
    else
        *edns0 = 0;

    pthread_mutex_unlock(&mutex);
    return ret_val;
}

int 
res_nsfallback_ea(struct expected_arrival *temp, struct timeval *closest_event, 
                  const char *name, const u_int16_t class_h, 
                  const u_int16_t type_h, int *edns0)
{
    const static int edns0_fallback[] = { 4096, 1492, 512, 0 };
    long             delay = 0, i;

    if (!temp && !name)
        return -1;

    if ((temp->ea_ns->ns_options & RES_USE_DNSSEC) && 
        (temp->ea_ns->ns_edns0_size > 0)) {
        *edns0 = 1;
        for (i = 0; i < sizeof(edns0_fallback); i++) {
            if (temp->ea_ns->ns_edns0_size > edns0_fallback[i]) {
                /* try using a lower edns0 value */
                temp->ea_ns->ns_edns0_size = edns0_fallback[i];
                if (edns0_fallback[i] == 0) {
                    /* try without EDNS0 */
                    temp->ea_ns->ns_options ^= RES_USE_DNSSEC;
                    *edns0 = 0;
                    if (temp->ea_signed)
                        FREE(temp->ea_signed);
                    temp->ea_signed = NULL;
                    temp->ea_signed_length = 0;

                    if (res_create_query_payload(temp->ea_ns,
                                    name, class_h, type_h,
                                    &temp->ea_signed,
                                    &temp->ea_signed_length) < 0)
                        break;
                }
                temp->ea_remaining_attempts++;
                if (temp->ea_socket != INVALID_SOCKET)
                    CLOSESOCK(temp->ea_socket);
                temp->ea_socket = INVALID_SOCKET;

                break;
            }
        }
    }
    else
        *edns0 = 0;

    if (temp->ea_remaining_attempts == 0)
        return -1;

    gettimeofday(&temp->ea_next_try, NULL);
    for (i = 0; i < temp->ea_remaining_attempts; i++)
        delay += temp->ea_ns->ns_retrans << i;

    set_alarm(&temp->ea_cancel_time, delay); 
    UPDATE(closest_event, temp->ea_next_try);
    /* 
     *  if next event is in the future, make sure we
     *  offset it to the current time 
     */
    if (temp->ea_next) {
        struct expected_arrival *t;
        long offset = temp->ea_next->ea_next_try.tv_sec - 
                            temp->ea_next_try.tv_sec;
        if (offset > 0) {
            for (t=temp->ea_next; t; t=t->ea_next) {
                t->ea_next_try.tv_sec -= offset;
                t->ea_cancel_time.tv_sec -= offset;
            } 
        }
    }
    return 0;
}

static void
res_io_next_address(struct expected_arrival *ea,
                    const char *more_prefix, const char *no_more_str)
{
    /*
     * If there is another address, move to it else cancel it 
     */
    if (ea->ea_which_address < (ea->ea_ns->ns_number_of_addresses-1)) {
        /*
         * Start over with new address 
         */
        if (ea->ea_socket != INVALID_SOCKET) {
            CLOSESOCK (ea->ea_socket);
            ea->ea_socket = INVALID_SOCKET;
        }
        ea->ea_which_address++;
        ea->ea_remaining_attempts = ea->ea_ns->ns_retry+1;
        set_alarm(&(ea->ea_next_try), 0);
        set_alarm(&(ea->ea_cancel_time),res_get_timeout(ea->ea_ns));
        val_log(NULL, LOG_INFO,
                "libsres: ""%s - SWITCHING TO NEW ADDRESS", more_prefix);
    } else {
        /*
         * cancel this source 
         */
        res_io_cancel_remaining_attempts(ea);
        val_log(NULL, LOG_INFO, "libsres: ""%s", no_more_str);
    }
    res_print_ea(ea);
}

int
res_io_check_one(struct expected_arrival *ea, struct timeval *next_evt,
                 struct timeval *now)
{
    int             total = 0, checked = 0;
    struct timeval  local_now;
    struct expected_arrival *orig_ea = ea;
            struct name_server *tempns;
            char            name_buf[INET6_ADDRSTRLEN + 1];
            int i = 0;
    
    /*
     * if caller didn't pass us current time, get it
     */
    if (NULL == now) {
        now = &local_now;
        gettimeofday(&local_now, NULL);
        local_now.tv_usec = 0;
    }

    val_log(NULL, LOG_DEBUG, "libsres: ""res_io_check_one");

    for ( ; ea; ea = ea->ea_next ) {
        if (ea->ea_remaining_attempts == -1) {
            val_log(NULL, LOG_DEBUG, "libsres: "
                    " res_io_check_one skipping %p (sock %d, rem %d)",
                    ea, ea->ea_socket, ea->ea_remaining_attempts);
            continue;
        }
        if (ea->ea_socket != -1 ) {
            val_log(NULL, LOG_DEBUG, "libsres: "
                    " ea %p/%p socket=%d, rem %d, ns %d/%d, next try %d, cancel %d",
                    orig_ea, ea, ea->ea_socket, ea->ea_remaining_attempts,
                    ea->ea_which_address, ea->ea_ns->ns_number_of_addresses,
                    ea->ea_next_try, ea->ea_cancel_time);
            for(i=0,tempns = ea->ea_ns ; i<tempns->ns_number_of_addresses; ++i)
                val_log(NULL, LOG_DEBUG+1, "    %d:%s", i,
                        val_get_ns_string((struct sockaddr *)
                                          tempns->ns_address[i],
                                          name_buf, sizeof(name_buf)));
        }

        /*
         * check for timeouts. If there is another address, move to it
         */
        if ( LTEQ(ea->ea_cancel_time, (*now))) {
            res_io_next_address(ea, "TIMEOUTS", "TIMEOUT - CANCELING");
            --total;
        }

        /*
         * send next try. on error, if there is another address, move to it
         */
        else if (LTEQ(ea->ea_next_try, (*now))) {
            int needed_new_socket = (ea->ea_socket == INVALID_SOCKET);
            val_log(NULL, LOG_DEBUG, "libsres: "" retry");
            while (ea->ea_remaining_attempts != -1) {
                if (res_io_send(ea) == SR_IO_SOCKET_ERROR) {
                    res_io_next_address(ea, "ERROR",
                                        "CANCELING DUE TO SENDING ERROR");
                }
                else {
                    if (needed_new_socket)
                        ++total;
                    break; /* from while remaining attempts */
                }
            } /* while */
        }
        else if (ea->ea_socket == -1) {
            struct expected_arrival *tmp_ea = ea;
            int count = 1;
            for (ea = ea->ea_next; ea; ea = ea->ea_next )
#if 0 
                val_log(NULL, LOG_DEBUG, "libsres: "" skipping"
                        " ea %p/%p socket=%d, rem %d, ns %d/%d, "
                        "next try %d, cancel %d",
                        orig_ea, ea, ea->ea_socket, ea->ea_remaining_attempts,
                        ea->ea_which_address, ea->ea_ns->ns_number_of_addresses,
                        ea->ea_next_try, ea->ea_cancel_time);
#else
                ++count;
            val_log(NULL, LOG_DEBUG, "libsres: "" skipping remaining %d ns list",
                    count);
#endif
            break;
        }
        else
            ++checked;

        /*
         * update next event
         */
        if (next_evt && ea->ea_remaining_attempts != -1) {
            UPDATE(next_evt, ea->ea_cancel_time);
            UPDATE(next_evt, ea->ea_next_try);
        }
    }

    return total;
}

static int
res_io_check(int transaction_id, struct timeval *next_evt)
{
    int             i;
    struct timeval  tv;
    struct expected_arrival *ea;

    gettimeofday(&tv, NULL);
    val_log(NULL, LOG_DEBUG, "libsres: ""Checking at %ld.%ld", tv.tv_sec,
            tv.tv_usec);
    tv.tv_usec = 0;

    /*
     * Start "next event" at 0.0 seconds 
     */
    memset(next_evt, 0, sizeof(struct timeval));

    pthread_mutex_lock(&mutex);

    for (i = 0; i < MAX_TRANSACTIONS; i++)
        if (transactions[i])
            res_io_check_one(transactions[i], next_evt, &tv);

    ea = transactions[transaction_id];
    pthread_mutex_unlock(&mutex);

    val_log(NULL, LOG_DEBUG,
            "libsres: "" Next event is at %ld", next_evt->tv_sec);

    /*
     * check for remaining attempts for this transaction
     */
    for (; ea; ea = ea->ea_next)
        if (ea->ea_remaining_attempts != -1)
            return 1;

    return 0; /* no events for this transaction */
}

int
res_io_deliver(int *transaction_id, u_char * signed_query,
               size_t signed_length, struct name_server *ns, long delay)
{
    int             try_index;
    struct expected_arrival *temp, *new_ea;
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
    new_ea = res_ea_init(signed_query, signed_length, ns, delay);
    if (new_ea == NULL) {
        /** We can't add this */
        pthread_mutex_unlock(&mutex);
        return SR_IO_MEMORY_ERROR;
    }
    if (transactions[*transaction_id] == NULL) {
        /*
         * Add this as the first request 
         */
        transactions[*transaction_id] = new_ea;
    } else {
        /*
         * Retaining order is important 
         */
        temp = transactions[*transaction_id];
        while (temp->ea_next)
            temp = temp->ea_next;
        temp->ea_next = new_ea;
    }

    pthread_mutex_unlock(&mutex);

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
    res_io_select_info(ea_list, NULL, read_descriptors, NULL);
}

void
res_io_select_info(struct expected_arrival *ea_list, int *nfds,
                   fd_set * read_descriptors, struct timeval *timeout)
{
    struct timeval now;
    struct expected_arrival *orig_ea_list = ea_list;

    if (timeout) {
        val_log(NULL, LOG_DEBUG,
                "libsres: "" ea %p select/timeout info. orig timeout %ld,%ld",
                ea_list, timeout->tv_sec, timeout->tv_usec);
        gettimeofday(&now, NULL);
        now.tv_usec = 0;
    }
    else
        val_log(NULL, LOG_DEBUG, "libsres: "" ea %p select info",
                ea_list);
    /*
     * Find all sockets in use for a particular transaction chain of
     * expected arrivals
     */
    for ( ; ea_list; ea_list = ea_list->ea_next) {
        if ((ea_list->ea_remaining_attempts == -1) ||
            (ea_list->ea_socket == INVALID_SOCKET))
            continue;

        val_log(NULL,LOG_DEBUG, "libsres:""   fd %d added", ea_list->ea_socket);
        if (read_descriptors)
            FD_SET(ea_list->ea_socket, read_descriptors);
        if (nfds && (ea_list->ea_socket >= *nfds))
            *nfds = ea_list->ea_socket + 1;

        if (timeout) {
            UPDATE(timeout, ea_list->ea_cancel_time);
            UPDATE(timeout, ea_list->ea_next_try);
        }
    }
    if (timeout) {
        val_log(NULL, LOG_DEBUG,
                "libsres: "" ea %p select/timeout info. final timeout %ld,%ld",
                orig_ea_list, timeout->tv_sec, timeout->tv_usec);
    }
}

static int
res_io_select_sockets(fd_set * read_descriptors, struct timeval *timeout)
{
    /*
     * Perform the select call 
     */
    int             i, max_sock, count, ready;
    struct timeval  in,out;

    max_sock = -1;

    i = getdtablesize(); 
    if (i > FD_SETSIZE)
        i = FD_SETSIZE;
    for (--i; i >= 0; --i)
        if (FD_ISSET(i, read_descriptors)) {
            max_sock = i;
            break;
        }
    if (max_sock < 0)
        return 0; /* nothing to read */
    if (max_sock > FD_SETSIZE)
        max_sock = FD_SETSIZE;

    for (count=i=0; i <= max_sock; ++i)
        if (FD_ISSET(i, read_descriptors)) {
            ++count;
            val_log(NULL,LOG_DEBUG, "libsres: ""  fd %d set", i);
        }
    gettimeofday(&in, NULL);
    val_log(NULL, LOG_DEBUG,
            "libsres: ""SELECT on %d fds, max %d, timeout %ld.%ld @ %ld.%ld",
            count, max_sock+1,timeout->tv_sec,timeout->tv_usec,
            in.tv_sec,in.tv_usec);
#ifdef HAVE_PSELECT
    struct timespec timeout_ts;
    timeout_ts.tv_sec = timeout->tv_sec;
    timeout_ts.tv_nsec = 0;
    ready = pselect(max_sock + 1, read_descriptors, NULL, NULL, &timeout_ts, NULL);
#else
    ready = select(max_sock + 1, read_descriptors, NULL, NULL, timeout);
#endif
    gettimeofday(&out, NULL);
    val_log(NULL, LOG_DEBUG, "libsres: "" %d ready fds @ %ld.%ld",
            i,out.tv_sec,out.tv_usec);
    for (count=i=0; i <= max_sock; ++i)
        if (FD_ISSET(i, read_descriptors)) {
            ++count;
            val_log(NULL,LOG_DEBUG, "libsres: ""  fd %d ready", i);
        }

    return ready;
}

void
wait_for_res_data(fd_set * pending_desc, struct timeval *closest_event)
{
    struct timeval timeout;

    val_log(NULL,LOG_DEBUG,"libsres: ""wait_for_res_data");

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
    val_log(NULL, LOG_DEBUG, "libsres: "" closest event %ld,%ld",
            closest_event->tv_sec, closest_event->tv_usec);
    res_io_set_timeout(&timeout, closest_event);
    res_io_select_sockets(pending_desc, &timeout); 
	
    // ignore return value from previous function, 
    // will catch this condition when we actually read data
}

int
res_io_get_a_response(struct expected_arrival *ea_list, u_char ** answer,
                      size_t * answer_length,
                      struct name_server **respondent)
{
    int             retval;
    int             save_count = -1;

    for( ; ea_list; ea_list = ea_list->ea_next) {
        if (ea_list->ea_remaining_attempts == -1)
            continue;

        if (!ea_list->ea_response)
            continue;

        { /** dummy block to preserve indentation; reformat later */
            *answer = ea_list->ea_response;
            *answer_length = ea_list->ea_response_length;
            val_log(NULL, LOG_DEBUG,
                    "libsres: ""get_response got %zd bytes on socket %d",
                    *answer_length, ea_list->ea_socket);

            /*
             * don't clone all when we just need one. temporarily set
             * number of nameservers to 1 before cloning.
             */
            if (ea_list->ea_ns->ns_number_of_addresses > 1) {
                save_count = ea_list->ea_ns->ns_number_of_addresses;
                ea_list->ea_ns->ns_number_of_addresses = 1;
            }
            if (SR_UNSET !=
                (retval = clone_ns(respondent, ea_list->ea_ns)))
                return retval;
            if (save_count > 0) /* restore original count */
                ea_list->ea_ns->ns_number_of_addresses = save_count;

            /** if response wasn't from first address, fixup respondent */
            if (ea_list->ea_which_address != 0) {
                memcpy(((*respondent)->ns_address[0]),
                       ea_list->ea_ns->ns_address[ea_list->
                                                  ea_which_address],
                       sizeof(struct sockaddr_storage));
            }
            ea_list->ea_response = NULL;
            ea_list->ea_response_length = 0;
            return SR_IO_GOT_ANSWER;
        }
    }
    return SR_IO_UNSET;
}

size_t
complete_read(SOCKET sock, u_char *field, size_t length)
{
    size_t             bytes;
    size_t             bytes_read = 0;
    memset(field, '\0', length);

    do {
        bytes = recv(sock, field + bytes_read, length - bytes_read, 0);
        if (bytes == SOCKET_ERROR) {
            bytes_read = -1;
            break;
        }
        bytes_read += bytes;
    } while (bytes_read < length);

    return bytes_read;
}

int
res_io_read_tcp(struct expected_arrival *arrival)
{
    u_int16_t    len_n;
    size_t       len_h;

    /*
     * Read length 
     */
    if (complete_read(arrival->ea_socket, (u_char *)&len_n, sizeof(len_n))
        != sizeof(len_n)) {
        CLOSESOCK(arrival->ea_socket);
        arrival->ea_socket = INVALID_SOCKET;
        return SR_IO_SOCKET_ERROR;
    }

    len_h = ntohs(len_n);

    /*
     * read() message 
     */
    arrival->ea_response = (u_char *) MALLOC(len_h * sizeof(u_char));
    if (arrival->ea_response == NULL) {
        CLOSESOCK(arrival->ea_socket);
        arrival->ea_socket = INVALID_SOCKET;
        return SR_IO_MEMORY_ERROR;
    }

    arrival->ea_response_length = len_h;

    if (complete_read(arrival->ea_socket, (u_char *)arrival->ea_response, len_h) !=
        len_h) {
        FREE(arrival->ea_response);
        arrival->ea_response = NULL;
        arrival->ea_response_length = 0;
        /*
         * Cancel this source 
         */
        res_io_cancel_remaining_attempts(arrival);
        return SR_IO_SOCKET_ERROR;
    }
    return SR_IO_UNSET;
}

int
res_io_read_udp(struct expected_arrival *arrival)
{
    size_t bytes_waiting = 8192;
    struct sockaddr_storage from;
    socklen_t       from_length = sizeof(from);
    int             ret_val, arr_family;

    if (NULL == arrival)
        return SR_IO_INTERNAL_ERROR;

    arrival->ea_response = (u_char *) MALLOC(bytes_waiting * sizeof(u_char));
    if (NULL == arrival->ea_response)
        return SR_IO_MEMORY_ERROR;

    ret_val =
        recvfrom(arrival->ea_socket, (char *)arrival->ea_response, bytes_waiting,
                 0, (struct sockaddr*)&from, &from_length);

    if (0 == ret_val) { /* what does 0 bytes mean from udp socket? */
        // xxx-rks: allow other attempt, or goto error?
        val_log(NULL, LOG_INFO,
                "libsres: ""0 bytes on socket %d, read_udp failed",
                arrival->ea_socket);
        FREE(arrival->ea_response);
        arrival->ea_response = NULL;
        arrival->ea_response_length = 0;
        return SR_IO_SOCKET_ERROR;
    }

    arr_family = arrival->ea_ns->ns_address[arrival->ea_which_address]->ss_family;
    if ((ret_val < 0) || (from.ss_family != arr_family))
        goto error;
    
    if (AF_INET == from.ss_family) {
        struct sockaddr_in *arr_in = (struct sockaddr_in *)
            arrival->ea_ns->ns_address[arrival->ea_which_address];
        struct sockaddr_in *from_in = (struct sockaddr_in *) &from;
        if ((from_in->sin_port != arr_in->sin_port) ||
            memcmp(&from_in->sin_addr, &arr_in->sin_addr,
                   sizeof(struct in_addr)))
            goto error;
        /* XXX Wait for actual response */ 
    }
#ifdef VAL_IPV6
    else if (AF_INET6 == from.ss_family) {
        struct sockaddr_in6 *arr_in = (struct sockaddr_in6 *)
            arrival->ea_ns->ns_address[arrival->ea_which_address];
        struct sockaddr_in6 *from_in = (struct sockaddr_in6 *) &from;
        if ((from_in->sin6_port != arr_in->sin6_port) ||
            (memcmp(&from_in->sin6_addr, &arr_in->sin6_addr,
                   sizeof(struct in6_addr))))
            goto error;
        /* XXX Wait for actual response */ 
    }
#endif
    else
        goto error; /* unknown family */

    /* ret_val is greater than zero here */
    arrival->ea_response_length = ret_val;
    return SR_IO_UNSET;

  error:
    val_log(NULL, LOG_ERR, "libsres: ""Closing socket %d, read_udp failed",
            arrival->ea_socket);
    FREE(arrival->ea_response);
    arrival->ea_response = NULL;
    arrival->ea_response_length = 0;
    /*
     * Cancel this source 
     */
    res_io_cancel_source(arrival);
    return SR_IO_SOCKET_ERROR;
}


void
res_switch_to_tcp(struct expected_arrival *ea)
{
    val_log(NULL, LOG_INFO, "libsres: ""Switching to TCP");

    if (NULL == ea)
        return;

    FREE(ea->ea_response);
    ea->ea_response = NULL;
    ea->ea_response_length = 0;

    /*
     * Use the same "ea_which_address," since it already got a rise. 
     */
    ea->ea_using_stream = TRUE;
    if (ea->ea_socket != INVALID_SOCKET) {
        CLOSESOCK(ea->ea_socket);
        ea->ea_socket = INVALID_SOCKET;
    }
    ea->ea_remaining_attempts = ea->ea_ns->ns_retry+1;
    set_alarm(&ea->ea_next_try, 0);

    set_alarm(&ea->ea_cancel_time, res_get_timeout(ea->ea_ns));
}

int
res_io_read(fd_set * read_descriptors, struct expected_arrival *ea_list)
{
    int             handled = 0;
    struct expected_arrival *arrival;

    for (; ea_list; ea_list = ea_list->ea_next) {
        /*
         * skip canceled/expired attempts, or sockets without data
         */
        if ((ea_list->ea_remaining_attempts == -1) ||
            (ea_list->ea_socket == INVALID_SOCKET) ||
            ! FD_ISSET(ea_list->ea_socket, read_descriptors))
            continue;

        { /* dummy block to preserve indentation; remove later */

            val_log(NULL, LOG_DEBUG, "libsres: ""ACTIVITY on %d",
                    ea_list->ea_socket);
            ++handled;
            arrival = ea_list;
            res_print_ea(arrival);

            if (arrival->ea_using_stream) {
                /** Use TCP */
                if (res_io_read_tcp(arrival) == SR_IO_SOCKET_ERROR)
                    continue;
            } else {
                /** Use UDP */
                if (res_io_read_udp(arrival) == SR_IO_SOCKET_ERROR)
                    continue;
            }
            val_log(NULL, LOG_DEBUG, "libsres: ""Read %zd byptes via %s",
                    arrival->ea_response_length,
                       arrival->ea_using_stream ? "TCP" : "UDP");

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
                val_log(NULL, LOG_ERR, "libsres: ""dropping response: "
                        "query and response ID's or q_fields don't match");
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
    }
    return handled;
}

int
res_io_accept(int transaction_id, fd_set *pending_desc, 
              struct timeval *closest_event, 
              u_char ** answer,
              size_t * answer_length, 
              struct name_server **respondent)
{
    int             ret_val;
    struct timeval  next_event;
    struct timeval zero_time;
    fd_set read_descriptors;
    zero_time.tv_sec = 0;
    zero_time.tv_usec = 0;

    FD_ZERO(&read_descriptors);

    val_log(NULL, LOG_DEBUG, "libsres: ""Calling io_accept");

    /*
     * See what needs to be sent.  A return code of 0 means that there
     * is nothing more to be sent and there is also nothing to wait for.
     * 
     * All is not hopeless though - more sources may still waiting to be
     * added via res_io_deliver().
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

    /*
     * Decision time: does this call only look at the sockets used by
     * its transaction id, or does it look at all?
     * 
     * Answer for now -> just the sockets we are interested in.
     */
    res_io_collect_sockets(&read_descriptors, 
                           transactions[transaction_id]);
    pthread_mutex_unlock(&mutex);

    ret_val = res_io_select_sockets(&read_descriptors, &zero_time);

    if (ret_val == SOCKET_ERROR)
        /** select call failed */
        return SR_IO_SOCKET_ERROR;

    pthread_mutex_lock(&mutex);

    /** make sure transaction didn't get cancelled */
    if (transactions[transaction_id] == NULL) {
        pthread_mutex_unlock(&mutex);
        return SR_IO_NO_ANSWER;
    }

    if (ret_val == 0) { 
        /** There are sources, but none are talking (yet) */

        /* save descriptors that we are waiting on */
        res_io_collect_sockets(pending_desc, 
                               transactions[transaction_id]);

        /* check if next_event is closer than closest_event */
        if (closest_event->tv_sec == 0 ||
            LTEQ(next_event, (*closest_event))) {
            closest_event->tv_sec = next_event.tv_sec;
        }
        pthread_mutex_unlock(&mutex);
        return SR_IO_NO_ANSWER_YET;
    }

    /*
     * React to the active desciptors.
     */
    res_io_read(&read_descriptors, transactions[transaction_id]);

    /*
     * Pluck the answer and return it to the caller.
     */
    ret_val = res_io_get_a_response(transactions[transaction_id],
                                    answer, answer_length, respondent);
    pthread_mutex_unlock(&mutex);

    if (ret_val == SR_IO_UNSET)
        return SR_IO_NO_ANSWER_YET;
    else
        return SR_IO_GOT_ANSWER;
}

void
res_cancel(int *transaction_id)
{
    struct expected_arrival *ea;

    if (*transaction_id == -1)
        return;

    pthread_mutex_lock(&mutex);
    ea = transactions[*transaction_id];
    transactions[*transaction_id] = NULL;
    pthread_mutex_unlock(&mutex);

    res_free_ea_list(ea);

    *transaction_id = -1;
}

void
res_io_cancel_all(void)
{
    int             i, j;
    for (i = 0; i < MAX_TRANSACTIONS; i++) {
        j = i;
        res_cancel(&j);
    }
}

void
res_print_ea(struct expected_arrival *ea)
{
    int             i = ea->ea_which_address, port = 0;
    char            buf[INET6_ADDRSTRLEN + 1];
    const char     *addr = NULL;
    size_t	    buflen = sizeof(buf);

        struct sockaddr_in *s =
            (struct sockaddr_in *) ((ea->ea_ns->ns_address[i]));
#ifdef VAL_IPV6
        struct sockaddr_in6 *s6 =
            (struct sockaddr_in6 *) ((ea->ea_ns->ns_address[i]));
        if (AF_INET6 == ea->ea_ns->ns_address[i]->ss_family) {
	        INET_NTOP(AF_INET6, (struct sockaddr *)s6, sizeof(s6), buf, buflen, addr);
            port = s6->sin6_port;
        }
#endif


        if (AF_INET == ea->ea_ns->ns_address[i]->ss_family) {
	        INET_NTOP(AF_INET, (struct sockaddr *)s, sizeof(s), buf, buflen, addr);
            port = s->sin_port;
        }

        val_log(NULL, LOG_DEBUG, "libsres: "
                "  Socket: %d, Stream: %d, Nameserver: %s/(%d)",
                ea->ea_socket, ea->ea_using_stream, addr ? addr : "",
                ntohs(port));
        val_log(NULL, LOG_DEBUG, "libsres: "
                "  Remaining retries: %d, Next try %ld, Cancel at %ld",
                ea->ea_remaining_attempts, ea->ea_next_try.tv_sec,
                ea->ea_cancel_time.tv_sec);
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
    val_log(NULL, LOG_DEBUG, "libsres: ""Current time is %ld", tv.tv_sec);

    pthread_mutex_lock(&mutex);
    for (i = 0; i < MAX_TRANSACTIONS; i++)
        if (transactions[i]) {
            val_log(NULL, LOG_DEBUG, "libsres: ""Transaction id: %3d", i);
            for (ea = transactions[i], j = 0; ea; ea = ea->ea_next, j++) {
                val_log(NULL, LOG_DEBUG, "libsres: ""Source #%d", j);
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

int
res_io_count_ready(fd_set *read_desc)
{
    int i, count, max = getdtablesize(); 
    if (max > FD_SETSIZE)
        max = FD_SETSIZE;
    for (count=i=0; i < max; ++i)
        if (FD_ISSET(i, read_desc)) {
            val_log(NULL,LOG_DEBUG, "libsres: "" fd %d ready", i);
            ++count;
        }
    return count;
}

struct expected_arrival *
res_async_query_send(const char *name, const u_int16_t type_h,
                     const u_int16_t class_h, struct name_server *pref_ns)
{
    int                 ret_val = SR_UNSET;
    u_char             *signed_query = NULL;
    size_t              signed_length = 0;
    struct name_server *ns_list = NULL;
    struct name_server *ns;
    struct expected_arrival *head = NULL, *new_ea, *temp_ea;
    long                delay = 0;

    if ((name == NULL) || (pref_ns == NULL))
        return NULL;

    /*
     * clone nameservers and store to ns_list
     */
    if ((ret_val = clone_ns_list(&ns_list, pref_ns)) != SR_UNSET)
        return NULL;

    /*
     * Loop through the list of destinations, form the query and send it
     */
    for (ns = ns_list; ns; ns = ns->ns_next) {

        /** create payload */
        ret_val = res_create_query_payload(ns, name, class_h, type_h,
                                           &signed_query, &signed_length);
        if (ret_val < 0)
            break; /* fatal, bail */

        /** create expected arrival struct */
        new_ea = res_ea_init(signed_query, signed_length, ns, delay);
        if (NULL == new_ea) {
            FREE(signed_query);
            ret_val = SR_IO_MEMORY_ERROR;
            break; /* fatal, bail */
        }

        /** add to list */
        if (NULL != head) {
            temp_ea = head;
            while(temp_ea->ea_next)
                temp_ea = temp_ea->ea_next;
            temp_ea->ea_next = new_ea;
        } else
            head = new_ea;

        delay += LIBSRES_NS_STAGGER;
    }

    /** if bad ret_val, clear list, else send query */
    if (ret_val != SR_UNSET) {
        res_free_ea_list(head);
        head = NULL;
    }
    else
        ret_val = res_io_check_one(head,NULL,NULL);

    return head;
}

void
res_async_query_select_info(struct expected_arrival *ea, int *nfds,
                            fd_set *fds, struct timeval *timeout)
{
    if (!ea || (!nfds && !fds && !timeout))
        return;

    res_io_select_info(ea, nfds, fds, timeout);
}

int
res_async_query_handle(struct expected_arrival *ea, int *handled, fd_set *fds)
{
    int ret_val = SR_NO_ANSWER;

    if (!ea || !handled || !fds)
        return SR_INTERNAL_ERROR;

    /*
     * React to any active desciptors and see if we got a response, or
     * if we at least still have an open socket (i.e. potential response).
     */
    *handled = res_io_read(fds, ea);
    for( ; ea; ea = ea->ea_next) {
        if (ea->ea_remaining_attempts == -1)
            continue;
        else if (ea->ea_response) {
            ret_val = SR_UNSET;
            break;
        }
        else if (ea->ea_socket != INVALID_SOCKET)
            ret_val = SR_NO_ANSWER_YET;
    }

    return ret_val;
}

void
res_async_query_free(struct expected_arrival *ea)
{
    res_free_ea_list(ea);
}

void
res_async_query_cancel(struct expected_arrival *ea)
{

}

int
res_async_ea_is_using_stream(struct expected_arrival *ea)
{
    if (NULL == ea)
        return 0;

    return ea->ea_using_stream;
}

int
res_async_ea_isset(struct expected_arrival *ea, fd_set *fds)
{
    if (NULL == ea || NULL == fds)
        return 0;

    return FD_ISSET(ea->ea_socket, fds);
}

int
res_async_ea_count_active(struct expected_arrival *ea)
{
    int count = 0;

    for ( ; ea; ea = ea->ea_next ) {
        if ((ea->ea_remaining_attempts == -1) || (ea->ea_socket == -1))
            continue;
        ++count;
    }

    return count;
}
