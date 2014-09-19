
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

#include "res_support.h"
#include "res_mkquery.h"
#include "res_io_manager.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/*
 * Less than or equal comparison for timeval structures
 * note: timercmp doesn't handle <= or >=
 * For reference:
 * # define timercmp(a, b, CMP)   \
 *            (((a)->tv_sec == (b)->tv_sec) ?  \
 *             ((a)->tv_usec CMP (b)->tv_usec) :         \
 *             ((a)->tv_sec CMP (b)->tv_sec))
 */
#define LTEQ(a,b)  (                                                    \
        ((a.tv_sec == b.tv_sec) ?                                       \
         ((a.tv_usec < b.tv_usec) || (a.tv_usec == b.tv_usec)) :        \
         (a.tv_sec < b.tv_sec)) )
#define UPDATE(a,b) do {                                                \
        if (!timerisset(a) || timercmp(a, &b, > ))                      \
            memcpy (a, &b, sizeof(struct timeval));                     \
    } while(0)


static long     _max_fd = 0;
static long     _open_sockets = 0;

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
#define NUM_RND_TRIES 10
static int
bind_to_random_source(int af, SOCKET s)
{   
    struct sockaddr_in sa4;
#ifdef VAL_IPV6
    struct sockaddr_in6 sa6;
#endif
    struct sockaddr *sa;
    size_t sock_size;

    u_int16_t next_port;
    int count = 0;

    if (af == AF_INET) {
        memset(&sa4, 0, sizeof(struct sockaddr_in));
        memset(&sa4.sin_addr, 0, sizeof(sa4.sin_addr));
        sa4.sin_family = AF_INET;
        sa4.sin_addr.s_addr = htonl(INADDR_ANY);
#ifdef VAL_IPV6
    } else if (af == AF_INET6) {
        memset(&sa6, 0, sizeof(struct sockaddr_in6));
        memset(&sa6.sin6_addr, 0, sizeof(sa6.sin6_addr));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_addr = in6addr_any;
#endif
    } else {
        res_log(NULL,LOG_ERR,"libsres: could not bind to random port for unsupported address family %d", af);
        return 1; /* failure */
    }


    do {
        next_port = (libsres_random() % 64512) + 1024;

        if (af == AF_INET) {
            sa4.sin_port = htons(next_port);
            sa = (struct sockaddr *) &sa4;
            sock_size = sizeof(struct sockaddr_in);
#ifdef VAL_IPV6
        } else {
            sa6.sin6_port = htons(next_port);
            sa = (struct sockaddr *) &sa6;
            sock_size = sizeof(struct sockaddr_in6);
#endif
        } 

        if (0 == bind(s, sa, sock_size)) {
            //res_log(NULL,LOG_ERR,"libsres: bound to random port %d", next_port);
            return 0; /* success */
        }
    } while (count++ < NUM_RND_TRIES);

    /* wrapped around and still no ports found */
    res_log(NULL,LOG_ERR,"libsres: could not bind to random port");

    return 1; /* failure */
}

/*
 * find the max number of file descriptors for this process
 */
static int _init_max_fd(void) {
    struct rlimit info;
    int rc;
    int lim;

#ifndef HAVE_GETRLIMIT
    /** hmm, cannot get current value. let's just guess. */
    info.rlim_cur = info.rlim_max = SR_IO_NOFILE_UNKNOWN_SIZE;
#else
    rc = getrlimit( RLIMIT_NOFILE, &info);
    if (rc) {
        /** hmm, cannot get current value. let's just guess. */
        info.rlim_cur = info.rlim_max = SR_IO_NOFILE_UNKNOWN_SIZE;
    }
#ifdef HAVE_SETRLIMIT
    else if (info.rlim_cur < info.rlim_max) {
        int prev = info.rlim_cur;
        info.rlim_cur = info.rlim_max;
        rc = setrlimit( RLIMIT_NOFILE, &info);
        if (rc) /* oh well, we tried. revert to previous limit */
            info.rlim_cur = prev;
    }
#endif /* HAVE_GETRLIMIT */
#endif /* HAVE_GETRLIMIT */
    lim = info.rlim_cur - SR_IO_NOFILE_RESERVED;
    if (lim <= 0)
        lim = 1;
    return lim;
}

long
res_io_get_max_fd(void) {
    return _max_fd;
}

long
res_io_get_open_sockets(void) {
    return _open_sockets;
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
    if ((ea == NULL) || (*ea == NULL))
        return;

    if ((*ea)->ea_socket != INVALID_SOCKET)
        res_log(NULL, LOG_DEBUG, "libsres: ""ea %p, fd %d free",
                *ea, (*ea)->ea_socket);
    else
        res_log(NULL, LOG_DEBUG+1, "libsres: ""ea %p, fd %d free",
                *ea, (*ea)->ea_socket);
    if ((*ea)->ea_ns != NULL)
        free_name_server(&((*ea)->ea_ns));
#ifdef EA_EXTRA_DEBUG
    if ((*ea)->name != NULL)
        free((*ea)->name);
#endif
    if ((*ea)->ea_socket != INVALID_SOCKET) {
        CLOSESOCK((*ea)->ea_socket);
        --_open_sockets;
    }
    if ((*ea)->ea_signed)
        FREE((*ea)->ea_signed);
    if ((*ea)->ea_response)
        FREE((*ea)->ea_response);

#ifdef DEBUG_DONT_RELEASE_ANYTHING
    {
        static struct expected_arrival *holding = NULL;

        (*ea)->ea_next = holding;
        holding = *ea;
    }
#else
    FREE(*ea);
#endif

    *ea = NULL;
}

void
res_free_ea_list(struct expected_arrival *head)
{
    struct expected_arrival *ea;

    res_log(NULL, LOG_DEBUG, "libsres: ""ea %p free list", head);
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
}

void
set_alarms(struct expected_arrival *ea, long next, long cancel)
{
    gettimeofday(&ea->ea_next_try, NULL);
    ea->ea_next_try.tv_sec += next;
    ea->ea_cancel_time.tv_sec = ea->ea_next_try.tv_sec + cancel;
    ea->ea_cancel_time.tv_usec = ea->ea_next_try.tv_usec;
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
    set_alarms(temp, delay, res_get_timeout(ns));
    temp->ea_next = NULL;

    return temp;
}

/*
 * give up on current response for this address.
 * set up next try to try address again.
 */
void
res_io_retry_source(struct expected_arrival *ea)
{
    res_log(NULL, LOG_DEBUG, "libsres: ""retry source ea %p", ea);
    res_print_ea(ea);

    /* close socket */
    if (ea->ea_socket != INVALID_SOCKET) {
        CLOSESOCK(ea->ea_socket);
        --_open_sockets;
        ea->ea_socket = INVALID_SOCKET;
    }

    /* bump retry time to current time */
    gettimeofday(&ea->ea_next_try, NULL);
}

/*
 * give up on current address for this nameserver.
 * set cancel time, which will trigger move to next address.
 */
void
res_io_reset_source(struct expected_arrival *ea)
{
    res_log(NULL, LOG_DEBUG, "libsres: ""reset source ea %p", ea);
    res_print_ea(ea);

    /* close socket */
    if (ea->ea_socket != INVALID_SOCKET) {
        CLOSESOCK(ea->ea_socket);
        --_open_sockets;
        ea->ea_socket = INVALID_SOCKET;
    }

    /* bump cancel time to current time */
    gettimeofday(&ea->ea_cancel_time, NULL);
}

/*
 * give up on all addresses for this nameserver
 * set remaining retries to -1; no more addresses will be tried
 */
void
res_io_cancel_source(struct expected_arrival *ea)
{
    res_log(NULL, LOG_DEBUG, "libsres: ""canceling source ea %p", ea);
    res_print_ea(ea);

    /* close socket */
    if (ea->ea_socket != INVALID_SOCKET) {
        CLOSESOCK(ea->ea_socket);
        --_open_sockets;
        ea->ea_socket = INVALID_SOCKET;
    }

    /* bump cancel time to current time */
    gettimeofday(&ea->ea_cancel_time, NULL);

    /* no more retries */
    ea->ea_remaining_attempts = -1;
}

void
res_io_cancel_all_remaining_attempts(struct expected_arrival *ea)
{
    for ( ; ea; ea = ea->ea_next)
        res_io_cancel_source(ea);
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
    struct timeval  timeout;

    if (shipit == NULL)
        return SR_IO_INTERNAL_ERROR;

    /** init _max_fd as needed */
    if (0 == _max_fd) {
        _max_fd =  _init_max_fd();
        res_log(NULL, LOG_INFO, "libsres: ""max fd  initialized to %d", _max_fd);
    }

    socket_type = (shipit->ea_using_stream == 1) ? SOCK_STREAM : SOCK_DGRAM;
    socket_proto = (socket_type == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
    res_log(NULL, LOG_DEBUG, "libsres: ""ea %p SENDING type %d %s over %s",
            shipit,
            shipit->ea_ns->ns_address[shipit->ea_which_address]->ss_family,
            shipit->ea_using_stream ? "stream" : "dgram",
            (socket_proto == IPPROTO_TCP) ? "tcp" : "udp");

    /* don't send too many packets at once. */
    if (shipit->ea_socket == INVALID_SOCKET && _open_sockets >= _max_fd) {
        res_log(NULL, LOG_DEBUG, "libsres: ""ea %p too many packets in flight",
                shipit);
        return SR_IO_TOO_MANY_TRANS;
    }

    /*
     * If no socket exists for the transfer, create and connect it (TCP
     * or UDP).  If for some reason this fails, return a INVALID_SOCKET 
     * which causes the source to be cancelled next go-round.
     */
    if (shipit->ea_socket == INVALID_SOCKET) {
        int i = shipit->ea_which_address;
        int af =  shipit->ea_ns->ns_address[i]->ss_family;

        shipit->ea_socket = socket(af, socket_type, 0);
        if (shipit->ea_socket == INVALID_SOCKET) {
            res_log(NULL,LOG_ERR,"libsres: ""socket() failed, errno = %d %s",
                    errno, strerror(errno));
            return SR_IO_SOCKET_ERROR;
        }
        ++_open_sockets;

        /* Set the source port */
        if (0 != bind_to_random_source(af, shipit->ea_socket)) {
            /* error */
            res_io_retry_source(shipit);
            return SR_IO_SOCKET_ERROR;
        }

        /*
         * Set the timeout interval
         */
        timeout.tv_sec = shipit->ea_ns->ns_retrans;
        timeout.tv_usec = 0;

        if (setsockopt (shipit->ea_socket, SOL_SOCKET, SO_SNDTIMEO, 
                    (char *)&timeout, sizeof(timeout)) < 0) {
            /* error */
            res_io_retry_source(shipit);
            return SR_IO_SOCKET_ERROR;
        }

        /*
         * OS X wants the socket size to be sockaddr_in for INET,
         * while Linux is happy with sockaddr_storage. 
         */
        if (af == AF_INET) {
            socket_size = sizeof(struct sockaddr_in);
#ifdef VAL_IPV6
        } else if (af == AF_INET6) {
            socket_size = sizeof(struct sockaddr_in6);
#endif
        } else {
            socket_size = sizeof(struct sockaddr_storage); 
        }

        if (connect
            (shipit->ea_socket,
             (struct sockaddr *) shipit->ea_ns->ns_address[i],
             socket_size) == SOCKET_ERROR) {
            res_log(NULL, LOG_ERR,
                    "libsres: ""Closing socket %d, connect errno = %d",
                    shipit->ea_socket, errno);
            res_io_reset_source(shipit);
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
            res_io_reset_source(shipit);
            return SR_IO_SOCKET_ERROR;
        }


        if (bytes_sent != sizeof(length_n)) {
            res_io_reset_source(shipit);
            return SR_IO_SOCKET_ERROR;
        }
    }

    bytes_sent = send(shipit->ea_socket, (const char*)shipit->ea_signed,
                      shipit->ea_signed_length, 0);
    if (bytes_sent != shipit->ea_signed_length) {
        res_log(NULL, LOG_ERR, "libsres: "
                "Closing socket %d, sending %d bytes failed (rc %d)",
                shipit->ea_socket, shipit->ea_signed_length, bytes_sent);
        res_io_reset_source(shipit);
        return SR_IO_SOCKET_ERROR;
    }

    delay = shipit->ea_ns->ns_retrans
        << (shipit->ea_ns->ns_retry + 1 - shipit->ea_remaining_attempts--);
    res_log(NULL, LOG_DEBUG, "libsres: ""next try delay %d", delay);
    set_alarms(shipit, delay, res_get_timeout(shipit->ea_ns));
    res_print_ea(shipit);

    return SR_IO_UNSET;
}

/*
 * 1 : edns0 fallback succeeded, ready for retry.
 * 0 : edns0 fallback failed, no more retries for server
 * -1: unknown error
 *     NOTE: val_res_nsfallback will cancel an entire request if -1 returned
 */
int 
res_nsfallback(int transaction_id, struct timeval *closest_event, 
               struct name_server *server, const char *name,
               const u_int16_t class_h, const u_int16_t type_h)
{
    struct expected_arrival *temp;
    int ret_val = -1;

    if (transaction_id < 0)
        return -1;

    pthread_mutex_lock(&mutex);
    temp = transactions[transaction_id];
    if (temp != NULL)
        ret_val = res_nsfallback_ea(temp, closest_event, server, name, class_h,
                                    type_h);
    pthread_mutex_unlock(&mutex);
    return ret_val;
}

static void
_reset_timeouts(struct expected_arrival *temp)
{
    res_log(NULL, LOG_INFO, "libsres: ""reset timeout for %p", temp);

    set_alarms(temp, 0, res_get_timeout(temp->ea_ns));

    /* 
     *  if next event is in the future, make sure we
     *  offset it to the current time IF it's not already active.
     */
    if (temp->ea_next) {
        struct expected_arrival *t;
        long offset = temp->ea_next->ea_next_try.tv_sec - 
                            temp->ea_next_try.tv_sec;
        if (offset > 0) {
            for (t=temp->ea_next; t; t=t->ea_next) {
                if (INVALID_SOCKET != t->ea_socket)
                    continue;
                res_log(NULL, LOG_INFO, "libsres: ""timeout offset %ld for %p",
                        offset, t);
                t->ea_next_try.tv_sec -= offset;
                t->ea_cancel_time.tv_sec -= offset;
            } 
        }
    }
}

/*
 * 1 : edns0 fallback succeeded, ready for retry.
 * 0 : edns0 fallback failed, no more retries for server
 * -1: unknown error
 *     NOTE: val_res_nsfallback will cancel an entire request if -1 returned
 */
int 
res_nsfallback_ea(struct expected_arrival *ea, struct timeval *closest_event, 
                  struct name_server *server, const char *name,
                  const u_int16_t class_h, const u_int16_t type_h)
{
    const static int edns0_fallback[] = { 4096, 1492, 512, 0 };
    int fallback_max_index = 3; /* This must match the array above */

    long             i, old_size;
    struct expected_arrival *temp = ea;

    if (!temp || !temp->ea_ns || !name)
        return -1;

    /*
     * If we're given a server try to find an exact match
     */
    if (server) {
        for(;temp;temp=temp->ea_next) {
            //res_print_ea(temp);
            /** match name, then look for address */
            if (!temp->ea_ns || namecmp(server->ns_name_n, temp->ea_ns->ns_name_n) != 0)
                continue;
            if (memcmp(server->ns_address[0],
                       temp->ea_ns->ns_address[temp->ea_which_address],
                       sizeof(*server->ns_address[0])) == 0)
                break;
        }
        if (!temp) {
            res_log(NULL, LOG_DEBUG, "libsres: "
                    "no matching server found for fallback");
            return -1;
        }
    }

    res_log(NULL, LOG_DEBUG, "libsres: ""ea %p attempting ns fallback", temp);

    old_size = temp->ea_ns->ns_edns0_size;
    if ((temp->ea_ns->ns_options & SR_QUERY_VALIDATING_STUB_FLAGS) && 
        (temp->ea_ns->ns_edns0_size > 0)) {
        for (i = 0; i < fallback_max_index; i++) {
            if (temp->ea_ns->ns_edns0_size > edns0_fallback[i]) {
                /* try using a lower edns0 value */
                temp->ea_ns->ns_edns0_size = edns0_fallback[i];
                if (edns0_fallback[i] == 0) {
                    /* try without EDNS0 */
                    res_log(NULL, LOG_DEBUG, "libsres: "
                            "fallback disabling edns0");
                    temp->ea_ns->ns_options ^= SR_QUERY_VALIDATING_STUB_FLAGS;
                }
                if (temp->ea_remaining_attempts < 0) {
                    /* give a last shot attempt with a reduced EDNS */
                    temp->ea_remaining_attempts = 1;
                }
                else {
                    temp->ea_remaining_attempts++;
                }
                break;
            }
        }
    }

    /** didn't find a smaller size to try and were already on last attempt */
    if (temp->ea_remaining_attempts <= 0) {
        res_log(NULL, LOG_DEBUG, "libsres: "
                "fallback already exhausted edns retries");
        res_io_reset_source(temp);
        if (res_io_are_all_finished(ea))
            return -1;
        return 0;
    }

    /** reset timeouts for immediate retries */
    _reset_timeouts(temp);
    UPDATE(closest_event, temp->ea_next_try);

    if (0 == old_size) {
        res_log(NULL, LOG_DEBUG, "libsres: ""fallback already disabled edns");
        return 0;
    }

    if (temp->ea_signed)
        FREE(temp->ea_signed);
    temp->ea_signed = NULL;
    temp->ea_signed_length = 0;

    if (res_create_query_payload(temp->ea_ns,
                name, class_h, type_h,
                &temp->ea_signed,
                &temp->ea_signed_length) < 0) {
        res_log(NULL, LOG_DEBUG, "libsres: ""could not create query payload");
        return -1;
    }

    /** close socket so retry uses different port */
    if (temp->ea_socket != INVALID_SOCKET) {
        CLOSESOCK(temp->ea_socket);
        --_open_sockets;
    }
    temp->ea_socket = INVALID_SOCKET;

    res_log(NULL, LOG_INFO, "libsres: "
            "ns fallback for {%s %s(%d) %s(%d)}, edns0 size %d > %d",
            name, p_class(class_h), class_h, p_type(type_h), type_h,
            old_size, temp->ea_ns->ns_edns0_size);

    return 1;
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
            --_open_sockets;
            ea->ea_socket = INVALID_SOCKET;
        }
        ea->ea_which_address++;
        ea->ea_remaining_attempts = ea->ea_ns->ns_retry+1;
        set_alarms(ea, 0, res_get_timeout(ea->ea_ns));
        res_log(NULL, LOG_INFO,
                "libsres: ""%s - SWITCHING TO NEW ADDRESS", more_prefix);
    } else {
        struct expected_arrival *next_server = ea->ea_next;

        /*
         * tried all addresses, cancel this source 
         */
        res_io_cancel_source(ea);
        res_log(NULL, LOG_INFO, "libsres: ""%s", no_more_str);

        if (next_server && next_server->ea_remaining_attempts &&
            INVALID_SOCKET == next_server->ea_socket) {
            res_log(NULL, LOG_INFO, "libsres: ""jump-starting next server %p",
                    next_server);
            _reset_timeouts(next_server);
        }
    }
    res_print_ea(ea);
}
/*
 * net_change : optional pointer for returning the net change in the
 *              number of open/active sockets.
 *
 * active : optional pointer for returning number of active queries.
 *          this includes any query with remaining retries, regardless
 *          of whether or not it has a current open/active socket.
 */
int
res_io_check_ea_list(struct expected_arrival *ea, struct timeval *next_evt,
                     struct timeval *now, int *net_change, int *active)
{
    struct timeval  local_now;
    int             remaining = 0, no_sock = 0, no_att = 0, open = 0;
    
    /*
     * if caller didn't pass us current time, get it
     */
    if (NULL == now) {
        now = &local_now;
        gettimeofday(&local_now, NULL);
    }
    if (net_change)
        *net_change = 0;
    if (active)
        *active = 0;

    res_log(NULL, LOG_DEBUG, __FUNCTION__);
    if (next_evt)
        res_log(NULL, LOG_DEBUG, "libsres: ""  Initial next event %ld.%ld",
                next_evt->tv_sec, next_evt->tv_usec);

    for ( ; ea; ea = ea->ea_next ) {
        if (ea->ea_remaining_attempts == -1) {
            res_log(NULL, LOG_DEBUG, "libsres: "
                    " skipping %p (sock %d, rem %d)",
                    ea, ea->ea_socket, ea->ea_remaining_attempts);
            ++no_att;
            continue;
        }
        if (ea->ea_socket != INVALID_SOCKET )
            res_print_ea(ea);
        else
            ++no_sock;

        /*
         * check for timeouts. If there is another address, move to it
         */
        if ( LTEQ(ea->ea_cancel_time, (*now)) ||
             ((0 == ea->ea_remaining_attempts) && LTEQ(ea->ea_next_try, (*now)))) {
            if (net_change && ea->ea_socket != INVALID_SOCKET)
                --(*net_change);
            res_io_next_address(ea, "TIMEOUTS", "TIMEOUT - CANCELING");
        }

        /*
         * send next try. on error, if there is another address, move to it
         */
        else if (LTEQ(ea->ea_next_try, (*now))) {
            int needed_new_socket = (ea->ea_socket == INVALID_SOCKET);
            res_log(NULL, LOG_DEBUG, "libsres: "" retry");
            while (ea->ea_remaining_attempts != -1) {
                if (res_io_send(ea) == SR_IO_SOCKET_ERROR) {
                    res_io_next_address(ea, "ERROR",
                                        "CANCELING DUE TO SENDING ERROR");
                }
                else {
                    if (needed_new_socket) {
                        if (net_change && ea->ea_socket != INVALID_SOCKET)
                            ++(*net_change);
                    }
                    break; /* from while remaining attempts */
                }
            } /* while */
        }

        /*
         * update next event
         */
        if (ea->ea_remaining_attempts != -1) {
            ++remaining;
            if (next_evt) {
                UPDATE(next_evt, ea->ea_cancel_time);
                UPDATE(next_evt, ea->ea_next_try);
            }
            if (ea->ea_socket != INVALID_SOCKET)
                ++open;
        }
    }
    if (next_evt) {
        struct timeval  now,when;
        gettimeofday(&now, NULL);
        timersub(next_evt, &now, &when);
        if (when.tv_sec < 0) {
            when.tv_sec = when.tv_usec = 0;
        }
        res_log(NULL, LOG_DEBUG, "libsres: "
                "  Next event %ld.%ld (%ld.%ld) remaining %d (%d active)",
                next_evt->tv_sec, next_evt->tv_usec, when.tv_sec, when.tv_usec,
                remaining, open);
    } else
        res_log(NULL, LOG_DEBUG, "libsres: ""  remaining %d (%d active)",
                remaining, open);
    if (no_sock || no_att)
        res_log(NULL, LOG_DEBUG, "libsres: "
                "  skipped %d closed sockets, %d no attempts", no_sock, no_att);

    if (active)
        *active = remaining;
    if (remaining)
        return SR_IO_UNSET;
    else
        return SR_IO_NO_ANSWER;
}

int
res_io_check_one(struct expected_arrival *ea, struct timeval *next_evt,
                 struct timeval *now)
{
    res_log(NULL, LOG_INFO,
            "res_io_check_one deprecated, use res_io_check_ea_list instead");
    return res_io_check_ea_list(ea, next_evt, now, NULL, NULL);
}

/** static version that assume caller has mutex lock... */
static int
_check_one_tid(int tid, struct timeval *next_evt, struct timeval *now)
{
    int                      active = 0;
    struct expected_arrival *ea;

    /** assume caller has mutex lock */

    ea = transactions[tid];
    if (ea)
        res_io_check_ea_list(ea, next_evt, now, NULL, &active);

    return (active > 0); /* have active queries */
}

/*
 * this version does not clear next_evt. now parameter is optional but
 * suggested if calling this function in a loop.
 */
int
res_io_check_one_tid(int tid, struct timeval *next_evt, struct timeval *now)
{
    int ret_val;

    if ((NULL == next_evt) || (tid < 0) || (tid >= MAX_TRANSACTIONS))
        return 0; /* i.e. no transactions for this tid */

    pthread_mutex_lock(&mutex);

    ret_val = _check_one_tid(tid, next_evt, now);

    pthread_mutex_unlock(&mutex);

    res_log(NULL, LOG_DEBUG, "libsres: "" tid %d next event is at %ld.%ld",
            tid, next_evt->tv_sec, next_evt->tv_usec);

    return ret_val;
}

/*
 * for backwards compatability, this checks all transactions.
 * I'd like to have it call res_io_check_one_tid, but that'd
 * involve a mutex lock/unlock for each active transaction, which
 * seems wasteful...
 */
int
res_io_check(int transaction_id, struct timeval *next_evt)
{
    int             i, ret_val;
    struct timeval  tv;

    if ((NULL == next_evt) || (transaction_id < 0) ||
        (transaction_id >= MAX_TRANSACTIONS))
        return 0;

    gettimeofday(&tv, NULL);
    res_log(NULL, LOG_DEBUG, "libsres: ""Checking tids at %ld.%ld", tv.tv_sec,
            tv.tv_usec);

    /*
     * Start "next event" at 0.0 seconds 
     */
    memset(next_evt, 0, sizeof(struct timeval));
    ret_val = 0; /* no active queries */

    pthread_mutex_lock(&mutex);

    /** check all except specified transaction_id, ignore return */
    for (i = 0; i < MAX_TRANSACTIONS; i++)
        if ((i != transaction_id) && transactions[i])
            _check_one_tid(i, next_evt, &tv);

    /** check for remaining attempts for specified transaction */
    ret_val = _check_one_tid(transaction_id, next_evt, &tv);

    pthread_mutex_unlock(&mutex);

    res_log(NULL, LOG_DEBUG, "libsres: "" next global event is at %ld.%ld",
            next_evt->tv_sec, next_evt->tv_usec);

    return ret_val;
}

int
res_io_deliver(int *transaction_id, u_char * signed_query,
               size_t signed_length, struct name_server *ns, long delay)
{
    struct timeval  next_event;
    int             rc;

    rc = res_io_queue(transaction_id, signed_query, signed_length, ns, delay);
    res_log(NULL, LOG_DEBUG, "libsres: "" res_io_queue rc %d", rc);

    /*
     * Call the res_io_check routine 
     */
    return res_io_check(*transaction_id, &next_event);
}

int
res_io_queue_ea(int *transaction_id, struct expected_arrival *new_ea)
{
    int             try_index;
    struct expected_arrival *temp;

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

    return SR_IO_UNSET;
}

int
res_io_queue(int *transaction_id, u_char * signed_query,
             size_t signed_length, struct name_server *ns, long delay)
{
    struct expected_arrival *new_ea;
    int                      ret_val;

    new_ea = res_ea_init(signed_query, signed_length, ns, delay);
    if (new_ea == NULL)
        return SR_IO_MEMORY_ERROR;

    ret_val = res_io_queue_ea(transaction_id, new_ea);
    if (ret_val != SR_IO_UNSET) {
        res_free_ea_list(new_ea);
        return ret_val;
    }

    return SR_IO_UNSET;
}

void
res_io_set_timeout(struct timeval *timeout, struct timeval *next_event)
{
    gettimeofday(timeout, NULL);
 
    if (LTEQ((*timeout), (*next_event)))
        timersub(next_event, timeout, timeout);
    else
        memset(timeout, 0, sizeof(struct timeval));
}

void
res_io_select_info_tid(int tid, int *nfds,
                       fd_set * read_descriptors,struct timeval *next_evt)
{
    struct expected_arrival *ea;

    if ((tid < 0) || (tid >= MAX_TRANSACTIONS))
        return;

    pthread_mutex_lock(&mutex);

    ea = transactions[tid];
    if (ea)
        res_io_select_info(ea, nfds, read_descriptors, next_evt);

    pthread_mutex_unlock(&mutex);
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
    struct timeval now, orig;
    int            count = 0, skipped = 0;

    if (timeout) {
        res_log(NULL, LOG_DEBUG,
                "libsres: "" ea %p select/timeout info", ea_list);
        res_log(NULL, LOG_DEBUG+1, "libsres: ""    orig timeout %ld,%ld",
                timeout->tv_sec, timeout->tv_usec);
        memcpy(&orig, timeout, sizeof(orig));
        gettimeofday(&now, NULL);
    }
    else
        res_log(NULL, LOG_DEBUG, "libsres: "" ea %p select info",
                ea_list);
    /*
     * Find all sockets in use for a particular transaction chain of
     * expected arrivals
     */
    for ( ; ea_list; ea_list = ea_list->ea_next) {
        if ((ea_list->ea_remaining_attempts == -1) ||
            (ea_list->ea_socket == INVALID_SOCKET)) {
            if (ea_list->ea_remaining_attempts > 0) {
                if (timeout) {
                    UPDATE(timeout, ea_list->ea_cancel_time);
                    UPDATE(timeout, ea_list->ea_next_try);
                }
                ++skipped;
            }
            res_log(NULL,LOG_DEBUG+1, "libsres:""   fd %d, rem %d",
                    ea_list->ea_socket, ea_list->ea_remaining_attempts);
            continue;
        }

        if (read_descriptors &&
            FD_ISSET(ea_list->ea_socket, read_descriptors)) {
            ++skipped;
            res_log(NULL,LOG_DEBUG+1, "libsres:""   fd %d already set",
                    ea_list->ea_socket);
            continue;
        }
                
        ++count;
        res_log(NULL,LOG_DEBUG, "libsres:""   fd %d added, rem %d",
                ea_list->ea_socket, ea_list->ea_remaining_attempts);
        if (read_descriptors)
            FD_SET(ea_list->ea_socket, read_descriptors);
        if (nfds && (ea_list->ea_socket >= *nfds))
            *nfds = ea_list->ea_socket + 1;

        if (timeout) {
            UPDATE(timeout, ea_list->ea_cancel_time);
            UPDATE(timeout, ea_list->ea_next_try);
        }
    }
    if (timeout && (orig.tv_sec != timeout->tv_sec ||
                    orig.tv_usec != timeout->tv_usec)) {
        res_log(NULL, LOG_DEBUG,
                "libsres: ""    new timeout %ld.%ld, %d fds added, %d inactive",
                timeout->tv_sec, timeout->tv_usec, count, skipped);
    }
    else
        res_log(NULL, LOG_DEBUG,
                "libsres: ""    %d fds added, %d inactive", count, skipped);

}

static int
res_io_select_sockets(fd_set * read_descriptors, struct timeval *timeout)
{
    /*
     * Perform the select call 
     */
    int             i, max_sock, count, ready;
    struct timeval  in,out;

    res_log(NULL,LOG_DEBUG,"libsres: "" res_io_select_sockets");

    max_sock = -1;

#ifndef WIN32 
    i = getdtablesize(); 
    if (i > FD_SETSIZE)
        i = FD_SETSIZE;
    for (--i; i >= 0; --i)
        if (FD_ISSET(i, read_descriptors)) {
            max_sock = i;
            break;
        }
    if (max_sock < 0) {
        res_log(NULL,LOG_DEBUG,"libsres: "" no fds set");
        return 0; /* nothing to read */
    }

    if (max_sock > FD_SETSIZE)
        max_sock = FD_SETSIZE;
#endif

    count = res_io_count_ready(read_descriptors, max_sock + 1);
    gettimeofday(&in, NULL);
    res_log(NULL, LOG_DEBUG,
            "libsres: ""SELECT on %d fds, max %d, timeout %ld.%ld @ %ld.%ld",
            count, max_sock+1,timeout->tv_sec,timeout->tv_usec,
            in.tv_sec,in.tv_usec);
#ifdef HAVE_PSELECT
    struct timespec timeout_ts;
    timeout_ts.tv_sec = timeout->tv_sec;
    timeout_ts.tv_nsec = timeout->tv_usec * 1000;
    ready = pselect(max_sock + 1, read_descriptors, NULL, NULL, &timeout_ts, NULL);
#else
    ready = select(max_sock + 1, read_descriptors, NULL, NULL, timeout);
#endif
    gettimeofday(&out, NULL);
    res_log(NULL, LOG_DEBUG, "libsres: "" %d ready fds @ %ld.%ld",
            ready,out.tv_sec,out.tv_usec);
    if (ready > 0)
        res_io_count_ready(read_descriptors, max_sock + 1);

    return ready;
}

void
wait_for_res_data(fd_set * pending_desc, struct timeval *closest_event)
{
    struct timeval timeout;
    int            ready;

    res_log(NULL,LOG_DEBUG,"libsres: ""wait_for_res_data");
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
    res_log(NULL, LOG_DEBUG, "libsres: "" wait for closest event %ld,%ld",
            closest_event->tv_sec, closest_event->tv_usec);
    res_io_set_timeout(&timeout, closest_event);
    ready = res_io_select_sockets(pending_desc, &timeout); 
    res_log(NULL, LOG_DEBUG, "libsres: ""   %d ready", ready);
	
    // ignore return value from previous function, 
    // will catch this condition when we actually read data
}

static int
_clone_respondent(struct expected_arrival *ea,
                  struct name_server **respondent)
{
    int save_count = -1, retval;

    /*
     * don't clone all when we just need one. temporarily set
     * number of nameservers to 1 before cloning.
     */
    if (ea->ea_ns->ns_number_of_addresses > 1) {
        save_count = ea->ea_ns->ns_number_of_addresses;
        ea->ea_ns->ns_number_of_addresses = 1;
    }
    if (SR_UNSET != (retval = clone_ns(respondent, ea->ea_ns)))
        return retval;
    if (save_count > 0) /* restore original count */
        ea->ea_ns->ns_number_of_addresses = save_count;
    
    /** if response wasn't from first address, fixup respondent */
    if (ea->ea_which_address != 0) {
        memcpy(((*respondent)->ns_address[0]),
               ea->ea_ns->ns_address[ea->ea_which_address],
               sizeof(struct sockaddr_storage));
    }

    return SR_UNSET;
}

int
res_io_get_a_response(struct expected_arrival *ea_list, u_char ** answer,
                      size_t * answer_length,
                      struct name_server **respondent)
{
    int             retval = SR_IO_UNSET, retries = 0;

    struct expected_arrival *orig = ea_list;
    res_log(NULL,LOG_DEBUG,"libsres: "" checking for response for ea %p list",
            ea_list);
    for( ; ea_list; ea_list = ea_list->ea_next) {

        if (ea_list->ea_remaining_attempts != -1)
            ++retries;

        if (!ea_list->ea_response)
            continue;

        if (ea_list->ea_remaining_attempts == -1) {
            res_log(NULL, LOG_DEBUG, "libsres: "
                    " *** ANSWER with no remaining attempts");
            //continue;
        }

        /** basic format checks; NOTE: returns SR_*, *NOT* SR_IO_* */
        retval = res_response_checks(&ea_list->ea_response,
                                     &ea_list->ea_response_length, respondent);
        if (SR_UNSET != retval) { /* cleared response */
            res_log(NULL, LOG_DEBUG, "libsres: "
                    "*** dropped response for ea %p rc %d", ea_list, retval);
            /** close socket so retry uses different port */
            if (ea_list->ea_socket != INVALID_SOCKET) {
                CLOSESOCK (ea_list->ea_socket);
                --_open_sockets;
                ea_list->ea_socket = INVALID_SOCKET;
            }
            res_print_ea(ea_list);
            _clone_respondent(ea_list, respondent);
            set_alarms(ea_list, 0, res_get_timeout(ea_list->ea_ns));
            retval = SR_IO_NO_ANSWER;
            continue; /* in case another ea has a response */
        }

        { /** dummy block to preserve indentation; reformat later */
            if (ea_list != orig)
                res_log(NULL,LOG_DEBUG,"libsres: "" found response in ea %p",
                        ea_list);
            *answer = ea_list->ea_response;
            *answer_length = ea_list->ea_response_length;
            res_log(NULL, LOG_DEBUG,
                    "libsres: ""get_response got %zd bytes on socket %d",
                    *answer_length, ea_list->ea_socket);

            retval = _clone_respondent(ea_list, respondent);

            if (SR_UNSET != retval)
                return retval;

            ea_list->ea_response = NULL;
            ea_list->ea_response_length = 0;
            return SR_IO_GOT_ANSWER;
        }
    }

    if (0 == retries) {
        res_log(NULL, LOG_DEBUG, "libsres: ""*** no answer and no retries!");
        retval = SR_IO_NO_ANSWER;
    }

    return retval;
}

size_t
complete_read(SOCKET sock, u_char *field, size_t length)
{
    ssize_t             bytes;
    size_t             bytes_read = 0;
#if 0
#ifdef MSG_DONTWAIT
    int                flags = MSG_DONTWAIT;
#else
    int                flags =0;
#endif
#endif
    int                flags =0;/* XXX For now don't enable MSG_DONTWAIT */

    memset(field, '\0', length);

    do {
        bytes = recv(sock, field + bytes_read, length - bytes_read, flags);
        if (bytes < 0) {
            break;
        }
        bytes_read += bytes;
    } while (bytes_read < length && bytes > 0);

    if (0 == bytes)
        res_log(NULL, LOG_INFO, "libsres: ""socket shutdown.", socket);
    if (bytes_read != length) {
        res_log(NULL, LOG_INFO,
                "libsres: ""incomplete read on socket %d; read %d of %d\n",
                sock, bytes_read, length);
        if (bytes == SOCKET_ERROR) {
            res_log(NULL, LOG_INFO, "libsres: ""  errno %d %s.", errno,
                    strerror(errno));
            return -1;
        }
    }

    return bytes_read;
}

static int
res_io_read_tcp(struct expected_arrival *arrival)
{
    u_int16_t    len_n;
    size_t       len_h;

    /*
     * Read length 
     */
    if (complete_read(arrival->ea_socket, (u_char *)&len_n, sizeof(len_n))
        != sizeof(len_n)) {
        /*
         * reset this source
         */
        res_io_reset_source(arrival);
        return SR_IO_SOCKET_ERROR;
    }

    len_h = ntohs(len_n);

    /*
     * read() message 
     */
    arrival->ea_response = (u_char *) MALLOC(len_h * sizeof(u_char));
    if (arrival->ea_response == NULL) {
        /*
         * retry this source 
         */
        res_io_retry_source(arrival);
        return SR_IO_MEMORY_ERROR;
    }

    arrival->ea_response_length = len_h;

    if (complete_read(arrival->ea_socket, (u_char *)arrival->ea_response, len_h) !=
        len_h) {
        FREE(arrival->ea_response);
        arrival->ea_response = NULL;
        arrival->ea_response_length = 0;
        /*
         * reset this source 
         */
        res_io_reset_source(arrival);
        return SR_IO_SOCKET_ERROR;
    }
    return SR_IO_UNSET;
}

static int
res_io_read_udp(struct expected_arrival *arrival)
{
    size_t bytes_waiting = 8192;
    struct sockaddr_storage from;
    socklen_t       from_length = sizeof(from);
    int             ret_val, arr_family;
    int             flags = 0;

    if (NULL == arrival)
        return SR_IO_INTERNAL_ERROR;

    if (NULL != arrival->ea_response) {
        res_log(NULL, LOG_INFO,
                "libsres: ""**** already have response for ea 0x%x socket %d.",
                arrival, arrival->ea_socket);
        return SR_IO_UNSET;
    }

    arrival->ea_response = (u_char *) MALLOC(bytes_waiting * sizeof(u_char));
    if (NULL == arrival->ea_response)
        return SR_IO_MEMORY_ERROR;
    memset(arrival->ea_response, 0, bytes_waiting * sizeof(u_char));

    memset(&from, 0, sizeof(from));

#ifdef MSG_DONTWAIT
    flags = MSG_DONTWAIT;
#endif
    ret_val =
        recvfrom(arrival->ea_socket, (char *)arrival->ea_response, bytes_waiting,
                 flags, (struct sockaddr*)&from, &from_length);

    if (0 == ret_val) {
        res_log(NULL, LOG_INFO,
                "libsres: ""0 bytes on socket %d, socket shutdown.",
                arrival->ea_socket);
        goto error;
    }
    else if (-1 == ret_val && (EAGAIN == errno || EWOULDBLOCK == errno)) {
        res_log(NULL, LOG_INFO,
                "libsres: ""**** no data on socket %d.", arrival->ea_socket);
        goto allow_retry;
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
    /*
     * reset this source 
     */
    res_io_reset_source(arrival);

  allow_retry:
    FREE(arrival->ea_response);
    arrival->ea_response = NULL;
    arrival->ea_response_length = 0;
    return SR_IO_SOCKET_ERROR;
}


void
res_switch_to_tcp(struct expected_arrival *ea)
{
    res_log(NULL, LOG_INFO, "libsres: ""Switching to TCP");

    if (NULL == ea)
        return;

    if (ea->ea_response != NULL) {
        FREE(ea->ea_response);
    }
    ea->ea_response = NULL;
    ea->ea_response_length = 0;

    /*
     * Use the same "ea_which_address," since it already got a rise. 
     */
    ea->ea_using_stream = TRUE;
    if (ea->ea_socket != INVALID_SOCKET) {
        CLOSESOCK(ea->ea_socket);
        --_open_sockets;
        ea->ea_socket = INVALID_SOCKET;
    }
    ea->ea_remaining_attempts = ea->ea_ns->ns_retry+1;
    set_alarms(ea, 0, res_get_timeout(ea->ea_ns));
}

/*
 * switch all ea entries in the chain to tcp.
 *
 * unlike res_switch_to_tcp, which is used during processing, this
 * function is intended to be called BEFORE processing starts. Thus
 * the retry count and next/cancel timers are not touched.
 */
void
res_switch_all_to_tcp(struct expected_arrival *ea)
{
    res_log(NULL, LOG_INFO, "libsres: ""Switching all to TCP");

    for (; ea; ea = ea->ea_next) {

        if (ea->ea_response != NULL) {
            FREE(ea->ea_response);
        }
        ea->ea_response = NULL;
        ea->ea_response_length = 0;

        ea->ea_using_stream = TRUE;
        if (ea->ea_socket != INVALID_SOCKET) {
            CLOSESOCK(ea->ea_socket);
            --_open_sockets;
            ea->ea_socket = INVALID_SOCKET;
        }
    }
}

void
res_switch_all_to_tcp_tid(int tid)
{
    struct expected_arrival *ea;

    if ((tid < 0) || (tid >= MAX_TRANSACTIONS))
        return;

    ea = transactions[tid];
    if (ea)
        res_switch_all_to_tcp(ea);
}

int
res_io_read(fd_set * read_descriptors, struct expected_arrival *ea_list)
{
    int             handled = 0, rc;
    struct expected_arrival *arrival;

    res_log(NULL,LOG_DEBUG,"libsres: "" res_io_read ea %p", ea_list);

    for (; ea_list; ea_list = ea_list->ea_next) {
        /*
         * skip canceled/expired attempts, or sockets without data
         */
        if ((ea_list->ea_remaining_attempts == -1) ||
            (ea_list->ea_socket == INVALID_SOCKET) ||
            ! FD_ISSET(ea_list->ea_socket, read_descriptors))
            continue;

        { /* dummy block to preserve indentation; remove later */

            res_log(NULL, LOG_DEBUG, "libsres: ""ACTIVITY on %d",
                    ea_list->ea_socket);
            ++handled;
            FD_CLR(ea_list->ea_socket, read_descriptors);

            arrival = ea_list;
            res_print_ea(arrival);

            if (arrival->ea_using_stream) {
                /** Use TCP */
                rc = res_io_read_tcp(arrival);
            } else {
                /** Use UDP */
                rc = res_io_read_udp(arrival);
            }
            res_log(NULL, LOG_DEBUG, "libsres: ""Read %zd bytes via %s",
                    arrival->ea_response_length,
                       arrival->ea_using_stream ? "TCP" : "UDP");
            if (SR_IO_UNSET != rc)
                continue;

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
                res_log(NULL, LOG_WARNING, 
                        "libsres: ""dropping response with rcode=%x : " 
                        "query and response ID's or query names don't match",
                        ((HEADER *) arrival->ea_response)->rcode);
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
    res_log(NULL,LOG_DEBUG,"libsres: ""   handled %d", handled);
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

    timerclear(&zero_time);

    FD_ZERO(&read_descriptors);

    res_log(NULL, LOG_DEBUG, "libsres: ""Calling io_accept");

    /*
     * See what needs to be sent.  A return code of 0 means that there
     * is nothing more to be sent and there is also nothing to wait for.
     * 
     * All is not hopeless though - more sources may still waiting to be
     * added via res_io_deliver().
     */
    if (res_io_check(transaction_id, &next_event) == 0) {
        res_log(NULL, LOG_DEBUG, "libsres: "" tid %d: no active queries",
                transaction_id);
        return SR_IO_NO_ANSWER;
    }

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
        UPDATE(closest_event, next_event);

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
    else if (ret_val == SR_IO_NO_ANSWER)
        return SR_IO_NO_ANSWER;
    else
        return SR_IO_GOT_ANSWER;
}

void
res_cancel(int *transaction_id)
{
    struct expected_arrival *ea;

    if ((NULL == transaction_id) || (*transaction_id == -1))
        return;

    res_log(NULL, LOG_DEBUG, "libsres: ""tid %d cancel", *transaction_id);

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
res_print_server(struct name_server *ea_ns, int i)
{
    struct sockaddr_in *s =
        (struct sockaddr_in *) ((ea_ns->ns_address[i]));
    char            buf[INET6_ADDRSTRLEN + 1];
    const char     *addr = NULL;
    size_t	    buflen = sizeof(buf);
    if (AF_INET == ea_ns->ns_address[i]->ss_family)
        INET_NTOP(AF_INET, (struct sockaddr *)s, sizeof(s), buf, buflen,
                  addr);
    res_log(NULL, LOG_DEBUG, "libsres: ""   Nameserver: %s", 
            addr ? addr : "");
}

void
res_print_ea(struct expected_arrival *ea)
{
    int             i = ea->ea_which_address, port = 0;
    char            buf[INET6_ADDRSTRLEN + 1];
    const char     *addr = NULL;
    size_t	    buflen = sizeof(buf);
    struct timeval  now,when_next, when_cancel;

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

        gettimeofday(&now, NULL);
        timersub(&ea->ea_next_try, &now, &when_next);
        timersub(&ea->ea_cancel_time, &now, &when_cancel);

        if (ea->ea_remaining_attempts < 0) { 
            res_log(NULL, LOG_DEBUG, "libsres: ""  ea %p "
#ifdef EA_EXTRA_DEBUG
                    "%s "
#endif
                    "Socket: %d, Nameserver: %s:%d, no more retries", ea,
#ifdef EA_EXTRA_DEBUG
                    ea->name,
#endif
                    ea->ea_socket, addr ? addr : "", ntohs(port));
        } else {
            res_log(NULL, LOG_DEBUG, "libsres: " "  ea %p "
#ifdef EA_EXTRA_DEBUG
                    "{%s %s(%d) %s(%d)} "
#endif
                    "Socket: %d, Stream: %d, Nameserver: %s:%d", ea,
#ifdef EA_EXTRA_DEBUG
                    ea->name, p_class(ea->ea_class_h), ea->ea_class_h,
                    p_type(ea->ea_type_h), ea->ea_type_h,
#endif
                    ea->ea_socket, ea->ea_using_stream, addr ? addr : "",
                    ntohs(port));
            res_log(NULL, LOG_DEBUG, "libsres: "
                    "  Remaining retries: %d, "
                    "Next try %ld.%ld (%ld.%ld), Cancel at %ld.%ld (%ld.%ld)",
                    ea->ea_remaining_attempts, ea->ea_next_try.tv_sec,
                    ea->ea_next_try.tv_usec, when_next.tv_sec,
                    when_next.tv_usec, ea->ea_cancel_time.tv_sec,
                    ea->ea_cancel_time.tv_usec, when_cancel.tv_sec,
                    when_cancel.tv_usec);
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
    res_log(NULL, LOG_DEBUG, "libsres: ""Current time is %ld", tv.tv_sec);

    pthread_mutex_lock(&mutex);
    for (i = 0; i < MAX_TRANSACTIONS; i++)
        if (transactions[i]) {
            res_log(NULL, LOG_DEBUG, "libsres: ""Transaction id: %3d", i);
            for (ea = transactions[i], j = 0; ea; ea = ea->ea_next, j++) {
                res_log(NULL, LOG_DEBUG, "libsres: ""Source #%d", j);
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

#ifndef WIN32
int
res_io_count_ready(fd_set *read_desc, int num_fds)
{
    int i, count, max;

    if (NULL == read_desc) {
        res_log(NULL,LOG_DEBUG, "libsres: "" count: no fds set (NULL fd_set)");
        return 0;
    }

    if (num_fds > 0)
        max = num_fds;
    else
        max = getdtablesize(); 

    if (max > FD_SETSIZE)
        max = FD_SETSIZE;
    for (count=i=0; i < max; ++i)
        if (FD_ISSET(i, read_desc)) {
            res_log(NULL,LOG_DEBUG, "libsres: "" count: fd %d set", i);
            ++count;
        }
    if (0 == count)
        res_log(NULL,LOG_DEBUG, "libsres: "" count: no fds set");
    return count;
}
#else
int
res_io_count_ready(fd_set *read_desc, int num_fds)
{
    return 0;
}
#endif /* ! WIN32 */

struct expected_arrival *
res_async_query_send(const char *name, const u_int16_t type_h,
                     const u_int16_t class_h, struct name_server *pref_ns)
{
    int                      ret_val;
    struct expected_arrival *head = 
        res_async_query_create(name, type_h, class_h, pref_ns, 0);

    if (NULL != head) {
        ret_val = res_io_check_ea_list(head,NULL,NULL,NULL,NULL);
        res_log(NULL,LOG_DEBUG, "libsres: "" res_io_check_ea_list returned %d",
                ret_val);
    } else
        res_log(NULL,LOG_DEBUG, "libsres: "" *** res_async_query_create returned NULL");

    return head;
}

struct expected_arrival *
res_async_query_create(const char *name, const u_int16_t type_h,
                       const u_int16_t class_h, struct name_server *pref_ns,
                       u_int flags)
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

        signed_query = NULL;
        signed_length = 0;

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
#ifdef EA_EXTRA_DEBUG
        new_ea->name = strdup(name);
        new_ea->ea_type_h = type_h;
        new_ea->ea_class_h = class_h;
#endif

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

    for (; ea; ea = ea->ea_next) {
        if (ea->ea_socket != INVALID_SOCKET &&
                FD_ISSET(ea->ea_socket, fds))
            return 1;
    }

    return 0;
}

int
res_async_tid_isset(int tid, fd_set *fds)
{
    int retval = 0;

    if (tid < 0 || tid >= MAX_TRANSACTIONS || NULL == fds)
        return 0;

    pthread_mutex_lock(&mutex);

    if (transactions[tid])
        retval = res_async_ea_isset(transactions[tid],fds);

    pthread_mutex_unlock(&mutex);

    return retval;
}

int
res_async_ea_count_active(struct expected_arrival *ea)
{
    int count = 0;

    for ( ; ea; ea = ea->ea_next ) {
        if ((ea->ea_remaining_attempts == -1) || (ea->ea_socket == INVALID_SOCKET))
            continue;
        ++count;
    }

    return count;
}
