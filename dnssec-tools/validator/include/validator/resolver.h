
/*
 * Portions Copyright (c) 1995, 1996, 1997 by Trusted Information Systems, Inc.
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
/*
 * The timersub macro is from
 *      $NetBSD: time.h,v 1.64 2009/03/27 11:06:26 drochner Exp $ 
 * which specifies the following license:
 *
 * Copyright (c) 1982, 1986, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)time.h      8.5 (Berkeley) 5/4/95
 */

/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef RESOLVER_H
#define RESOLVER_H

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef __MINGW32__
#include <winsock2.h>
#endif

#ifdef __cplusplus
extern          "C" {
#endif

/* 
 * Application is responsible for pointing to the definitions of these types 
 * if it plans on using them 
 */
struct sockaddr_storage;
struct timeval;

#ifndef SOCKET
#define SOCKET int
#endif

#define LIBSRES_NS_STAGGER 5 /* how far apart should we stagger queries to
                                different authoritative name servers */


#define ZONE_USE_NOTHING        0x00000000
#define ZONE_USE_TSIG           0x00000001
#define SR_ZI_STATUS_UNSET      0
#define SR_ZI_STATUS_PERMANENT      1
#define SR_ZI_STATUS_LEARNED        2

/*
 * Resolver errors 
 */
#define SR_UNSET    0
#define SR_INTERNAL_ERROR         1
#define SR_CALL_ERROR             SR_INTERNAL_ERROR
#define SR_MEMORY_ERROR           SR_INTERNAL_ERROR
#define SR_MKQUERY_INTERNAL_ERROR SR_INTERNAL_ERROR
#define SR_TSIG_INTERNAL_ERROR    SR_INTERNAL_ERROR
#define SR_SEND_INTERNAL_ERROR    SR_INTERNAL_ERROR
#define SR_RCV_INTERNAL_ERROR     SR_INTERNAL_ERROR

#define SR_TSIG_ERROR             2
#define SR_NO_ANSWER              3     /* No answer received */
#define SR_NO_ANSWER_YET          4     /* No answer as yet, but this value will change */
#define SR_HEADER_ERROR           5     /* some inconsistency in the DNS response header */
#define SR_DNS_GENERIC_ERROR      6     /*Look at RCODE */
#define SR_EDNS_VERSION_ERROR     7
#define SR_UNSUPP_EDNS0_LABEL     8
#define SR_NAME_EXPANSION_FAILURE 9 
#define SR_NXDOMAIN               10    /*RCODE set to NXDOMAIN w/o appropriate records */
#define SR_FORMERR                11    /*RCODE set to FORMERR */
#define SR_SERVFAIL               12    /*RCODE set to SERVFAIL */
#define SR_NOTIMPL                13    /*RCODE set to NOTIMPL */
#define SR_REFUSED                14    /*RCODE set to REFUSED */

#ifndef NS_MAXCDNAME
#define NS_MAXCDNAME    255     /* maximum compressed domain name */
#endif

#define TSIG_ALG_HMAC_MD5_STR "hmac-md5.sig-alg.reg.int"
#define TSIG_ALG_HMAC_SHA1_STR "hmac-sha1"
#define TSIG_ALG_HMAC_SHA256_STR "hmac-sha256"
#define TSIG_FUDGE_DEFAULT  300

struct name_server {
    unsigned char  ns_name_n[NS_MAXCDNAME];
    struct ns_tsig *ns_tsig;
    unsigned int   ns_security_options;
    unsigned int   ns_status;
    unsigned long  ns_options;
    int            ns_edns0_size;
    int             ns_retrans;
    int             ns_retry;

    struct name_server *ns_next;

    /*
     * NOTE: ns_address MUST be last element
     */
    int             ns_number_of_addresses;
    struct sockaddr_storage **ns_address;
    /*
     * DO NOT ADD MEMBERS BELOW ns_addresses
     */
};

/*
 * ns_options values
 */
#define SR_QUERY_DEBUG              0x00000001
#define SR_QUERY_RECURSE            0x00000002 
#define SR_QUERY_SET_DO             0x00000004 
#define SR_QUERY_SET_CD             0x00000008
#define SR_QUERY_VALIDATING_STUB_FLAGS  (SR_QUERY_SET_DO | SR_QUERY_SET_CD) 
#define SR_QUERY_DEFAULT                (SR_QUERY_RECURSE) 


struct expected_arrival {
    SOCKET          ea_socket;
#ifdef EA_EXTRA_DEBUG
    char           *name;
    u_int16_t       ea_type_h;
    u_int16_t       ea_class_h;
#endif
    struct name_server *ea_ns;
    int             ea_which_address;
    int             ea_using_stream;
    unsigned char   *ea_signed;
    size_t          ea_signed_length;
    unsigned char   *ea_response;
    size_t          ea_response_length;
    int             ea_remaining_attempts;
    struct timeval  ea_next_try;
    struct timeval  ea_cancel_time;
    struct expected_arrival *ea_next;
};

/*
 * Interfaces to the resolver 
 */
size_t          wire_name_length(const unsigned char *field);
int             query_send(const char *name,
                           const unsigned short type_h,
                           const unsigned short class_h,
                           struct name_server *nslist,
                           int *trans_id);
int             query_queue(const char *name, const unsigned short type_h,
                            const unsigned short class_h,
                            struct name_server *pref_ns, int *trans_id);
int             response_recv(int *trans_id,
                              fd_set *pending_desc,
                              struct timeval *closest_event,
                              struct name_server **respondent,
                              unsigned char ** answer, size_t * answer_length);
int             res_response_checks(u_char ** answer, size_t * answer_length,
                                    struct name_server **respondent);
void            res_cancel(int *transaction_id);
int             res_nsfallback(int transaction_id,
                               struct timeval *closest_event,
                               struct name_server *server,
                               const char *name, const unsigned short class_h,
                               const unsigned short type_h);

void            wait_for_res_data(fd_set * pending_desc,
                                  struct timeval *closest_event);
int             get(const char *name_n,
                    const unsigned short type_h,
                    const unsigned short class_h,
                    struct name_server *nslist,
                    struct name_server **server,
                    unsigned char ** response, size_t * response_length);
int             get_tcp(const char *name_n,
                        unsigned short type_h,
                        unsigned short class_h,
                        struct name_server *nslist,
                        struct name_server **server,
                    unsigned char ** response, size_t * response_length);
void            print_response(unsigned char * ans, size_t resplen);
int             res_gettimeofday_buf(char *buf, size_t bufsize);

struct sockaddr_storage **create_nsaddr_array(int num_addrs);
struct name_server *create_name_server(void);
struct name_server *parse_name_server(const char *cp,
                                      const char *name_n);
int             clone_ns(struct name_server **cloned_ns,
                         struct name_server *ns);
int             clone_ns_list(struct name_server **ns_list,
                              struct name_server *orig_ns_list);
void            free_name_server(struct name_server **ns);
void            free_name_servers(struct name_server **ns);

void            res_set_debug_level(int val);
int             res_get_debug_level(void);
void            res_io_view(void);

int             label_bytes_cmp(const u_char * field1, size_t length1,
                                const u_char * field2, size_t length2);
int             labelcmp(const u_char * name1, const u_char * name2, 
                        size_t label_cnt);
int             namecmp(const u_char * name1, const u_char * name2);

    int             res_map_srio_to_sr(int val);

unsigned short       res_nametoclass(const char *buf, int *successp);
unsigned short       res_nametotype(const char *buf, int *successp);

void res_io_view(void);
int res_io_check_one(struct expected_arrival *ea, struct timeval *next_evt,
                     struct timeval *now);

/*
 * asynchronous interface to the resolver
 */

int res_nsfallback_ea(struct expected_arrival *temp,
                      struct timeval *closest_event, struct name_server *server,
                      const char *name, const unsigned short class_h,
                      const unsigned short type_h);

struct expected_arrival *
res_async_query_create(const char *name, const unsigned short type_h,
                       const unsigned short class_h, struct name_server *pref_ns,
                       unsigned int flags);

struct expected_arrival *
res_async_query_send(const char *name, const unsigned short type_h,
                     const unsigned short class_h, struct name_server *pref_ns);

void
res_async_query_select_info(struct expected_arrival *ea, int *nfds,
                            fd_set *fds, struct timeval *timeout);
int
res_async_query_handle(struct expected_arrival *ea, int *handled, fd_set *fds);

void
res_async_query_free(struct expected_arrival *ea);

int
res_io_check_ea_list(struct expected_arrival *ea, struct timeval *next_evt,
                     struct timeval *now, int *net_change, int *active);

int
res_io_get_a_response(struct expected_arrival *ea_list, unsigned char **answer,
                      size_t *answer_length, struct name_server **respondent);

void
res_io_cancel_all_remaining_attempts(struct expected_arrival *ea);

int
res_io_is_finished(struct expected_arrival *ea);

int
res_io_are_all_finished(struct expected_arrival *ea);

/*
 * count the number of descriptors set in the given fdset.
 *
 * the max_fd argument is optional and specifies the highest number fd that
 * may be set (i.e. like the nfds param to select()). If it is less than or
 * equal to zero, every fd is checked.
 */
int
res_io_count_ready(fd_set *read_desc, int max_fd);

int
res_async_ea_is_using_stream(struct expected_arrival *ea);

int
res_async_ea_isset(struct expected_arrival *ea, fd_set *fds);

void res_switch_all_to_tcp_tid(int trans_id);

/*
 * TSIG interface
 */
int res_set_ns_tsig(struct name_server *ns, char *tsig);

/*
 * define timersub macro if not defined. Set top of this header file
 * for the license for this hunk of code.
 */
#ifndef timersub
#define timersub(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (/* CONSTCOND */ 0)
#endif
#ifndef timerclear
#define timerclear(tvp)         (tvp)->tv_sec = (tvp)->tv_usec = 0L
#endif
#ifndef timerisset
#define timerisset(tvp)         ((tvp)->tv_sec || (tvp)->tv_usec)
#endif
#ifndef timercmp
#define timercmp(tvp, uvp, cmp)                                         \
    (((tvp)->tv_sec == (uvp)->tv_sec) ?                                 \
     ((tvp)->tv_usec cmp (uvp)->tv_usec) :                              \
     ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif
#ifndef timeradd
#define timeradd(tvp, uvp, vvp)                                         \
    do {                                                                \
        (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;                  \
        (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;               \
        if ((vvp)->tv_usec >= 1000000) {                                \
            (vvp)->tv_sec++;                                            \
            (vvp)->tv_usec -= 1000000;                                  \
        }                                                               \
    } while (/* CONSTCOND */ 0)
#endif

#ifdef __cplusplus
}                               /* extern C */
#endif
#endif                          /* RESOLVER_H */
