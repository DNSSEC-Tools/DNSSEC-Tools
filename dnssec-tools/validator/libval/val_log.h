/*
 * Copyright 2006 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_LOG_H
#define VAL_LOG_H

#include <stdarg.h>

struct val_log;

typedef void    (*val_log_logger_t) (struct val_log * logp,
                                     const val_context_t * ctx, int level,
                                     const char *template, va_list ap);

typedef struct val_log {

    val_log_logger_t logf;      /* log function ptr */

    unsigned char   level;      /* 0 - 9, corresponds w/sylog severities */
    unsigned char   lflags;     /* generic log flags */

    const char     *str;        /* logger dependent */
    union {
        struct {
            int             sock;
            struct sockaddr_in server;
        } udp;

        struct {
            char           *name;
            FILE           *fp;
        } file;

        struct {
            int             facility;
        } syslog;

        struct {
            void           *my_ptr;
        } user;

    } opt;

    struct val_log *next;

} val_log_t;


char           *get_hex_string(const unsigned char *data, int datalen,
                               char *buf, int buflen);
void            val_log_rrset(const val_context_t * ctx, int level,
                              struct rrset_rec *rrset);
void            val_log_base64(val_context_t * ctx, int level,
                               unsigned char *message, int message_len);
void            val_log_rrsig_rdata(const val_context_t * ctx, int level,
                                    const char *prefix,
                                    val_rrsig_rdata_t * rdata);
void            val_log_dnskey_rdata(val_context_t * ctx, int level,
                                     const char *prefix,
                                     val_dnskey_rdata_t * rdata);
void            val_log_authentication_chain(const val_context_t * ctx,
                                             int level, u_char * name_n,
                                             u_int16_t class_h,
                                             u_int16_t type_h,
                                             struct val_query_chain
                                             *queries, struct val_result_chain
                                             *results);
void            val_log(const val_context_t * ctx, int level,
                        const char *template, ...);

val_log_t      *val_log_add_filep(int level, FILE * p);
val_log_t      *val_log_add_file(int level, const char *filen);
val_log_t      *val_log_add_syslog(int level, int facility);
val_log_t      *val_log_add_network(int level, char *host, int port);
val_log_t      *val_log_add_optarg(char *args, int use_stderr);

int             val_log_debug_level(void);
void            val_log_set_debug_level(int);

const char     *p_query_status(int err);
const char     *p_ac_status(val_astatus_t valerrno);
const char     *p_val_status(val_status_t err);

#endif
