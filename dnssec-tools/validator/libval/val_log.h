/*
 * Copyright 2006 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_LOG_H
#define VAL_LOG_H

char *get_hex_string(const unsigned char *data, int datalen, char *buf, int buflen);
void val_log_rrset(val_context_t *ctx, int level, struct rrset_rec *rrset);
void val_log_base64(val_context_t *ctx, int level, unsigned char * message, int message_len);
void val_log_rrsig_rdata (val_context_t *ctx, int level, const char *prefix, val_rrsig_rdata_t *rdata);
void val_log_dnskey_rdata (val_context_t *ctx, int level, const char *prefix, val_dnskey_rdata_t *rdata);
void val_log_assertion_chain(val_context_t *ctx, int level, u_char *name_n, u_int16_t class_h, u_int16_t type_h,
                struct val_query_chain *queries, struct val_result_chain *results);
void val_log (const val_context_t *ctx, int level, const char *template, ...);
char *p_query_error(int errno);
char *p_as_error(int valerrno);
char *p_val_error(int err);

#endif
