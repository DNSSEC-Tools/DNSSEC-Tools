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
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef RES_SUPPORT_H
#define RES_SUPPORT_H

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif

#define RES_GET16(s, cp) do { \
        register const u_char *t_cp = (const u_char *)(cp); \
        (s) = ((u_int16_t)t_cp[0] << 8) \
            | ((u_int16_t)t_cp[1]) \
            ; \
        (cp) += NS_INT16SZ; \
} while (0)

#define RES_GET32(l, cp) do { \
        register const u_char *t_cp = (const u_char *)(cp); \
        (l) = ((u_int32_t)t_cp[0] << 24) \
            | ((u_int32_t)t_cp[1] << 16) \
            | ((u_int32_t)t_cp[2] << 8) \
            | ((u_int32_t)t_cp[3]) \
            ; \
        (cp) += NS_INT32SZ; \
} while (0)

#define RES_PUT16(s, cp) do { \
	register u_int16_t t_s = (u_int16_t)(s); \
	register u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += NS_INT16SZ; \
} while (0)

#define RES_PUT32(l, cp) do { \
	register u_int32_t t_l = (u_int32_t)(l); \
	register u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp   = t_l; \
	(cp) += NS_INT32SZ; \
} while (0)

#define RES_PUT48(ll, cp) do { \
	register u_int64_t t_ll = (u_int64_t)(ll); \
	register u_char *t_cp = (u_char *)(cp); \
    u_int16_t t_s = t_ll >> 32;\
    u_int32_t t_l = t_ll & 0xffffffff ;\
	*t_cp++ = t_s >> 8; \
	*t_cp++ = t_s; \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp = t_l; \
	(cp) += NS_INT32SZ; \
	(cp) += NS_INT16SZ; \
} while (0)


void            my_free(void *p, char *filename, int lineno);
void           *my_malloc(size_t t, char *filename, int lineno);
char           *my_strdup(const char *str, char *filename, int lineno);

void            print_response(u_char * ans, size_t resplen);
void            log_response(u_char * ans, size_t resplen);
void            print_hex_field(u_char field[], size_t length, size_t width,
                                char *pref);
void            print_hex(u_char field[], size_t length);
void            dump_response(const u_char * ans, size_t resplen);
u_int16_t       libsres_random(void);
int             libsres_msg_getflag(ns_msg han, int flag);

void            res_log(void *dont_care, int level, const char *template, ...);
void            res_log_ap(void *dont_care, int level, const char *template,
                           va_list ap);


#endif                          /* RES_SUPPORT_H */
