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
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
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

void print_response (u_int8_t *ans, int resplen);
void print_hex_field (u_int8_t field[], int length, int width, char *pref);
void print_hex (u_int8_t field[], int length);
int complete_read (int sock, void* field, int length);
void my_free (void *p, char *filename, int lineno);
void *my_malloc (size_t t, char *filename, int lineno);
char *my_strdup (const char *str, char *filename, int lineno);
void dump_response (const u_int8_t *ans, int resplen);
int wire_to_ascii_name (char *name, u_int8_t *wire, int name_length);
u_int16_t retrieve_type (const u_int8_t *rr);

#endif /* RES_SUPPORT_H */
