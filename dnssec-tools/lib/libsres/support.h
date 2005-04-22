
/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 */

#ifndef SUPPORT_H
#define SUPPORT_H

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
u_int16_t wire_name_length (const u_int8_t *field);
u_int16_t wire_name_labels (const u_int8_t *field);
void my_free (void *p, char *filename, int lineno);
void *my_malloc (size_t t, char *filename, int lineno);
char *my_strdup (const char *str, char *filename, int lineno);
void dump_response (const u_int8_t *ans, int resplen);
int wire_to_ascii_name (char *name, u_int8_t *wire, int name_length);
int skip_questions(const u_int8_t *buf);
u_int16_t retrieve_type (const u_int8_t *rr);
int res_sq_set_message(char **error_msg, char *msg, int error_code);
int namecmp (const u_int8_t *name1, const u_int8_t *name2);

#endif /* SUPPORT_H */
