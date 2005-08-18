
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
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <arpa/nameser.h>
#include <resolv.h>

#include "resolver.h"

extern void res_pquery(const res_state statp, const u_char *msg, int len, FILE *file);


static int seq_number = 0;
FILE        *logfile = NULL;
#define MEM_LOGFILE "memory_logfile"        
                                                                                                                  
void my_free (void *p, char *filename, int lineno)
{
    if (logfile==NULL)
        logfile = fopen (MEM_LOGFILE, "w");
                                                                                                                          
    fprintf (logfile, "0x%08lx %5d bFREE %-20s %5d\n", (u_long) p, seq_number++,
                                filename, lineno);
    fflush (logfile);
    free (p);
}
                                                                                                                          
void *my_malloc (size_t t, char *filename, int lineno)
{
    void *p = malloc (t);
                                                                                                                          
    if (logfile==NULL)
        logfile = fopen (MEM_LOGFILE, "w");
                                                                                                                          
    fprintf (logfile, "0x%08lx %5d aMALL %-20s %5d size=%6d\n", (u_long) p, seq_number++,
                                filename, lineno, (u_int)t);
    fflush (logfile);
                                                                                                                          
    return p;
}
                                                                                                                          
char *my_strdup (const char *str, char *filename, int lineno)
{
    char *p = strdup (str);
    if (logfile==NULL)
        logfile = fopen (MEM_LOGFILE, "w");
                                                                                                                          
    fprintf (logfile, "0x%08lx %5d aSTRD %-20s %5d\n", (u_long) p, seq_number++,
                                filename, lineno);
    fflush (logfile);
                                                                                                                          
    return p;
}

void print_response (u_int8_t *ans, int resplen)
{
    /* fp_nquery is a resolver debug routine (I think), the rest
        would dump the response in byte form, formatted to match
        the query's structure */
    //fp_nquery(ans, resplen, stdout);
    if ((_res.options & RES_INIT) == 0U && res_init() == -1)
        return;
    res_pquery(&_res, ans, resplen, stdout);
}

void print_hex_field (u_int8_t field[], int length, int width, char *pref)
{
    /* Prints an arbitrary bit field, from one address for some number of
        bytes.  Output is formatted via the width, and includes the raw
        hex value and (if printable) the printed value underneath.  "pref"
        is a string used to start each line, e.g., "   " to indent.
                                                                                                                          
        This is very useful in gdb to see what's in a memory field.
    */
    int     i, start, stop;
                                                                                                                          
    start=0;
    do
    {
        stop=(start+width)<length?(start+width):length;
        printf (pref);
        for (i = start; i < stop; i++)
            printf ("%02x ", (u_char) field[i]);
        printf ("\n");
                                                                                                                          
        printf (pref);
        for (i = start; i < stop; i++)
            if (isprint(field[i]))
                printf (" %c ", (u_char) field[i]);
            else
                printf ("   ");
            printf ("\n");
                                                                                                                          
        start = stop;
    } while (start < length);
}

void print_hex (u_int8_t field[], int length)
{
    /* Prints the hex values of a field...not as pretty as the print_hex_field.
    */
    int     i, start, stop;
                                                                                                                          
    start=0;
    do
    {
        stop=length;
        for (i = start; i < stop; i++)
            printf ("%02x ", (u_char) field[i]);
        start = stop;
        if (start < length) printf ("\n");
    } while (start < length);
}

int complete_read (int sock, void* field, int length)
{
    int bytes;
    int bytes_read = 0;
    memset (field, '\0', length);
                                                                                                                          
    do
    {
        bytes = read (sock, field+bytes_read, length-bytes_read);
        if (bytes == -1) return -1;
        if (bytes == 0) return -1;
        bytes_read += bytes;
    } while (bytes_read < length);
    return length;
}


int wire_to_ascii_name (char *name, u_int8_t *wire, int name_length)
{
    int ret_val;
    memset (name, 0, name_length);
    ret_val = ns_name_ntop (wire, name, name_length-1);
    if (name[strlen(name)-1]!='.')
        strcat (name, ".");
    else
        ret_val--;
    return ret_val;
}


void free_name_server (struct name_server **ns)
{
    if (ns && *ns)
    {
        if ((*ns)->ns_name_n) FREE ((*ns)->ns_name_n);
        if ((*ns)->ns_tsig_key) FREE ((*ns)->ns_tsig_key);
        FREE (*ns);
        *ns=NULL;
    }
}
                                                                                                                          
void free_name_servers (struct name_server **ns)
{
    if (ns && *ns)
    {
        if ((*ns)->ns_next) free_name_servers (&((*ns)->ns_next));
        free_name_server (ns);
    }
}


