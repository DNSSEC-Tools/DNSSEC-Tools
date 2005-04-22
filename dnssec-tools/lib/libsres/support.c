
/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <arpa/nameser.h>
#include <resolv.h>

#include "resolver.h"
#include "res_errors.h"

extern void res_pquery(const res_state statp, const u_char *msg, int len, FILE *file);

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

u_int16_t wire_name_length (const u_int8_t *field)
{
    /* Calculates the number of bytes in a DNS wire format name */
    u_short j;
    if (field==NULL) return 0;
                                                                                                                          
    for (j = 0; field[j]&&!(0xc0&field[j])&&j<MAXDNAME ; j += field[j]+1);
    if (field[j]) j++;
    j++;
                                                                                                                          
    if (j > MAXDNAME)
        return 0;
    else
        return j;
}

u_int16_t wire_name_labels (const u_int8_t *field)
{
    /* Calculates the number of bytes in a DNS wire format name */
    u_short j;
    u_short l=0;
    if (field==NULL) return 0;
                                                                                                                          
    for (j = 0; field[j]&&!(0xc0&field[j])&&j<MAXDNAME ; j += field[j]+1)
        l++;
    if (field[j]) j++;
    j++;
    l++;
                                                                                                                          
    if (j > MAXDNAME)
        return 0;
    else
        return l;
}

static int seq_number = 0;
FILE        *logfile = NULL;
                                                                                                                          
void my_free (void *p, char *filename, int lineno)
{
    if (logfile==NULL)
        logfile = fopen ("memory_logfile", "w");
                                                                                                                          
    fprintf (logfile, "0x%08lx %5d bFREE %-20s %5d\n", (u_long) p, seq_number++,
                                filename, lineno);
    fflush (logfile);
    free (p);
}
                                                                                                                          
void *my_malloc (size_t t, char *filename, int lineno)
{
    void *p = malloc (t);
                                                                                                                          
    if (logfile==NULL)
        logfile = fopen ("memory_logfile", "w");
                                                                                                                          
    fprintf (logfile, "0x%08lx %5d aMALL %-20s %5d size=%6d\n", (u_long) p, seq_number++,
                                filename, lineno, (u_int)t);
    fflush (logfile);
                                                                                                                          
    return p;
}
                                                                                                                          
char *my_strdup (const char *str, char *filename, int lineno)
{
    char *p = strdup (str);
    if (logfile==NULL)
        logfile = fopen ("memory_logfile", "w");
                                                                                                                          
    fprintf (logfile, "0x%08lx %5d aSTRD %-20s %5d\n", (u_long) p, seq_number++,
                                filename, lineno);
    fflush (logfile);
                                                                                                                          
    return p;
}

void dump_response (const u_int8_t *ans, int resplen)
{
    /* Prints the "raw" response from DNS */
    int i,j, k;
                                                                                                                          
    printf ("Message length is %d\n", resplen);
                                                                                                                          
    for (i = 0; i < 12; i++) printf ("%02x ", (u_char) ans[i]);
    printf ("\n");
    k = 12;
    while (ans[k]) k += ans[k] + 1;
    for (i = 12; i < k+1; i++) printf ("%02x ", (u_char) ans[i]);
    printf (": ");
    for (i = k+1; i < k+5; i++) printf ("%02x ", (u_char) ans[i]);
    printf ("\n");
    k += 5;
    if (k < resplen)
    do
    {
        j = wire_name_length(&ans[k]) + 10; /* j = envelope length */
        j += ntohs(*(u_short*)(&ans[k+j-2])); /* adds rdata length to j */
        for (i = k; i < k+j; i++) printf ("%02x ", (u_char) ans[i]);
        printf ("\n");
        k += j;
    } while (k < resplen);
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

int skip_questions(const u_int8_t *buf)
{
    return 12 + wire_name_length (&buf[12]) + 4;
}


u_int16_t retrieve_type (const u_int8_t *rr)
{
    u_int16_t   type_n;
    int         name_length = wire_name_length (rr);
                                                                                                                          
    memcpy (&type_n, &rr[name_length], sizeof(u_int16_t));
    return ntohs(type_n);
}

int res_sq_set_message(char **error_msg, char *msg, int error_code)
{
    *error_msg = (char *) MALLOC (strlen(msg)+1);
    if (*error_msg==NULL) return SR_MEMORY_ERROR;
    sprintf (*error_msg, "%s", msg);
    return error_code;
}

int labelcmp (const u_int8_t *name1, const u_int8_t *name2)
{
    /* Compare two names, assuming same number of labels in each */
    int             index1 = 0;
    int             index2 = 0;
    int             length1 = (int) name1[index1];
    int             length2 = (int) name2[index2];
    int             min_len = length1 < length2 ? length1 : length2;
    int             ret_val;
                                                                                                                          
    u_int8_t        buffer1[MAXDNAME];
    u_int8_t        buffer2[MAXDNAME];
    int             i;
                                                                                                                          
    /* Degenerate case - root versus root */
    if (length1==0 && length2==0) return 0;
                                                                                                                          
    /* Recurse to try more significant label(s) first */
    ret_val=labelcmp(&name1[length1+1],&name2[length2+1]);
                                                                                                                          
    /* If there is a difference, propogate that back up the calling tree */
    if (ret_val!=0) return ret_val;
                                                                                                                          
    /* Compare this label's first min_len bytes */
    /* Convert to lower case first */
    memcpy (buffer1, &name1[index1+1], min_len);
    for (i =0; i < min_len; i++)
        if (isupper(buffer1[i])) buffer1[i]=tolower(buffer1[i]);
                                                                                                                          
    memcpy (buffer2, &name2[index2+1], min_len);
    for (i =0; i < min_len; i++)
        if (isupper(buffer2[i])) buffer2[i]=tolower(buffer2[i]);
                                                                                                                          
    ret_val=memcmp(buffer1, buffer2, min_len);
                                                                                                                          
    /* If they differ, propgate that */
    if (ret_val!=0) return ret_val;
    /* If the first n bytes are the same, then the length determines
        the difference - if any */
    return length1-length2;
}
                                                                                                                          
int namecmp (const u_int8_t *name1, const u_int8_t *name2)
{
    /* compare the DNS wire format names in name1 and name2 */
    /* return -1 if name1 is before name2, 0 if equal, +1 otherwise */
    int labels1 = 1;
    int labels2 = 1;
    int index1 = 0;
    int index2 = 0;
    int ret_val;
    int i;
                                                                                                                          
    /* count labels */
    for (;name1[index1];index1 += (int) name1[index1]+1) labels1++;
    for (;name2[index2];index2 += (int) name2[index2]+1) labels2++;
                                                                                                                          
    index1 = 0;
    index2 = 0;
                                                                                                                          
    if (labels1 > labels2)
        for (i = 0; i < labels1-labels2; i++) index1 += (int) name1[index1]+1;
    else
        for (i = 0; i < labels2-labels1; i++) index2 += (int) name2[index2]+1;
                                                                                                                          
    ret_val = labelcmp(&name1[index1], &name2[index2]);
                                                                                                                          
    if (ret_val != 0) return ret_val;
                                                                                                                          
    /* If one dname is a "proper suffix" of the other,
        the shorter comes first */
    return labels1-labels2;
}

