
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
#include "validator-internal.h"

#include <openssl/rand.h>

#include "res_support.h"
#include "res_io_manager.h"

extern void     libsres_pquery(const u_char * msg, size_t len, FILE * file);


static int      seq_number = 0;
FILE           *logfile = NULL;
#define MEM_LOGFILE "memory_logfile"

#ifdef WIN32
/*
   Implementation as per:
   The Open Group Base Specifications, Issue 6
   IEEE Std 1003.1, 2004 Edition

   The timezone pointer arg is ignored.  Errors are ignored.
*/

int gettimeofday(struct timeval* p, void* tz /* IGNORED */)
{
    union {
        long long ns100; /*time since 1 Jan 1601 in 100ns units */
        FILETIME ft;
    } now;

    GetSystemTimeAsFileTime( &(now.ft) );
    p->tv_usec=(long)((now.ns100 / 10LL) % 1000000LL );
    p->tv_sec= (long)((now.ns100-(116444736000000000LL))/10000000LL);
    return 0;
}
#endif

int
res_gettimeofday_buf(char *buf, size_t bufsize) {

    struct timeval  tv;
    struct tm       *tp;
    struct tm       tm;

    tp = NULL;

#ifdef WIN32
    time(&tv.tv_sec);
#else
    gettimeofday(&tv, NULL);
#endif

#ifdef HAVE_LOCALTIME_R
    localtime_r(&tv.tv_sec, &tm);
    tp = &tm;
#else
    tp = localtime(&tv.tv_sec);
#endif

    if (tp) {
        snprintf(buf, bufsize, "%04d%02d%02d::%02d:%02d:%02d ", 
            tp->tm_year+1900, tp->tm_mon+1, tp->tm_mday,
            tp->tm_hour, tp->tm_min, tp->tm_sec);
    } else {
        snprintf(buf, bufsize, "0000:00:00::00:00:00 ");
    }

    return 0;
}


void
my_free(void *p, char *filename, int lineno)
{
    if (logfile == NULL)
        logfile = fopen(MEM_LOGFILE, "w");

    fprintf(logfile, "0x%08lx %5d bFREE %-20s %5d\n", (u_long) p,
            seq_number++, filename, lineno);
    fflush(logfile);
    free(p);
}

void           *
my_malloc(size_t t, char *filename, int lineno)
{
    void           *p;

    if (logfile == NULL)
        logfile = fopen(MEM_LOGFILE, "w");

    if (t == 0) {
        res_log(NULL,LOG_DEBUG, "0 byte alloc from %-20s %5d", filename, lineno);
        p = NULL;
    }
    else
        p = malloc(t);

    fprintf(logfile, "0x%08lx %5d aMALL %-20s %5d size=%6d\n", (u_long) p,
            seq_number++, filename, lineno, (u_int) t);
    fflush(logfile);

    return p;
}

char           *
my_strdup(const char *str, char *filename, int lineno)
{
    char           *p = strdup(str);
    if (logfile == NULL)
        logfile = fopen(MEM_LOGFILE, "w");

    fprintf(logfile, "0x%08lx %5d aSTRD %-20s %5d\n", (u_long) p,
            seq_number++, filename, lineno);
    fflush(logfile);

    return p;
}

void
print_response(u_char * ans, size_t resplen)
{
    if (ans && (resplen > 0))
        libsres_pquery(ans, resplen, stdout);
}

void
log_response(u_char * ans, size_t resplen)
{
    if (ans && (resplen > 0))
        libsres_pquery(ans, resplen, NULL);
}

void
print_hex_field(u_char field[], size_t length, size_t width, char *pref)
{
    /*
     * Prints an arbitrary bit field, from one address for some number of
     * bytes.  Output is formatted via the width, and includes the raw
     * hex value and (if printable) the printed value underneath.  "pref"
     * is a string used to start each line, e.g., "   " to indent.
     * 
     * This is very useful in gdb to see what's in a memory field.
     */
    size_t             i, start, stop;

    start = 0;
    do {
        stop = (start + width) < length ? (start + width) : length;
        printf("%s", pref);
        for (i = start; i < stop; i++)
            printf("%02x ", (u_char) field[i]);
        printf("\n");

        printf("%s", pref);
        for (i = start; i < stop; i++)
            if (isprint(field[i]))
                printf(" %c ", (u_char) field[i]);
            else
                printf("   ");
        printf("\n");

        start = stop;
    } while (start < length);
}

void
print_hex(u_char field[], size_t length)
{
    /*
     * Prints the hex values of a field...not as pretty as the print_hex_field.
     */
    size_t             i, start, stop;

    start = 0;
    do {
        stop = length;
        for (i = start; i < stop; i++)
            printf("%02x ", (u_char) field[i]);
        start = stop;
        if (start < length)
            printf("\n");
    } while (start < length);
}


struct sockaddr_storage **
create_nsaddr_array(int num_addrs)
{
    int i, j;

    struct sockaddr_storage **ns_address = (struct sockaddr_storage **)
        MALLOC (num_addrs * sizeof(struct sockaddr_storage *));
    if(ns_address == NULL)
        return NULL;

    for(i=0; i< num_addrs; i++) {
        ns_address[i] = (struct sockaddr_storage *)
            MALLOC (sizeof(struct sockaddr_storage));
        if (ns_address[i] == NULL) {
            for(j=0; j<i; j++)
                FREE(ns_address[i]);
            FREE(ns_address);
            return NULL;
        }
        memset(ns_address[i], 0, sizeof(struct sockaddr_storage));
    }
    return ns_address;
}

struct name_server *
create_name_server(void)
{
    struct name_server *ns;
    ns = (struct name_server *) MALLOC(sizeof(struct name_server));
    if (ns == NULL)
        return NULL;

    /*
     * Initialize the rest of the fields
     */
    ns->ns_tsig = NULL;
    ns->ns_security_options = ZONE_USE_NOTHING;
    ns->ns_status = 0;

    ns->ns_retrans = RES_TIMEOUT;
    ns->ns_retry = RES_RETRY;
    ns->ns_options = SR_QUERY_DEFAULT | SR_QUERY_DEBUG;
    ns->ns_edns0_size = RES_EDNS0_DEFAULT;

    ns->ns_next = NULL;
    ns->ns_address = NULL;
    ns->ns_number_of_addresses = 0;

    return ns;
}

struct name_server *
parse_name_server(const char *cp, const char *name_n)
{
    short port_num = NS_DEFAULTPORT;
    const char *cpt;
    char addr[IPADDR_STRING_MAX];
    struct name_server *ns;

    struct sockaddr_storage serv_addr;
    struct sockaddr_in *sin = (struct sockaddr_in *)&serv_addr;
#ifdef VAL_IPV6
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&serv_addr;
#if defined( WIN32 )
    size_t addrlen6 = sizeof(struct sockaddr_in6);
#endif
#endif
#if defined( WIN32 )
    size_t addrlen4 = sizeof(struct sockaddr_in);
#endif

    if (cp ==  NULL)
        return NULL;

    ns = create_name_server();
    if (ns == NULL)
        return NULL;

    if (NULL == name_n)
        name_n = "."; /* root zone */
    if (ns_name_pton(name_n, ns->ns_name_n,
                     sizeof(ns->ns_name_n)) == -1) {
        FREE(ns);
        return NULL;
    }

    /*
     * Look for port number in address string
     * syntax of '[address]:port'
     */
    cpt = cp;
    if ( (*cpt == '[') && (cpt = strchr(cpt,']')) ) {
        if ( sizeof(addr) < (cpt - cp) )
            goto err;
        memset(addr, 0, sizeof(addr));
        strncpy(addr, (cp + 1), (cpt - cp - 1));
        cp = addr;
        if ( (*(++cpt) == ':') && (0 == (port_num = atoi(++cpt))) )
            goto err;
    }

    /*
     * convert address string
     */
    memset(&serv_addr, 0, sizeof(serv_addr));
    if (INET_PTON(AF_INET, cp, ((struct sockaddr *)sin), &addrlen4) > 0) {
        sin->sin_family = AF_INET;     // host byte order
        sin->sin_port = htons(port_num);       // short, network byte order
    }
    else {
#ifdef VAL_IPV6
        if (INET_PTON(AF_INET6, cp, ((struct sockaddr *)sin6), &addrlen6) != 1)
            goto err;

        sin6->sin6_family = AF_INET6;     // host byte order
        sin6->sin6_port = htons(port_num);       // short, network byte order
#else
        goto err;
#endif
    }

    ns->ns_address = create_nsaddr_array(1);
    if(ns->ns_address == NULL)
        goto err;

    memcpy(ns->ns_address[0], &serv_addr,
           sizeof(serv_addr));
    ns->ns_number_of_addresses = 1;
    return ns;

  err:
    FREE(ns);
    return NULL;
}

void
free_name_server(struct name_server **ns)
{
    int             i;

    if (ns && *ns) {
        if ((*ns)->ns_tsig)
            FREE((*ns)->ns_tsig);
        for (i = 0; i < (*ns)->ns_number_of_addresses; i++) {
            FREE((*ns)->ns_address[i]);
        }
        if ((*ns)->ns_address)
            FREE((*ns)->ns_address);
        FREE(*ns);
        *ns = NULL;
    }
}

void
free_name_servers(struct name_server **ns)
{
    if (ns && *ns) {
        if ((*ns)->ns_next)
            free_name_servers(&((*ns)->ns_next));
        free_name_server(ns);
    }
}

u_int16_t libsres_random(void)
{
    u_int16_t rnd = 0;
    if (!RAND_bytes((unsigned char *)&rnd, sizeof(rnd))) {
        RAND_pseudo_bytes((unsigned char *)&rnd, sizeof(rnd));
    }
    
#if 0
    if (!RAND_pseudo_bytes((unsigned char *)&rnd, sizeof(rnd))) {
        /* bytes generated are not cryptographically strong */
        u_int16_t seed;
        seed = random() & 0xffff;
        RAND_seed(&seed, sizeof(seed));
        RAND_pseudo_bytes((unsigned char *)&rnd, sizeof(rnd));
    }
#endif

    return rnd;
}

int
label_bytes_cmp(const u_char * field1, size_t length1, 
                const u_char * field2, size_t length2)
{
    u_char        buffer1[NS_MAXCDNAME];
    u_char        buffer2[NS_MAXCDNAME];
    size_t        i;
    size_t        min_len;
    int           ret_val;

    /*
     * If the first n bytes are the same, then the length determines
     * the difference - if any 
     */
    if (length1 == 0 || length2 == 0)
        return length1 - length2;

    min_len = (length1 < length2) ? length1 : length2;

    /*
     * Compare this label's first min_len bytes 
     */
    /*
     * Convert to lower case first 
     */
    memcpy(buffer1, field1, min_len);
    for (i = 0; i < min_len; i++)
        if (isupper(buffer1[i]))
            buffer1[i] = tolower(buffer1[i]);

    memcpy(buffer2, field2, min_len);
    for (i = 0; i < min_len; i++)
        if (isupper(buffer2[i]))
            buffer2[i] = tolower(buffer2[i]);

    ret_val = memcmp(buffer1, buffer2, min_len);

    /*
     * If they differ, propgate that 
     */
    if (ret_val != 0)
        return ret_val;
    /*
     * If the first n bytes are the same, then the length determines
     * the difference - if any 
     */
    return length1 - length2;
}

int
labelcmp(const u_char * name1, const u_char * name2, size_t label_cnt)
{
    /*
     * Compare two names, assuming same number of labels in each 
     */
    size_t             length1;
    size_t             length2;
    const u_char  *ptr1[256];
    const u_char  *ptr2[256];
    size_t offset1 = 0;
    size_t offset2 = 0;
    size_t i;
    
    length1 = (int) (name1 ? name1[0] : 0);
    length2 = (int) (name2 ? name2[0] : 0);

    if (length1 == 0 || length2 == 0)
        return length1 - length2;

    if (label_cnt > 256) {
        return -1;
    }
    
    /* mark all the label start points */
    for(i=0; i<label_cnt; i++) {
        ptr1[i] = &name1[offset1];
        ptr2[i] = &name2[offset2];
        offset1 += name1[offset1]+1;
        offset2 += name2[offset2]+1; 
    }
    
    /* start from the last label, work upwards */
    while (label_cnt > 0) {
        int retval;

        length1 = *ptr1[label_cnt-1];
        length2 = *ptr2[label_cnt-1]; 

        if (length1 == 0 || length2 == 0) {
            retval = length1 - length2;
        } else {
            retval = label_bytes_cmp(&ptr1[label_cnt-1][1], 
                                     length1,
                                     &ptr2[label_cnt-1][1],
                                     length2);
        }

        if (retval != 0)
            return retval;

        label_cnt--; 
    }

    /* all labels are identical */
    return 0;
}

/*
 * compare DNS wire format names
 *
 * returns
 *      <0 if name1 is before name2
 *       0 if equal
 *      >0 if name1 is after name2
 */
int
namecmp(const u_char * name1, const u_char * name2)
{
    size_t             labels1 = 1;
    size_t             labels2 = 1;
    size_t             index1 = 0;
    size_t             index2 = 0;
    size_t             i;
    size_t             label_cnt;
    size_t             ldiff;
    int             ret_val;

    /*
     * deal w/any null ptrs 
     */
    if (name1 == NULL) {
        if (name2 == NULL)
            return 0;
        else
            return -1;
    } else {
        if (name2 == NULL)
            return 1;
    }

    /*
     * count labels 
     */
    for (; name1[index1]; index1 += (int) name1[index1] + 1)
        labels1++;
    for (; name2[index2]; index2 += (int) name2[index2] + 1)
        labels2++;

    index1 = 0;
    index2 = 0;

    /*
     * find index in longer name where the number of labels is equal 
     */
    if (labels1 > labels2) {
        label_cnt = labels2;
        ldiff = labels1 - labels2;
        for (i = 0; i < ldiff; i++)
            index1 += name1[index1] + 1;
    }
    else {
        label_cnt = labels1;
        ldiff = labels2 - labels1;
        for (i = 0; i < ldiff; i++)
            index2 += name2[index2] + 1;
    }

    /*
     * compare last N labels 
     */
    ret_val = labelcmp(&name1[index1], &name2[index2], label_cnt);

    if (ret_val != 0)
        return ret_val;

    /*
     * If one dname is a "proper suffix" of the other,
     * the shorter comes first 
     */
    return labels1 - labels2;
}

int
res_map_srio_to_sr(int val)
{
    switch(val) {
        case  SR_IO_UNSET:
        case  SR_IO_GOT_ANSWER:
            val = SR_UNSET;
            break;
        case SR_IO_NO_ANSWER_YET:
            val = SR_NO_ANSWER_YET;
            break;
        case  SR_IO_NO_ANSWER:
            val = SR_NO_ANSWER;
            break;
        case SR_IO_MEMORY_ERROR:
        case SR_IO_TOO_MANY_TRANS:
        case SR_IO_SOCKET_ERROR:
        case SR_IO_INTERNAL_ERROR:
        default:
            val = SR_INTERNAL_ERROR;
    }
    return val;
}

/*
 * using val_log for logging introduces a circular dependency. Default to
 * using stderr for logging unless USE_LIBVAL_LOGGING is defined.
 */
static int sres_level = LOG_WARNING;

void
res_set_debug_level(int level)
{
    sres_level = level;
}

int
res_get_debug_level(void)
{
    return sres_level;
}


#ifndef USE_LIBVAL_LOGGING

void
res_log(void *dont_care, int level, const char *template, ...)
{
    char            buf[1028];
    va_list         ap;

    if (NULL == template || level > sres_level)
        return;

    res_gettimeofday_buf(buf, sizeof(buf) - 2);
    va_start(ap, template);
    vsnprintf(&buf[19], sizeof(buf) - 21, template, ap);
    va_end(ap);

    fprintf(stderr, "%s\n", buf);
    fflush(stderr);
}

void
res_log_ap(void *dont_care, int level, const char *template, va_list ap)
{
    char            buf[1028];

    if (NULL == template || level > sres_level)
        return;

    res_gettimeofday_buf(buf, sizeof(buf) - 2);
    vsnprintf(&buf[19], sizeof(buf) - 21, template, ap);

    fprintf(stderr, "%s\n", buf);
    fflush(stderr);
}


#else /* ifdef USE_LIBVAL_LOGGING */

/** pass messages on to val_log... */
void
res_log_ap(void *dont_care, int level, const char *template, va_list ap)
{
    if (NULL == template || level > sres_level)
        return;

    val_log_ap((val_context_t*)dont_care, LOG_ERR, template, ap);
}

/** pass messages on to val_log... */
void
res_log(void *dont_care, int level, const char *template, ...)
{
    va_list         ap;

    if (NULL == template || level > sres_level)
        return;

    va_start(ap, template);
    val_log_ap((val_context_t*)dont_care, LOG_ERR, template, ap);
    va_end(ap);
}

#endif /* ifdef USE_LIBVAL_LOGGING */
