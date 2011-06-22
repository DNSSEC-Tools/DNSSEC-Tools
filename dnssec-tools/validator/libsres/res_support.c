
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
 * Copyright 2005-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#include "validator-config.h"
#include "validator-internal.h"

#include <openssl/rand.h>

#include "res_support.h"

extern void     libsres_pquery(const u_char * msg, size_t len, FILE * file);


static int      seq_number = 0;
FILE           *logfile = NULL;
#define MEM_LOGFILE "memory_logfile"

#ifndef HAVE_GETTIMEOFDAY
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
    /*
     * fp_nquery is a resolver debug routine (I think), the rest
     * would dump the response in byte form, formatted to match
     * the query's structure 
     */
    //fp_nquery(ans, resplen, stdout);
    if (ans && (resplen > 0))
        libsres_pquery(ans, resplen, stdout);
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
        printf(pref);
        for (i = start; i < stop; i++)
            printf("%02x ", (u_char) field[i]);
        printf("\n");

        printf(pref);
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
    }
    return ns_address;
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
#if defined( WIN32 ) && !defined( LIBVAL_USE_WOCK )
    size_t addrlen6 = sizeof(struct sockaddr_in6);
#endif
#endif
#if defined( WIN32 ) && !defined( LIBVAL_USE_WOCK )
    size_t addrlen4 = sizeof(struct sockaddr_in);
#endif

    if (cp ==  NULL)
        return NULL;

    ns = (struct name_server *) MALLOC(sizeof(struct name_server));
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
     * Initialize the rest of the fields
     */
    ns->ns_tsig = NULL;
    ns->ns_security_options = ZONE_USE_NOTHING;
    ns->ns_status = 0;

    ns->ns_retrans = RES_TIMEOUT;
    ns->ns_retry = RES_RETRY;
    ns->ns_options = RES_DEFAULT | RES_DEBUG;
    ns->ns_edns0_size = RES_EDNS0_DEFAULT;

    ns->ns_next = NULL;
    ns->ns_number_of_addresses = 0;

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
    u_int16_t rnd;
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

/*
 * using val_log for logging introduces a circular dependency. Default to
 * using stderr for logging unless USE_LIBVAL_LOGGING is defined.
 */
#ifndef USE_LIBVAL_LOGGING

static int sres_level = LOG_WARNING;

void
res_log(void *dont_care, int level, const char *template, ...)
{
    char            buf[1028];
    struct timeval  tv;
    struct tm       *tm;
    va_list         ap;

    if (NULL == template)
        return;

    /** check individual level */
    if (level > sres_level)
        return;

    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);

    snprintf(buf, sizeof(buf) - 2, "%04d%02d%02d::%02d:%02d:%02d ", 
            tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
            tm->tm_hour, tm->tm_min, tm->tm_sec);
    va_start(ap, template);
    vsnprintf(&buf[19], sizeof(buf) - 21, template, ap);

    fprintf(stderr, buf);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(ap);
}

#else /* ifdef USE_LIBVAL_LOGGING */

/** pass messages on to val_log... */
void
res_log(void *dont_care, int level, const char *template, ...)
{
    va_list         ap;

    if (NULL == template)
        return;

    va_start(ap, template);
    val_log((val_context_t*)dont_care, level, template, ap);
    va_end(ap);
}

#endif /* ifdef USE_LIBVAL_LOGGING */
