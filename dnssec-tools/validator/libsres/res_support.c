
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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <openssl/rand.h>

#include <resolv.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>

#include "validator/resolver.h"

extern void     libsres_pquery(const u_char * msg, size_t len, FILE * file);


static int      seq_number = 0;
FILE           *logfile = NULL;
#define MEM_LOGFILE "memory_logfile"

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
    void           *p = malloc(t);

    if (logfile == NULL)
        logfile = fopen(MEM_LOGFILE, "w");

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

int
complete_read(int sock, void *field, size_t length)
{
    size_t             bytes;
    size_t             bytes_read = 0;
    memset(field, '\0', length);

    do {
        bytes = read(sock, field + bytes_read, length - bytes_read);
        if (bytes == -1)
            return -1;
        if (bytes == 0)
            return -1;
        bytes_read += bytes;
    } while (bytes_read < length);
    return length;
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
#endif
    union {
        struct in_addr   v4;
#ifdef VAL_IPV6
        struct in6_addr  v6;
#endif
    } address;

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
    ns->ns_options = RES_DEFAULT | RES_RECURSE | RES_DEBUG;
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
        bzero(addr, sizeof(addr));
        strncpy(addr, (cp + 1), (cpt - cp - 1));
        cp = addr;
        if ( (*(++cpt) == ':') && (0 == (port_num = atoi(++cpt))) )
            goto err;
    }

    /*
     * convert address string
     */
    bzero(&serv_addr, sizeof(serv_addr));
    if (inet_pton(AF_INET, cp, &address.v4) > 0) {
        sin->sin_family = AF_INET;     // host byte order
        sin->sin_addr = address.v4;
        sin->sin_port = htons(port_num);       // short, network byte order
    }
    else {
#ifdef VAL_IPV6
        if (inet_pton(AF_INET6, cp, &address.v6) != 1)
            goto err;

        sin6->sin6_family = AF_INET6;     // host byte order
        memcpy(&sin6->sin6_addr, &address.v6, sizeof(address.v6));
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
