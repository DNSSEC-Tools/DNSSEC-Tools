/*
 * Copyright (c) 1985, 1993
 *    The Regents of the University of California.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "validator-config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#else
#include "arpa/header.h"
#endif

#include "resolver.h"
#include "res_mkquery.h"

/*
 * Uncomment the following line to turn on debugging for this file 
 */
/*
 * #define DEBUG
 */


extern const char *_libsres_opcodes[];

u_int
libsres_randomid(void)
{
    struct timeval  now;

    gettimeofday(&now, NULL);
    return (0xffff & (now.tv_sec ^ now.tv_usec ^ getpid()));
}

/*
 * Form all types of queries.
 * Returns the size of the result or -1.
 */
int
res_val_nmkquery(struct name_server *pref_ns, int op,   /* opcode of query */
                 const char *dname,     /* domain name */
                 int class, int type,   /* class and type of query */
                 const u_char * data,   /* resource record data */
                 int datalen,   /* length of data */
                 const u_char * newrr_in,       /* new rr for modify or append */
                 u_char * buf,  /* buffer to put query */
                 int buflen)
{                               /* size of buffer */
    register HEADER *hp;
    register u_char *cp, *ep;
    register int    n;
    u_char         *dnptrs[20], **dpp, **lastdnptr;

    //      UNUSED(newrr_in);

#ifdef DEBUG
    if (pref_ns->ns_options & RES_DEBUG)
        printf(";; res_val_nmkquery(%s, %s, %s, %s)\n",
               _libsres_opcodes[op], dname, p_class(class), p_type(type));
#endif
    /*
     * Initialize header fields.
     */
    if ((buf == NULL) || (buflen < NS_HFIXEDSZ))
        return (-1);
    memset(buf, 0, NS_HFIXEDSZ);
    hp = (HEADER *) buf;
    hp->id = libsres_randomid();
    hp->opcode = op;
    hp->rd = (pref_ns->ns_options & RES_RECURSE) != 0U;
    hp->rcode = ns_r_noerror;
    cp = buf + NS_HFIXEDSZ;
    ep = buf + buflen;
    dpp = dnptrs;
    *dpp++ = buf;
    *dpp++ = NULL;
    lastdnptr = dnptrs + sizeof dnptrs / sizeof dnptrs[0];
    /*
     * perform opcode specific processing
     */
    switch (op) {
    case ns_o_query:
        /** FALLTHROUGH */
    case ns_o_notify:
        if (ep - cp < NS_QFIXEDSZ)
            return (-1);
        if ((n = dn_comp(dname, cp, ep - cp - NS_QFIXEDSZ, dnptrs,
                         lastdnptr)) < 0)
            return (-1);
        cp += n;
        ns_put16(type, cp);
        cp += NS_INT16SZ;
        ns_put16(class, cp);
        cp += NS_INT16SZ;
        hp->qdcount = htons(1);
        if (op == ns_o_query || data == NULL)
            break;
        /*
         * Make an additional record for completion domain.
         */
        if ((ep - cp) < NS_RRFIXEDSZ)
            return (-1);
        n = dn_comp((const char *) data, cp, ep - cp - NS_RRFIXEDSZ,
                    dnptrs, lastdnptr);
        if (n < 0)
            return (-1);
        cp += n;
        ns_put16(ns_t_null, cp);
        cp += NS_INT16SZ;
        ns_put16(class, cp);
        cp += NS_INT16SZ;
        ns_put32(0, cp);
        cp += NS_INT32SZ;
        ns_put16(0, cp);
        cp += NS_INT16SZ;
        hp->arcount = htons(1);
        break;

    case ns_o_iquery:
        /*
         * Initialize answer section
         */
        if (ep - cp < 1 + NS_RRFIXEDSZ + datalen)
            return (-1);
        *cp++ = '\0';           /* no domain name */
        ns_put16(type, cp);
        cp += NS_INT16SZ;
        ns_put16(class, cp);
        cp += NS_INT16SZ;
        ns_put32(0, cp);
        cp += NS_INT32SZ;
        ns_put16(datalen, cp);
        cp += NS_INT16SZ;
        if (datalen) {
            memcpy(cp, data, datalen);
            cp += datalen;
        }
        hp->ancount = htons(1);
        break;

    default:
        return (-1);
    }
    return (cp - buf);
}

#ifdef RES_USE_EDNS0
/*
 * attach OPT pseudo-RR, as documented in RFC2671 (EDNS0). 
 */

int
res_val_nopt(struct name_server *pref_ns, int n0,       /* current offset in buffer */
             u_char * buf,      /* buffer to put query */
             int buflen,        /* size of buffer */
             int anslen)
{                               /* UDP answer buffer size */
    register HEADER *hp;
    register u_char *cp, *ep;
    u_int16_t       flags = 0;

#ifdef DEBUG
    if ((pref_ns->ns_options & RES_DEBUG) != 0U)
        printf(";; res_nopt()\n");
#endif

    hp = (HEADER *) buf;
    cp = buf + n0;
    ep = buf + buflen;

    if ((ep - cp) < 1 + NS_RRFIXEDSZ)
        return (-1);


    *cp++ = 0;                  /* "." */

    ns_put16(ns_t_opt, cp);     /* TYPE */
    cp += NS_INT16SZ;
    ns_put16(anslen & 0xffff, cp);      /* CLASS = UDP payload size */
    cp += NS_INT16SZ;
    *cp++ = ns_r_noerror;       /* extended RCODE */
    *cp++ = 0;                  /* EDNS version */
#ifdef DEBUG
    if (pref_ns->ns_options & RES_DEBUG)
        printf(";; res_opt()... ENDS0 DNSSEC\n");
#endif
    flags |= NS_OPT_DNSSEC_OK;
    ns_put16(flags, cp);
    cp += NS_INT16SZ;
    ns_put16(0, cp);            /* RDLEN */
    cp += NS_INT16SZ;
    hp->arcount = htons(ntohs(hp->arcount) + 1);

    return (cp - buf);
}
#endif
