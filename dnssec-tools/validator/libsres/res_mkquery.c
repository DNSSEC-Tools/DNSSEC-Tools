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
#include "validator-internal.h"

#include "res_mkquery.h"
#include "res_tsig.h"
#include "res_support.h"
#include "res_comp.h"

/*
 * Uncomment the following line to turn on debugging for this file 
 */
/*
 * #define DEBUG
 */

#if ! defined( NS_HFIXEDSZ ) && defined (HFIXEDSZ)
#define NS_HFIXEDSZ HFIXEDSZ
#define NS_QFIXEDSZ QFIXEDSZ 
#define NS_RRFIXEDSZ RRFIXEDSZ
#endif

extern const char *_libsres_opcodes[];

/*
 * Form all types of queries.
 * Returns the size of the result or -1.
 */
int
res_val_nmkquery(struct name_server *pref_ns, int op,   /* opcode of query */
                 const char *dname,     /* domain name */
                 u_int16_t class_h, u_int16_t type_h,   /* class and type of query */
                 const u_char * data,   /* resource record data */
                 size_t datalen,   /* length of data */
                 const u_char * newrr_in,       /* new rr for modify or append */
                 u_char * buf,  /* buffer to put query */
                 size_t buflen,
                 size_t *query_length)
{                               /* size of buffer */
    register HEADER *hp;
    register u_char *cp, *ep;
    register int    n;
    u_char         *dnptrs[20], **dpp, **lastdnptr;
    u_int16_t datalen_16 = (u_int16_t)datalen;

    //      UNUSED(newrr_in);

#ifdef DEBUG
    if (pref_ns->ns_options & SR_QUERY_DEBUG)
        printf(";; res_val_nmkquery(%s, %s, %s, %s)\n",
               _libsres_opcodes[op], dname, p_class(class_h), p_type(type_h));
#endif
    /*
     * Initialize header fields.
     */
    if ((buf == NULL) || (buflen < NS_HFIXEDSZ) || query_length == NULL 
            || datalen > datalen_16)
        return (-1);
    *query_length = 0;
    
    memset(buf, 0, NS_HFIXEDSZ);
    hp = (HEADER *) buf;
    hp->id = libsres_random();
    hp->opcode = op;
    hp->rd = (pref_ns->ns_options & SR_QUERY_RECURSE) != 0U;
    hp->rcode = ns_r_noerror;
    cp = buf + NS_HFIXEDSZ;
    ep = buf + buflen;
    dpp = dnptrs;
    *dpp++ = buf;
    *dpp++ = NULL;
    lastdnptr = dnptrs + sizeof(dnptrs) / sizeof(dnptrs[0]);
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
        RES_PUT16(type_h, cp);
        RES_PUT16(class_h, cp);
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
        RES_PUT16(ns_t_null, cp);
        RES_PUT16(class_h, cp);
        RES_PUT32(0, cp);
        RES_PUT16(0, cp);
        hp->arcount = htons(1);
        break;

    case ns_o_iquery:
        /*
         * Initialize answer section
         */
        if (ep - cp < 1 + NS_RRFIXEDSZ + datalen_16)
            return (-1);
        *cp++ = '\0';           /* no domain name */
        RES_PUT16(type_h, cp);
        RES_PUT16(class_h, cp);
        RES_PUT32(0, cp);
        RES_PUT16(datalen_16, cp);
        if (datalen_16) {
            memcpy(cp, data, datalen_16);
            cp += datalen_16;
        }
        hp->ancount = htons(1);
        break;

    default:
        return (-1);
    }
    if (cp > buf)
        *query_length = (cp - buf);

    return 0;
}

int
res_create_query_payload(struct name_server *ns,
                         const char *name,
                         const u_int16_t class_h,
                         const u_int16_t type_h,
                         u_char **signed_query,
                         size_t *signed_length)
{
    u_char          query[12 + NS_MAXDNAME + 4];
    size_t          query_limit = 12 + NS_MAXDNAME + 4;
    size_t          query_length = 0;
    int ret_val;

    ret_val = res_val_nmkquery(ns, ns_o_query, name, class_h, type_h, NULL,
                             0, NULL, query, query_limit, &query_length);
    if (ret_val==  -1)
        return SR_MKQUERY_INTERNAL_ERROR;

    if (ns->ns_options & SR_QUERY_SET_DO) {
        /** Enable EDNS0 and set the DO flag */
        ret_val = res_val_nopt(ns, query, query_limit,
                             &query_length);
    }
    if (ns->ns_options & SR_QUERY_SET_CD) {
        /** Set the CD flag */
        if (!(ns->ns_options & SR_QUERY_SET_DO)) {
            res_log(NULL, LOG_NOTICE, 
                    "libsres: ""CD bit set without EDNS0/DO enabled");
        }
        ((HEADER *) query)->cd = 1;
    }
    if (ret_val == -1)
        return SR_MKQUERY_INTERNAL_ERROR;
    if (ns->ns_options & SR_QUERY_RECURSE) {
        ((HEADER *)query)->rd = 1;
    } else {
        /* don't ask for recursion */
        ((HEADER *)query)->rd = 0;
    }

    if ((ret_val = res_tsig_sign(query, query_length, ns,
                                 signed_query,
                                 signed_length)) != SR_TS_OK) {
        return SR_MKQUERY_INTERNAL_ERROR; 
    }
    return 0;
}



/*
 * attach OPT pseudo-RR, as documented in RFC2671 (EDNS0). 
 */

int
res_val_nopt(struct name_server *pref_ns, 
             u_char * buf,      /* buffer to put query */
             size_t buflen,        /* size of buffer */
             size_t *query_length)
{                               /* UDP answer buffer size */
    register HEADER *hp;
    register u_char *cp, *ep;
    u_int16_t       flags = 0;

#ifdef DEBUG
    if ((pref_ns->ns_options & SR_QUERY_DEBUG) != 0U)
        printf(";; res_nopt()\n");
#endif

    if (query_length == NULL)
        return -1;

    hp = (HEADER *) buf;
    cp = buf + *query_length;
    ep = buf + buflen;

    if ((ep - cp) < 1 + NS_RRFIXEDSZ)
        return (-1);


    *cp++ = 0;                  /* "." */

    RES_PUT16(ns_t_opt, cp);     /* TYPE */
    RES_PUT16(pref_ns->ns_edns0_size & 0xffff, cp);      /* CLASS = UDP payload size */
    *cp++ = ns_r_noerror;       /* extended RCODE */
    *cp++ = 0;                  /* EDNS version */
#ifdef DEBUG
    if (pref_ns->ns_options & SR_QUERY_DEBUG)
        printf(";; res_opt()... ENDS0 DNSSEC\n");
#endif
    flags |= NS_OPT_DNSSEC_OK;
    RES_PUT16(flags, cp);
    RES_PUT16(0, cp);            /* RDLEN */
    hp->arcount = htons(ntohs(hp->arcount) + 1);

    if (cp > buf)
        *query_length = cp - buf;

    return 0;
}
