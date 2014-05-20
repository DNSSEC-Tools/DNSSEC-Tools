/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-1999 by Internet Software Consortium.
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

#include "nsap_addr.h"
#include "res_support.h"
#include "res_comp.h"
#include "ns_samedomain.h"
#include "base64.h"
#include "res_debug.h"

#ifndef MIN
#define MIN(a, b)       ((a) < (b) ? (a) : (b))
#endif

#define ADD_BYTES(sptr, eptr) do { \
    int             n, m;\
    char           *p;\
    const u_char   *teptr = eptr;\
    while (sptr < teptr) {\
        p = tmp;\
        n = MIN(32, teptr - sptr);\
        for (m = 0; m < n; m++)\
            p += SPRINTF((p, "%02x", sptr[m]));\
        T(addstr(tmp, p - tmp, &buf, &buflen));\
        p = tmp;\
        sptr += n;\
    }\
} while (0);

/*
 * Forward. 
 */

static size_t   prune_origin(const char *name, const char *origin);
static int      charstr(const u_char * rdata, const u_char * edata,
                        char **buf, size_t * buflen);
static int      addname(const u_char * msg, size_t msglen,
                        const u_char ** p, const char *origin,
                        char **buf, size_t * buflen);
static void     addlen(size_t len, char **buf, size_t * buflen);
static int      addstr(const char *src, size_t len,
                       char **buf, size_t * buflen);
static int      addtab(size_t len, size_t target, int spaced,
                       char **buf, size_t * buflen);
int             ns_sprintrrf_data(const u_char * msg, size_t msglen,
                  const char *name, ns_class class_h, ns_type type_h,
                  u_long ttl, const u_char * rdata, size_t rdlen,
                  const char *origin,
                  char *buf, size_t buflen);
/*
 * Macros. 
 */

#define T(x) \
    do { \
        if ((x) < 0) \
            return (-1); \
    } while (0)

/*
 * Public. 
 */

/*
 * calculates the key id.
 * takes an array of bytes and a length.
 * returns a 16  bit checksum.
 */
u_int16_t
id_calc(const u_char * key, const int keysize)
{
    u_int32_t       ac;
    const u_char   *kp = key;
    int             size = keysize;

    if (!key || (keysize <= 0))
        return (-1);

    for (ac = 0; size > 1; size -= 2, kp += 2)
        ac += ((*kp) << 8) + *(kp + 1);

    if (size > 0)
        ac += ((*kp) << 8);
    ac += (ac >> 16) & 0xffff;

    return (ac & 0xffff);
}

/*
 * int
 * ns_sprintrr(handle, rr, name_ctx, origin, buf, buflen)
 *      Convert an RR to presentation format.
 * return:
 *      Number of characters written to buf, or -1 (check errno).
 */
int
ns_sprintrr(const ns_msg * handle, const ns_rr * rr,
            const char *name_ctx, const char *origin,
            char *buf, size_t buflen)
{
    int             n;

    n = ns_sprintrrf(ns_msg_base(*handle), ns_msg_size(*handle),
                     ns_rr_name(*rr), ns_rr_class(*rr), ns_rr_type(*rr),
                     ns_rr_ttl(*rr), ns_rr_rdata(*rr), ns_rr_rdlen(*rr),
                     name_ctx, origin, buf, buflen);
    return (n);
}

/*
 * int
 * ns_sprintrrf(msg, msglen, name, class, type, ttl, rdata, rdlen,
 *             name_ctx, origin, buf, buflen)
 *      Convert the fields of an RR into presentation format.
 * return:
 *      Number of characters written to buf, or -1 (check errno).
 */
int
ns_sprintrrf(const u_char * msg, size_t msglen,
             const char *name, ns_class class_h, ns_type type_h,
             u_long ttl, const u_char * rdata, size_t rdlen,
             const char *name_ctx, const char *origin,
             char *buf, size_t buflen)
{
    const char     *obuf = buf;
    int             spaced = 0;

    char            tmp[100];
    int             len, x;

    /*
     * Owner.
     */
    if (name_ctx != NULL && ns_samename(name_ctx, name) == 1) {
        T(addstr("\t\t\t", 3, &buf, &buflen));
    } else {
        len = prune_origin(name, origin);
        if (*name == '\0') {
            goto root;
        } else if (len == 0) {
            T(addstr("@\t\t\t", 4, &buf, &buflen));
        } else {
            T(addstr(name, len, &buf, &buflen));
            /*
             * Origin not used or not root, and no trailing dot? 
             */
            if (((origin == NULL || origin[0] == '\0') ||
                 (origin[0] != '.' && origin[1] != '\0' &&
                  name[len] == '\0')) && name[len - 1] != '.') {
              root:
                T(addstr(".", 1, &buf, &buflen));
                len++;
            }
            T(spaced = addtab(len, 24, spaced, &buf, &buflen));
        }
    }

    /*
     * TTL, Class, Type.
     */
    T(x = ns_format_ttl(ttl, buf, buflen));
    addlen(x, &buf, &buflen);
    len = SPRINTF((tmp, " %s %s", p_class(class_h), p_type(type_h)));
    T(addstr(tmp, len, &buf, &buflen));
    if (rdlen == 0U)
        return (buf - obuf);
     T(spaced = addtab(x + len, 16, spaced, &buf, &buflen));

    return ns_sprintrrf_data(msg, msglen, name, class_h, type_h,
                             ttl, rdata, rdlen, origin,
                             buf, buflen);
}

int
ns_sprintrrf_data(const u_char * msg, size_t msglen,
                  const char *name, ns_class class_h, ns_type type_h,
                  u_long ttl, const u_char * rdata, size_t rdlen,
                  const char *origin,
                  char *buf, size_t buflen)
{
    struct sockaddr_in sa;
#ifdef VAL_IPV6
    struct sockaddr_in6 sa6;
#endif
    const char *addr = NULL;
    int len;
    const u_char   *edata = rdata + rdlen;
    int             spaced = 0;
    char            tmp[100];
    const char     *obuf = buf;
    const char     *comment;

    memset(&sa, 0, sizeof(sa));
#ifdef VAL_IPV6
    memset(&sa6, 0, sizeof(sa6));
#endif

    /*
     * RData.
     */
    switch (type_h) {
    case ns_t_a:
        if (rdlen != (size_t) NS_INADDRSZ)
            goto formerr;
	    memcpy(&sa.sin_addr, rdata, NS_INADDRSZ);
        INET_NTOP(AF_INET, ((struct sockaddr *)&sa), sizeof(sa), buf, buflen, addr);
        addlen(strlen(buf), &buf, &buflen);
        break;

    case ns_t_cname:
    case ns_t_mb:
    case ns_t_mg:
    case ns_t_mr:
    case ns_t_ns:
    case ns_t_ptr:
    case ns_t_dname:
        T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
        break;

    case ns_t_hinfo:
    case ns_t_isdn:
        /*
         * First word. 
         */
        T(len = charstr(rdata, edata, &buf, &buflen));
        if (len == 0)
            goto formerr;
        rdata += len;
        T(addstr(" ", 1, &buf, &buflen));


        /*
         * Second word, optional in ISDN records. 
         */
        if (type_h == ns_t_isdn && rdata == edata)
            break;

        T(len = charstr(rdata, edata, &buf, &buflen));
        if (len == 0)
            goto formerr;
        rdata += len;
        break;

    case ns_t_soa:{
            u_long          t;

            /** Server name.  */
            T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
            T(addstr(" ", 1, &buf, &buflen));

            /** Administrator name.  */
            T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
            T(addstr(" (\n", 3, &buf, &buflen));
            spaced = 0;

            if ((edata - rdata) != 5 * NS_INT32SZ)
                goto formerr;

            /** Serial number.  */
            RES_GET32(t, rdata);
            T(addstr("\t\t\t\t\t", 5, &buf, &buflen));
            len = SPRINTF((tmp, "%lu", t));
            T(addstr(tmp, len, &buf, &buflen));
            T(spaced = addtab(len, 16, spaced, &buf, &buflen));
            T(addstr("; serial\n", 9, &buf, &buflen));
            spaced = 0;

            /** Refresh interval.  */
            RES_GET32(t, rdata);
            T(addstr("\t\t\t\t\t", 5, &buf, &buflen));
            T(len = ns_format_ttl(t, buf, buflen));
            addlen(len, &buf, &buflen);
            T(spaced = addtab(len, 16, spaced, &buf, &buflen));
            T(addstr("; refresh\n", 10, &buf, &buflen));
            spaced = 0;

            /** Retry interval.  */
            RES_GET32(t, rdata);
            T(addstr("\t\t\t\t\t", 5, &buf, &buflen));
            T(len = ns_format_ttl(t, buf, buflen));
            addlen(len, &buf, &buflen);
            T(spaced = addtab(len, 16, spaced, &buf, &buflen));
            T(addstr("; retry\n", 8, &buf, &buflen));
            spaced = 0;

            /** Expiry.  */
            RES_GET32(t, rdata);
            T(addstr("\t\t\t\t\t", 5, &buf, &buflen));
            T(len = ns_format_ttl(t, buf, buflen));
            addlen(len, &buf, &buflen);
            T(spaced = addtab(len, 16, spaced, &buf, &buflen));
            T(addstr("; expiry\n", 9, &buf, &buflen));
            spaced = 0;

            /** Minimum TTL.  */
            RES_GET32(t, rdata);
            T(addstr("\t\t\t\t\t", 5, &buf, &buflen));
            T(len = ns_format_ttl(t, buf, buflen));
            addlen(len, &buf, &buflen);
            T(addstr(" )", 2, &buf, &buflen));
            T(spaced = addtab(len, 16, spaced, &buf, &buflen));
            T(addstr("; minimum\n", 10, &buf, &buflen));

            break;
        }

    case ns_t_mx:
    case ns_t_afsdb:
    case ns_t_rt:{
            u_int           t;

            if (rdlen < (size_t) NS_INT16SZ)
                goto formerr;

            /** Priority.  */
            RES_GET16(t, rdata);
            len = SPRINTF((tmp, "%u ", t));
            T(addstr(tmp, len, &buf, &buflen));

            /** Target.  */
            T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

            break;
        }

    case ns_t_px:{
            u_int           t;

            if (rdlen < (size_t) NS_INT16SZ)
                goto formerr;

            /** Priority.  */
            RES_GET16(t, rdata);
            len = SPRINTF((tmp, "%u ", t));
            T(addstr(tmp, len, &buf, &buflen));

            /** Name1.  */
            T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
            T(addstr(" ", 1, &buf, &buflen));

            /** Name2.  */
            T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

            break;
        }

    case ns_t_x25:
        T(len = charstr(rdata, edata, &buf, &buflen));
        if (len == 0)
            goto formerr;
        rdata += len;
        break;

    case ns_t_txt:
        while (rdata < edata) {
            T(len = charstr(rdata, edata, &buf, &buflen));
            if (len == 0)
                goto formerr;
            rdata += len;
            if (rdata < edata)
                T(addstr(" ", 1, &buf, &buflen));
        }
        break;

    case ns_t_nsap:{
            char            t[2 + 255 * 3];

            (void) inet_nsap_ntoa(rdlen, rdata, t);
            T(addstr(t, strlen(t), &buf, &buflen));
            break;
        }

#ifdef VAL_IPV6
    case ns_t_aaaa:
        if (rdlen != (size_t) NS_IN6ADDRSZ)
            goto formerr;
	    memcpy(&sa6.sin6_addr, rdata, NS_IN6ADDRSZ);
	    INET_NTOP(AF_INET6, ((struct sockaddr *)&sa6), sizeof(sa6), buf, buflen, addr);
        addlen(strlen(buf), &buf, &buflen);
        break;
#endif

    case ns_t_loc:{
            char            t[255];

            /** XXX protocol format checking?  */
            (void) loc_ntoa(rdata, t);
            T(addstr(t, strlen(t), &buf, &buflen));
            break;
        }

    case ns_t_naptr:{
            u_int           order, preference;
            char            t[50];

            if (rdlen < 2U * NS_INT16SZ)
                goto formerr;

            /** Order, Precedence.  */
            RES_GET16(order, rdata);
            RES_GET16(preference, rdata);
            len = SPRINTF((t, "%u %u ", order, preference));
            T(addstr(t, len, &buf, &buflen));

            /** Flags.  */
            T(len = charstr(rdata, edata, &buf, &buflen));
            if (len == 0)
                goto formerr;
            rdata += len;
            T(addstr(" ", 1, &buf, &buflen));

            /** Service.  */
            T(len = charstr(rdata, edata, &buf, &buflen));
            if (len == 0)
                goto formerr;
            rdata += len;
            T(addstr(" ", 1, &buf, &buflen));

            /** Regexp.  */
            T(len = charstr(rdata, edata, &buf, &buflen));
            if (len < 0)
                return (-1);
            if (len == 0)
                goto formerr;
            rdata += len;
            T(addstr(" ", 1, &buf, &buflen));

            /** Server.  */
            T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
            break;
        }

    case ns_t_srv:{
            u_int           priority, weight, port;
            char            t[50];

            if (rdlen < 3U * NS_INT16SZ)
                goto formerr;

            /** Priority, Weight, Port.  */
            RES_GET16(priority, rdata);
            RES_GET16(weight, rdata);
            RES_GET16(port, rdata);
            len = SPRINTF((t, "%u %u %u ", priority, weight, port));
            T(addstr(t, len, &buf, &buflen));

            /** Server.  */
            T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
            break;
        }

    case ns_t_minfo:
    case ns_t_rp:
        /** Name1.  */
        T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
        T(addstr(" ", 1, &buf, &buflen));

        /** Name2.  */
        T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

        break;

    case ns_t_wks:{
            int             n, lcnt;

            if (rdlen < 1U + NS_INT32SZ)
                goto formerr;

            if (rdlen != (size_t) NS_INADDRSZ)
		        goto formerr;

            /** Address.  */
	        memcpy(&sa.sin_addr, rdata, NS_INADDRSZ);
	        INET_NTOP(AF_INET, ((struct sockaddr *)&sa), sizeof(sa), buf, buflen, addr);
            addlen(strlen(buf), &buf, &buflen);
            rdata += NS_INADDRSZ;

            /** Protocol.  */
            len = SPRINTF((tmp, " %u ( ", *rdata));
            T(addstr(tmp, len, &buf, &buflen));
            rdata += NS_INT8SZ;

            /** Bit map.  */
            n = 0;
            lcnt = 0;
            while (rdata < edata) {
                u_int           c = *rdata++;
                do {
                    if (c & 0200) {
                        if (lcnt == 0) {
                            T(addstr("\n\t\t\t\t", 5, &buf, &buflen));
                            lcnt = 10;
                            spaced = 0;
                        }
                        len = SPRINTF((tmp, "%d ", n));
                        T(addstr(tmp, len, &buf, &buflen));
                        lcnt--;
                    }
                    c <<= 1;
                } while (++n & 07);
            }
            T(addstr(")", 1, &buf, &buflen));

            break;
        }

    case ns_t_ds:{
            u_int           algo;
            u_int           digest_type;
            u_int           hashlen = 0;

            rdata += NS_INT16SZ; /* skip key_id */
            algo = *rdata++ & 0xF;
            digest_type = *rdata++ & 0xF;

            len = SPRINTF((tmp, "%u %u",
                           algo, digest_type));
            T(addstr(tmp, len, &buf, &buflen));

            /* check if length of remaining data matches hash length */
            len = edata - rdata;
            if(digest_type == ALG_DS_HASH_SHA1)
                hashlen = SHA_DIGEST_LENGTH;
            else if(digest_type == ALG_DS_HASH_SHA256)
                hashlen = SHA256_DIGEST_LENGTH;
            else
                goto formerr;

            if (len != hashlen)
                goto formerr;

            len = SPRINTF((tmp, "\n\t\t"));
            T(addstr(tmp, len, &buf, &buflen));
            ADD_BYTES(rdata, edata);

            break;
        }

    case ns_t_dnskey:{
            char            base64_key[NS_MD5RSA_MAX_BASE64];
            u_int           keyflags, protocol, algorithm, key_id;
            const char     *leader;
            int             n;

            if (rdlen < 0U + NS_INT16SZ + NS_INT8SZ + NS_INT8SZ)
                goto formerr;

            /*
             * Key flags, Protocol, Algorithm. 
             */
            if (!rdata) {
                key_id = 0;
            } else {
                /** compute a checksum on the key part of the key rr */
                key_id = id_calc(rdata, edata - rdata);
            }
            RES_GET16(keyflags, rdata);
            protocol = *rdata++;
            algorithm = *rdata++;
            len = SPRINTF((tmp, "0x%04x %u %u",
                           keyflags, protocol, algorithm));
            T(addstr(tmp, len, &buf, &buflen));

            /*
             * Public key data. 
             */
            len = b64_ntop(rdata, edata - rdata,
                           base64_key, sizeof(base64_key));
            if (len < 0)
                goto formerr;
            if (len > 15) {
                T(addstr(" (", 2, &buf, &buflen));
                leader = "\n\t\t";
                spaced = 0;
            } else
                leader = " ";
            for (n = 0; n < len; n += 48) {
                T(addstr(leader, strlen(leader), &buf, &buflen));
                T(addstr(base64_key + n, MIN(len - n, 48), &buf, &buflen));
            }
            if (len > 15)
                T(addstr(" )", 2, &buf, &buflen));
            n = SPRINTF((tmp, " ; key_tag= %u", key_id));
            T(addstr(tmp, n, &buf, &buflen));

            break;
        }

    case ns_t_rrsig:{
            char            base64_key[NS_MD5RSA_MAX_BASE64];
            u_int           type_h, algorithm, labels, footprint;
            const char     *leader;
            u_long          t;
            int             n;

            if (rdlen < 22U)
                goto formerr;

            /** Type covered, Algorithm, Label count, Original TTL.  */
            RES_GET16(type_h, rdata);
            algorithm = *rdata++;
            labels = *rdata++;
            RES_GET32(t, rdata);
            len = SPRINTF((tmp, "%s %d %d %lu ",
                           p_type(type_h), algorithm, labels, t));
            T(addstr(tmp, len, &buf, &buflen));
            if (labels > (u_int) dn_count_labels(name))
                goto formerr;

            /** Signature expiry.  */
            RES_GET32(t, rdata);
            len = SPRINTF((tmp, "%s ", p_secstodate(t)));
            T(addstr(tmp, len, &buf, &buflen));

            /** Time signed.  */
            RES_GET32(t, rdata);
            len = SPRINTF((tmp, "%s ", p_secstodate(t)));
            T(addstr(tmp, len, &buf, &buflen));

            /** Signature Footprint.  */
            RES_GET16(footprint, rdata);
            len = SPRINTF((tmp, "%u ", footprint));
            T(addstr(tmp, len, &buf, &buflen));

            /** Signer's name.  */
            T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

            /** Signature.  */
            len = b64_ntop(rdata, edata - rdata,
                           base64_key, sizeof(base64_key));
            if (len > 15) {
                T(addstr(" (", 2, &buf, &buflen));
                leader = "\n\t\t";
                spaced = 0;
            } else
                leader = " ";
            if (len < 0)
                goto formerr;
            for (n = 0; n < len; n += 48) {
                T(addstr(leader, strlen(leader), &buf, &buflen));
                T(addstr(base64_key + n, MIN(len - n, 48), &buf, &buflen));
            }
            if (len > 15)
                T(addstr(" )", 2, &buf, &buflen));
            break;
        }

#ifdef LIBVAL_NSEC3
    case ns_t_nsec3: {
            u_int           algo;
            u_int           flags;
            u_int           iterations;
            u_int           saltlen;
            u_int           hashlen;

            if (rdlen < 0U + NS_INT8SZ + NS_INT8SZ + NS_INT16SZ + NS_INT8SZ)
                goto formerr;

            /* algorithm flags iterations saltlen */
            algo = *rdata++ & 0xF;
            flags = *rdata++ & 0xF;
            RES_GET16(iterations, rdata);

            len = SPRINTF((tmp, "%u %u %u ",
                           algo, flags, iterations));
            T(addstr(tmp, len, &buf, &buflen));

            saltlen = *rdata++ & 0xF;
            if (edata - rdata < saltlen) 
                goto formerr;

            if (saltlen >  0) {
                ADD_BYTES(rdata, (rdata + saltlen));
                len = SPRINTF((tmp, " "));
                T(addstr(tmp, len, &buf, &buflen));
            }

            hashlen = *rdata++;
            if (hashlen > edata - rdata)
                goto formerr;

            len = SPRINTF((tmp, "\n\t\t"));
            T(addstr(tmp, len, &buf, &buflen));
            ADD_BYTES(rdata, (rdata + hashlen));
            goto nxtbitmaps;
        }
#endif /* LIBVAL_NSEC3 */

    case ns_t_nsec: {
            int             c, n;
            u_char          b, l;

            /** Next domain name.  */
            T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

#ifdef LIBVAL_NSEC3
nxtbitmaps:
#endif /* LIBVAL_NSEC3 */

            /** Type bit map.  */
            while (edata - rdata > 0) {
                b = *rdata;
                rdata += NS_INT8SZ;
                l = *rdata;
                rdata += NS_INT8SZ;
                n = l * 8;

                for (c = 0; c < n; c++)
                    if (NS_NXT_BIT_ISSET(c, rdata)) {
                        len =
                            SPRINTF((tmp, " %s", p_type(b * (2 ^ 8) + c)));
                        T(addstr(tmp, len, &buf, &buflen));
                    }
                rdata += n;
            }
            break;
        }

    case ns_t_cert:{
            u_int           c_type, key_tag, alg;
            int             n;
            unsigned int    siz;
            char            base64_cert[8192], tmp[40];
            const char     *leader;

            RES_GET16(c_type, rdata);
            RES_GET16(key_tag, rdata);
            alg = (u_int) * rdata++;

            len = SPRINTF((tmp, "%d %d %d ", c_type, key_tag, alg));
            T(addstr(tmp, len, &buf, &buflen));
            siz = (edata - rdata) * 4 / 3 + 4;  /* "+4" accounts for trailing \0 */
            if (siz > sizeof(base64_cert) * 3 / 4) {
                const char     *str = "record too long to print";
                T(addstr(str, strlen(str), &buf, &buflen));
            } else {
                len = b64_ntop(rdata, edata - rdata, base64_cert, siz);

                if (len < 0)
                    goto formerr;
                else if (len > 15) {
                    T(addstr(" (", 2, &buf, &buflen));
                    leader = "\n\t\t";
                    spaced = 0;
                } else
                    leader = " ";

                for (n = 0; n < len; n += 48) {
                    T(addstr(leader, strlen(leader), &buf, &buflen));
                    T(addstr(base64_cert + n, MIN(len - n, 48),
                             &buf, &buflen));
                }
                if (len > 15)
                    T(addstr(" )", 2, &buf, &buflen));
            }
            break;
        }


    case ns_t_tsig:{
            /*
             * BEW - need to complete this 
             */
            int             n;

            T(len = addname(msg, msglen, &rdata, origin, &buf, &buflen));
            T(addstr(" ", 1, &buf, &buflen));
            rdata += 8;         /* time */
            RES_GET16(n, rdata);
            rdata += n;         /* sig */
            RES_GET16(n, rdata);
            RES_GET16(n, rdata);
            SPRINTF((buf, "%d", n));
            addlen(strlen(buf), &buf, &buflen);
            break;
        }

#ifdef VAL_IPV6
    case ns_t_a6:{
            struct in6_addr a;
            int             pbyte, pbit;

            /** prefix length */
            if (rdlen == 0U)
                goto formerr;
            len = SPRINTF((tmp, "%d ", *rdata));
            T(addstr(tmp, len, &buf, &buflen));
            pbit = *rdata;
            if (pbit > 128)
                goto formerr;
            pbyte = (pbit & ~7) / 8;
            rdata++;

            /** address suffix: provided only when prefix len != 128 */
            if (pbit < 128) {
                if (rdata + pbyte >= edata)
                    goto formerr;
                memset(&a, 0, sizeof(a));
                memcpy(&a.s6_addr[pbyte], rdata, sizeof(a) - pbyte);
	            memcpy(&sa6.sin6_addr, &a, NS_IN6ADDRSZ);
	 	        INET_NTOP(AF_INET6, ((struct sockaddr *)&sa6), sizeof(sa6), buf, buflen, addr);
                addlen(strlen(buf), &buf, &buflen);
                rdata += sizeof(a) - pbyte;
            }

            /** prefix name: provided only when prefix len > 0 */
            if (pbit == 0)
                break;
            if (rdata >= edata)
                goto formerr;
            T(addstr(" ", 1, &buf, &buflen));
            T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

            break;
        }
#endif

    case ns_t_opt:{
            len = SPRINTF((tmp, "%u bytes", class_h));
            T(addstr(tmp, len, &buf, &buflen));
            break;
        }

    default:
        comment = "unknown RR type";
        goto hexify;
    }
    return (buf - obuf);
  formerr:
    comment = "RR format error";
  hexify:{
        int             n, m;
        char           *p;

        len = SPRINTF((tmp, "\\# %u (\t; %s", (unsigned)(edata - rdata), comment));
        T(addstr(tmp, len, &buf, &buflen));
        while (rdata < edata) {
            p = tmp;
            p += SPRINTF((p, "\n\t"));
            spaced = 0;
            n = MIN(16, edata - rdata);
            for (m = 0; m < n; m++)
                p += SPRINTF((p, "%02x ", rdata[m]));
            T(addstr(tmp, p - tmp, &buf, &buflen));
            if (n < 16) {
                T(addstr(")", 1, &buf, &buflen));
                T(addtab(p - tmp + 1, 48, spaced, &buf, &buflen));
            }
            p = tmp;
            p += SPRINTF((p, "; "));
            for (m = 0; m < n; m++)
                *p++ = (isascii(rdata[m]) && isprint(rdata[m]))
                    ? rdata[m]
                    : '.';
            T(addstr(tmp, p - tmp, &buf, &buflen));
            rdata += n;
        }
        return (buf - obuf);
    }
}


/*
 * Private. 
 */

/*
 * size_t
 * prune_origin(name, origin)
 *      Find out if the name is at or under the current origin.
 * return:
 *      Number of characters in name before start of origin,
 *      or length of name if origin does not match.
 * notes:
 *      This function should share code with samedomain().
 */
static          size_t
prune_origin(const char *name, const char *origin)
{
    const char     *oname = name;

    while (*name != '\0') {
        if (origin != NULL && ns_samename(name, origin) == 1)
            return (name - oname - (name > oname));
        while (*name != '\0') {
            if (*name == '\\') {
                name++;
                /*
                 * XXX need to handle \nnn form. 
                 */
                if (*name == '\0')
                    break;
            } else if (*name == '.') {
                name++;
                break;
            }
            name++;
        }
    }
    return (name - oname);
}

/*
 * int
 * charstr(rdata, edata, buf, buflen)
 *      Format a <character-string> into the presentation buffer.
 * return:
 *      Number of rdata octets consumed
 *      0 for protocol format error
 *      -1 for output buffer error
 * side effects:
 *      buffer is advanced on success.
 */
static int
charstr(const u_char * rdata, const u_char * edata, char **buf,
        size_t * buflen)
{
    const u_char   *odata = rdata;
    size_t          save_buflen = *buflen;
    char           *save_buf = *buf;

    if (addstr("\"", 1, buf, buflen) < 0)
        goto enospc;
    if (rdata < edata) {
        int             n = *rdata;

        if (rdata + 1 + n <= edata) {
            rdata++;
            while (n-- > 0) {
                if (strchr("\n\"\\", *rdata) != NULL)
                    if (addstr("\\", 1, buf, buflen) < 0)
                        goto enospc;
                if (addstr((const char *) rdata, 1, buf, buflen) < 0)
                    goto enospc;
                rdata++;
            }
        }
    }
    if (addstr("\"", 1, buf, buflen) < 0)
        goto enospc;
    return (rdata - odata);
  enospc:
    errno = ENOSPC;
    *buf = save_buf;
    *buflen = save_buflen;
    return (-1);
}

static int
addname(const u_char * msg, size_t msglen,
        const u_char ** pp, const char *origin,
        char **buf, size_t * buflen)
{
    size_t          newlen, save_buflen = *buflen;
    char           *save_buf = *buf;
    int             n;

    n = dn_expand(msg, msg + msglen, *pp, *buf, *buflen);
    if (n < 0)
        goto enospc;            /* Guess. */
    newlen = prune_origin(*buf, origin);
    if (**buf == '\0') {
        goto root;
    } else if (newlen == 0U) {
        /*
         * Use "@" instead of name. 
         */
        if (newlen + 2 > *buflen)
            goto enospc;        /* No room for "@\0". */
        (*buf)[newlen++] = '@';
        (*buf)[newlen] = '\0';
    } else {
        if (((origin == NULL || origin[0] == '\0') ||
             (origin[0] != '.' && origin[1] != '\0' &&
              (*buf)[newlen] == '\0')) && (*buf)[newlen - 1] != '.') {
            /*
             * No trailing dot. 
             */
          root:
            if (newlen + 2 > *buflen)
                goto enospc;    /* No room for ".\0". */
            (*buf)[newlen++] = '.';
            (*buf)[newlen] = '\0';
        }
    }
    *pp += n;
    addlen(newlen, buf, buflen);
    **buf = '\0';
    return (newlen);
  enospc:
    errno = ENOSPC;
    *buf = save_buf;
    *buflen = save_buflen;
    return (-1);
}

static void
addlen(size_t len, char **buf, size_t * buflen)
{
    if (len <= *buflen) {
        //INSIST(len <= *buflen);
        *buf += len;
        *buflen -= len;
    }
}

static int
addstr(const char *src, size_t len, char **buf, size_t * buflen)
{
    if (len >= *buflen) {
        errno = ENOSPC;
        return (-1);
    }
    memcpy(*buf, src, len);
    addlen(len, buf, buflen);
    **buf = '\0';
    return (0);
}

static int
addtab(size_t len, size_t target, int spaced, char **buf, size_t * buflen)
{
    size_t          save_buflen = *buflen;
    char           *save_buf = *buf;
    int             t;

    if (spaced || len >= target - 1) {
        T(addstr("  ", 2, buf, buflen));
        spaced = 1;
    } else {
        for (t = (target - len - 1) / 8; t >= 0; t--)
            if (addstr("\t", 1, buf, buflen) < 0) {
                *buflen = save_buflen;
                *buf = save_buf;
                return (-1);
            }
        spaced = 0;
    }
    return (spaced);
}
