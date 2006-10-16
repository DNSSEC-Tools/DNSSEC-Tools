/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#include "validator-config.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdio.h>

#include <arpa/nameser.h>
#include <resolver.h>
#include <validator.h>
#include "val_parse.h"
#include "val_support.h"
#include "val_crypto.h"

/*
 * From RFC 4034
 * Assumes that int is at least 16 bits.
 * First octet of the key tag is the most significant 8 bits of the
 * return value;
 * Second octet of the key tag is the least significant 8 bits of the
 * return value.
 */

unsigned int
keytag(const unsigned char key[],       /* the RDATA part of the DNSKEY RR */
       unsigned int keysize     /* the RDLENGTH */
    )
{
    unsigned long   ac;         /* assumed to be 32 bits or larger */
    int             i;          /* loop index */

    if (key == NULL)
        return 0;

    for (ac = 0, i = 0; i < keysize; ++i)
        ac += (i & 1) ? key[i] : key[i] << 8;
    ac += (ac >> 16) & 0xFFFF;
    return ac & 0xFFFF;
}

/*
 * Parse a domain name
 * Returns the number of bytes used by the domain name
 */
int
val_parse_dname(const unsigned char *buf, int buflen, int offset,
                char *dname)
{
    int             newoffset;
    int             nindex = 0;
    int             count = 0;
    int             compressed = 0;

    if ((dname == NULL) || (buf == NULL) || (offset > buflen))
        return 0;

    newoffset = offset;
    bzero(dname, sizeof(dname));

    while ((newoffset < buflen) && (buf[newoffset] != 0)) {
        int             len, i;

        if ((buf[newoffset] & 0xC0) == 0xC0) {  /* domain name compression */

            newoffset =
                ((buf[newoffset] & 0x3F) << 8) + buf[newoffset + 1];

            if (!compressed) {
                count += 1;
            }
            compressed = 1;
            continue;
        }

        len = buf[newoffset];

        for (i = 1; (i <= len) && ((newoffset + i) < buflen); i++) {
            dname[nindex++] = buf[newoffset + i];
        }

        dname[nindex++] = '.';
        dname[nindex] = '\0';

        if (!compressed) {
            count += (len + 1);
        }
        newoffset += (len + 1);
    }

    return count + 1;
}

/*
 * Parse rdata portion of a DNSKEY Resource Record.
 * Returns the number of bytes in the DNSKEY rdata portion that were parsed.
 */
int
val_parse_dnskey_rdata(const unsigned char *buf, int buflen,
                       val_dnskey_rdata_t * rdata)
{
    int             index = 0;
    const u_char   *cp;

    if (!rdata || !buf)
        return -1;

    if (index + 4 > buflen)
        return -1;

    cp = buf;
    VAL_GET16(rdata->flags, cp);
    index += 2;

    rdata->protocol = (u_int8_t) (buf[index]);
    index += 1;

    rdata->algorithm = (u_int8_t) (buf[index]);
    index += 1;

    rdata->public_key_len = (buflen > index) ? (buflen - index) : 0;

    if (rdata->public_key_len > 0) {
        rdata->public_key =
            (u_char *) MALLOC(rdata->public_key_len * sizeof(u_char));
        if (rdata->public_key == NULL)
            return -1;          /* xxx-check: should we return bytes parsed so far? */
        memcpy(rdata->public_key, buf + index, rdata->public_key_len);
        index += rdata->public_key_len;
    } else
        rdata->public_key = NULL;

    if (rdata->algorithm == ALG_RSAMD5) {
        rdata->key_tag = rsamd5_keytag(buf, buflen);
    } else {
        rdata->key_tag = keytag(buf, buflen);
    }


    return index;
}


#define TOK_IN_STR() do {                                               \
	int i = 0;                                                      \
	token[0] = '\0';						\
	while ((sp < ep) && isspace(*sp))                               \
            sp++;                                                       \
	if (sp >= ep)							\
            return VAL_BAD_ARGUMENT;                                    \
	while ((sp < ep) && !isspace(*sp) && (i<sizeof(token))) {       \
            token[i++] = *sp++;                                         \
	}                                                               \
	token[i] = '\0';						\
    } while (0)

/*
 * Parse the dnskey from the string. The string contains the flags, 
 * protocol, algorithm and the base64 key delimited by spaces.
 */
int
val_parse_dnskey_string(char *keystr, int keystrlen,
                        val_dnskey_rdata_t ** dnskey_rdata)
{
    char           *sp = keystr;
    char           *ep = sp + keystrlen + 1;
    char            token[NS_MAXDNAME];
    char           *keyptr = NULL;
    char           *cp;
    int             bufsize;
    int             buflen;
    u_char         *buf;
    u_char         *bp;
    u_int16_t       flags;

    if ((ep - sp > NS_MAXDNAME) || (dnskey_rdata == NULL))
        return VAL_BAD_ARGUMENT;

    (*dnskey_rdata) =
        (val_dnskey_rdata_t *) MALLOC(sizeof(val_dnskey_rdata_t));
    if ((*dnskey_rdata) == NULL)
        return VAL_OUT_OF_MEMORY;

    TOK_IN_STR();
    (*dnskey_rdata)->flags = atoi(token);

    TOK_IN_STR();
    (*dnskey_rdata)->protocol = atoi(token);

    TOK_IN_STR();
    (*dnskey_rdata)->algorithm = atoi(token);

    /*
     * What follows is the public key in base64.
     */

    /*
     * Remove any white spaces
     */
    for (cp = sp; sp < ep; sp++) {
        if (!isspace(*sp)) {
            if (keyptr == NULL)
                keyptr = cp;
            if (cp != sp)
                *cp = *sp;
            cp++;
        }
    }
    *cp = '\0';

    bufsize = ep - keyptr;
    (*dnskey_rdata)->public_key =
        (u_char *) MALLOC(bufsize * sizeof(char));
    if ((*dnskey_rdata)->public_key == NULL) {
        FREE(*dnskey_rdata);
        *dnskey_rdata = NULL;
        return VAL_OUT_OF_MEMORY;
    }

    /*
     * decode the base64 public key 
     */
    if(((*dnskey_rdata)->public_key_len = decode_base64_key(keyptr, 
                    (*dnskey_rdata)->public_key, bufsize)) <= 0) {

        FREE((*dnskey_rdata)->public_key);
        FREE(*dnskey_rdata);
        *dnskey_rdata = NULL;
        return VAL_BAD_ARGUMENT;
    }

    /*
     * For calculating the keytag, we need the 
     * complete DNSKEY RDATA in wire format
     */
    buflen = (*dnskey_rdata)->public_key_len + sizeof(u_int16_t) +      /* flags */
        sizeof(u_int8_t) +      /* proto */
        sizeof(u_int8_t);       /*algo */
    buf = (u_char *) MALLOC(buflen * sizeof(u_char));
    if (buf == NULL) {
        FREE((*dnskey_rdata)->public_key);
        FREE(*dnskey_rdata);
        *dnskey_rdata = NULL;
        return VAL_OUT_OF_MEMORY;
    }

    bp = buf;
    flags = (*dnskey_rdata)->flags;

    memcpy(bp, &flags, sizeof(u_int16_t));
    bp += sizeof(u_int16_t);
    *bp = (*dnskey_rdata)->protocol;
    bp++;
    *bp = (*dnskey_rdata)->algorithm;
    bp++;
    memcpy(bp, (*dnskey_rdata)->public_key,
           (*dnskey_rdata)->public_key_len);

    /*
     * Calculate the keytag 
     */
    if ((*dnskey_rdata)->algorithm == ALG_RSAMD5) {
        (*dnskey_rdata)->key_tag = rsamd5_keytag(buf, buflen);
    } else {
        (*dnskey_rdata)->key_tag = keytag(buf, buflen);
    }
    (*dnskey_rdata)->next = NULL;
    FREE(buf);

    return VAL_NO_ERROR;
}


/*
 * Parse rdata portion of an RRSIG Resource Record.
 * Returns the number of bytes in the RRSIG rdata portion that were parsed.
 * Caller assumes responsiblity for allocated dnskey_rdata memory.
 */
int
val_parse_rrsig_rdata(const unsigned char *buf, int buflen,
                      val_rrsig_rdata_t * rdata)
{
    int             index = 0;
    const u_char   *cp;

    if (!rdata || !buf)
        return -1;

    if (index + 18 > buflen)
        return -1;

    cp = buf;
    VAL_GET16(rdata->type_covered, cp);
    index += 2;

    rdata->algorithm = (u_int8_t) (buf[index]);
    index += 1;

    rdata->labels = (u_int8_t) (buf[index]);
    index += 1;

    cp = (buf + index);
    VAL_GET32(rdata->orig_ttl, cp);
    index += 4;

    VAL_GET32(rdata->sig_expr, cp);
    index += 4;

    VAL_GET32(rdata->sig_incp, cp);
    index += 4;

    VAL_GET16(rdata->key_tag, cp);
    index += 2;

    index +=
        val_parse_dname(buf, buflen, index, (char *) rdata->signer_name);

    rdata->signature_len = (buflen > index) ? (buflen - index) : 0;

    if (rdata->signature_len > 0) {
        rdata->signature =
            (u_char *) MALLOC(rdata->signature_len * sizeof(u_char));
        if (rdata->signature == NULL)
            return -1;          /* xxx-check: should we return bytes parsed so far? */
        memcpy(rdata->signature, buf + index, rdata->signature_len);
        index += rdata->signature_len;
    } else
        rdata->signature = NULL;

    return index;
}

/*
 * Parse rdata portion of a DS Resource Record.
 * Returns the number of bytes in the DS rdata portion that were parsed.
 */
int
val_parse_ds_rdata(const unsigned char *buf, int buflen,
                   val_ds_rdata_t * rdata)
{
    int             index = 0;
    const u_char   *cp = buf;

    if (!rdata || !buf)
        return -1;

    if (index + 2 + 1 + 1 > buflen)
        return -1;

    VAL_GET16(rdata->d_keytag, cp);
    index += 2;

    rdata->d_algo = (u_int8_t) (buf[index]);
    index += 1;

    rdata->d_type = (u_int8_t) (buf[index]);
    index += 1;

    /*
     * Only SHA-1 is understood 
     */
    if (rdata->d_type != ALG_DS_HASH_SHA1)
        return -1;

    rdata->d_hash_len = SHA_DIGEST_LENGTH;
    rdata->d_hash =
        (u_int8_t *) MALLOC(rdata->d_hash_len * sizeof(u_int8_t));
    if (rdata->d_hash == NULL)
        return -1;

    if (index + rdata->d_hash_len > buflen)
        return -1;

    memcpy(rdata->d_hash, buf + index, rdata->d_hash_len);
    index += rdata->d_hash_len;

    return index;
}

/*
 * Compare if two public keys are identical 
 * Return 0 if they are equal, 1 if not.
 */
int
dnskey_compare(val_dnskey_rdata_t * key1, val_dnskey_rdata_t * key2)
{

    if (!key1 || !key2)
        return 1;

    if ((key1->flags == key2->flags) &&
        (key1->protocol == key2->protocol) &&
        (key1->algorithm == key2->algorithm) &&
        (key1->key_tag == key2->key_tag) &&
        (key1->public_key_len == key2->public_key_len) &&
        (!memcmp
         (key1->public_key, key2->public_key, key1->public_key_len)))
        return 0;
    return 1;
}

#ifdef LIBVAL_NSEC3
val_nsec3_rdata_t *
val_parse_nsec3_rdata(u_int8_t * rr_rdata, u_int16_t rdatalen,
                      val_nsec3_rdata_t * nd)
{
    u_int8_t       *cp;
    u_int8_t        nexthashlen;
    u_int8_t       *nexthash;

    if (nd == NULL)
        return NULL;

    cp = rr_rdata;

    if (rdatalen < 5) {
        /*
         * somethings wrong 
         */
        return NULL;
    }
    nd->alg = *cp;
    memcpy(&nd->iterations, cp, 4 * sizeof(u_int8_t));
    nd->optout = (nd->iterations & 0x00800000) ? 1 : 0;
    nd->iterations &= 0x007fffff;
    cp += 4;

    nd->saltlen = *cp;
    cp += 1;
    if ((cp - rr_rdata) >= rdatalen)
        return NULL;

    nd->salt = cp;
    cp += nd->saltlen;
    if ((cp - rr_rdata) >= rdatalen)
        return NULL;

    nexthashlen = *cp;
    cp += 1;
    if ((cp - rr_rdata) >= rdatalen)
        return NULL;

    nexthash = cp;
    cp += nexthashlen;
    if ((cp - rr_rdata) >= rdatalen)
        return NULL;

    base32hex_encode(nexthash, nexthashlen, &(nd->nexthash),
                     &(nd->nexthashlen));

    nd->bit_field = cp - rr_rdata;
    if ((cp - rr_rdata) >= rdatalen)
        return NULL;

    return nd;
}

#endif
