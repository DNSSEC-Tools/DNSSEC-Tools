/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
/*
 * DESCRIPTION
 * Parsing functions for some useful RR types
 */
#include "validator-internal.h"

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

u_int16_t
keytag(const u_char key[],       /* the RDATA part of the DNSKEY RR */
       size_t keysize     /* the RDLENGTH */
    )
{
    u_int32_t   ac;         /* assumed to be 32 bits or larger */
    size_t  i;          /* loop index */

    if (key == NULL)
        return 0;

    for (ac = 0, i = 0; i < keysize; ++i)
        ac += (i & 1) ? key[i] : key[i] << 8;
    ac += (ac >> 16) & 0xFFFF;
    return ac & 0xFFFF;
}

/*
 * Parse a domain name
 */
int
val_parse_dname(const u_char *buf, size_t buflen, size_t offset,
                char *dname, size_t *dlen)
{
    size_t             newoffset;
    size_t             nindex = 0;
    size_t             count = 0;
    int                compressed = 0;

    if ((dname == NULL) || (dlen == NULL) 
            || (buf == NULL) || (offset > buflen))
        return VAL_BAD_ARGUMENT;

    newoffset = offset;
    *dname = '\0';
    *dlen = 0;

    while ((newoffset < buflen) && (buf[newoffset] != 0)) {
        size_t             len, i;

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

    *dlen = count + 1;
    return VAL_NO_ERROR;
}

/*
 * Parse rdata portion of a DNSKEY Resource Record.
 * Returns the number of bytes in the DNSKEY rdata portion that were parsed on success. 
 * Returns 0 on failure.
 */
int
val_parse_dnskey_rdata(const u_char *buf, size_t buflen,
                       val_dnskey_rdata_t * rdata)
{
    size_t index = 0;
    const u_char   *cp;

    if (!rdata || !buf)
        return VAL_BAD_ARGUMENT;

    if (index + 4 > buflen)
        return VAL_BAD_ARGUMENT;

    cp = buf;
    VAL_GET16(rdata->flags, cp);
    index += 2;

    rdata->protocol = (u_char) (buf[index]);
    index += 1;

    rdata->algorithm = (u_char) (buf[index]);
    index += 1;

    rdata->public_key_len = (buflen > index) ? (buflen - index) : 0;

    if (rdata->public_key_len > 0) {
        rdata->public_key =
            (u_char *) MALLOC(rdata->public_key_len * sizeof(u_char));
        if (rdata->public_key == NULL)
            return VAL_OUT_OF_MEMORY;
        memcpy(rdata->public_key, buf + index, rdata->public_key_len);
        index += rdata->public_key_len;
    } else
        rdata->public_key = NULL;

    if (rdata->algorithm == ALG_RSAMD5) {
        rdata->key_tag = rsamd5_keytag(buf, buflen);
    } else {
        rdata->key_tag = keytag(buf, buflen);
    }

    return VAL_NO_ERROR;
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
 * Parse the ds record from the string. The string contains 
 * the keytag, Algorithm and Digest type fields
 * delimited by spaces.
 */

int
val_parse_ds_string(char *dsstr, size_t dsstrlen,
                    val_ds_rdata_t ** ds_rdata)
{
    char           *sp = dsstr;
    char           *ep = sp + dsstrlen;
    char            token[NS_MAXDNAME];
    char           *dsptr = NULL;
    char           *cp;
    size_t          bufsize;
    int             i;

    if (dsstr == NULL || ds_rdata == NULL)
        return VAL_BAD_ARGUMENT;

    (*ds_rdata) =
        (val_ds_rdata_t *) MALLOC(sizeof(val_ds_rdata_t));
    if ((*ds_rdata) == NULL)
        return VAL_OUT_OF_MEMORY;

    TOK_IN_STR();
    (*ds_rdata)->d_keytag = (int)strtol(token, (char **)NULL, 10);

    TOK_IN_STR();
    (*ds_rdata)->d_algo = (int)strtol(token, (char **)NULL, 10);

    TOK_IN_STR();
    (*ds_rdata)->d_type = (int)strtol(token, (char **)NULL, 10);

    /*
     * What follows is the DS hash 
     */
    if (sp >= ep) {
        FREE(*ds_rdata);
        *ds_rdata = NULL;
        return VAL_CONF_PARSE_ERROR;
    }

    /*
     * Remove any white spaces
     */
    for (cp = sp; sp < ep; sp++) {
        if (!isspace(*sp)) {
            if (dsptr == NULL)
                dsptr = cp;
            if (cp != sp)
                *cp = *sp;
            cp++;
        }
    }
    *cp = '\0';
    ep = cp;

    bufsize = ep - dsptr;
    if (bufsize == 0) {
        FREE(*ds_rdata);
        *ds_rdata = NULL;
        return VAL_CONF_PARSE_ERROR;
    }
    (*ds_rdata)->d_hash =
        (u_char *) MALLOC(bufsize * sizeof(u_char));
    if ((*ds_rdata)->d_hash == NULL) {
        FREE(*ds_rdata);
        *ds_rdata = NULL;
        return VAL_OUT_OF_MEMORY;
    }

    /* Convert the hex string to a byte string */
    i = 0;
    while (dsptr < ep && i < bufsize) { 
        char hexdigit[3];
        memcpy(hexdigit, dsptr, 2);
        hexdigit[2] = '\0';
        (*ds_rdata)->d_hash[i++] = (u_char)strtol(hexdigit, NULL, 16);
        dsptr = dsptr+2;
    }
    (*ds_rdata)->d_hash_len = i;
    
    return VAL_NO_ERROR;
}

/*
 * Parse the dnskey from the string. The string contains the flags, 
 * protocol, algorithm and the base64 key delimited by spaces.
 */
int
val_parse_dnskey_string(char *keystr, size_t keystrlen,
                        val_dnskey_rdata_t ** dnskey_rdata)
{
    char           *sp = keystr;
    char           *ep = sp + keystrlen;
    char            token[NS_MAXDNAME];
    char           *keyptr = NULL;
    char           *cp;
    size_t         bufsize;
    size_t         buflen;
    u_char         *buf;
    u_char         *bp;
    u_int16_t       flags;

    if (keystr == NULL || dnskey_rdata == NULL)
        return VAL_BAD_ARGUMENT;

    (*dnskey_rdata) =
        (val_dnskey_rdata_t *) MALLOC(sizeof(val_dnskey_rdata_t));
    if ((*dnskey_rdata) == NULL)
        return VAL_OUT_OF_MEMORY;

    TOK_IN_STR();
    (*dnskey_rdata)->flags = (int)strtol(token, (char **)NULL, 10);

    TOK_IN_STR();
    (*dnskey_rdata)->protocol = (int)strtol(token, (char **)NULL, 10);

    TOK_IN_STR();
    (*dnskey_rdata)->algorithm = (int)strtol(token, (char **)NULL, 10);

    if (sp >= ep) {
        FREE(*dnskey_rdata);
        *dnskey_rdata = NULL;
        return VAL_CONF_PARSE_ERROR;
    }
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
    ep = cp; /* this is the last character in the public key */

    if (keyptr == NULL || keyptr >= ep) {
        FREE(*dnskey_rdata);
        *dnskey_rdata = NULL;
        return VAL_CONF_PARSE_ERROR;
    }
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
    if (((*dnskey_rdata)->public_key_len = 
                decode_base64_key(keyptr, (*dnskey_rdata)->
                                  public_key, bufsize)) <= 0) {

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
        sizeof(u_char) +      /* proto */
        sizeof(u_char);       /*algo */
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
val_parse_rrsig_rdata(const u_char *buf, size_t buflen,
                      val_rrsig_rdata_t * rdata)
{
    size_t index = 0;
    const u_char   *cp;
    size_t namelen;
    int retval;

    if (!rdata || !buf)
        return VAL_BAD_ARGUMENT;

    if (index + 18 > buflen)
        return VAL_BAD_ARGUMENT;

    cp = buf;
    VAL_GET16(rdata->type_covered, cp);
    index += 2;

    rdata->algorithm = (u_char) (buf[index]);
    index += 1;

    rdata->labels = (u_char) (buf[index]);
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

    if (VAL_NO_ERROR != 
            (retval = val_parse_dname(buf, buflen, index, 
                        (char *) rdata->signer_name,
                        &namelen))) {
        return retval;
    }
    index += namelen;

    rdata->signature_len = (buflen > index) ? (buflen - index) : 0;

    if (rdata->signature_len > 0) {
        rdata->signature =
            (u_char *) MALLOC(rdata->signature_len * sizeof(u_char));
        if (rdata->signature == NULL)
            return VAL_OUT_OF_MEMORY;
        memcpy(rdata->signature, buf + index, rdata->signature_len);
        index += rdata->signature_len;
    } else
        rdata->signature = NULL;

    return VAL_NO_ERROR;
}

/*
 * Parse rdata portion of a DS Resource Record.
 */
int
val_parse_ds_rdata(const u_char *buf, size_t buflen,
                   val_ds_rdata_t * rdata)
{
    size_t index = 0;
    const u_char   *cp = buf;

    if (!rdata || !buf)
        return VAL_BAD_ARGUMENT;

    if (index + 2 + 1 + 1 > buflen)
        return VAL_BAD_ARGUMENT;

    VAL_GET16(rdata->d_keytag, cp);
    index += 2;

    rdata->d_algo = (u_char) (buf[index]);
    index += 1;

    rdata->d_type = (u_char) (buf[index]);
    index += 1;

    /*
     * Only SHA-1 is understood 
     */
    if (rdata->d_type == ALG_DS_HASH_SHA1)
        rdata->d_hash_len = SHA_DIGEST_LENGTH;
    else if (rdata->d_type == ALG_DS_HASH_SHA256)
        rdata->d_hash_len = SHA256_DIGEST_LENGTH;
    else
        return VAL_NOT_IMPLEMENTED;

    if (index + rdata->d_hash_len > buflen)
        return VAL_BAD_ARGUMENT;

    rdata->d_hash =
        (u_char *) MALLOC(rdata->d_hash_len * sizeof(u_char));
    if (rdata->d_hash == NULL)
        return VAL_OUT_OF_MEMORY;

    memcpy(rdata->d_hash, buf + index, rdata->d_hash_len);
    index += rdata->d_hash_len;

    return VAL_NO_ERROR;
}


#ifdef LIBVAL_NSEC3
val_nsec3_rdata_t *
val_parse_nsec3_rdata(u_char * rr_rdata, size_t rdatalen,
                      val_nsec3_rdata_t * nd)
{
    u_char       *cp;
    size_t        nexthashlen, retlen;
    u_char       *nexthash;

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
    cp += 1;
    nd->flags = *cp;
    cp += 1;
    VAL_GET16(nd->iterations, cp);
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
    /* note that the next check does not check >= */
    /* this is because the bit field can be empty */
    if ((cp - rr_rdata) > rdatalen)
        return NULL;

    base32hex_encode(nexthash, nexthashlen, &(nd->nexthash),
                     &retlen);
    nd->nexthashlen = (u_char)retlen;
    if (retlen > nd->nexthashlen)
        return NULL;

    /* bit field can be empty */
    if (cp - rr_rdata == rdatalen) {
        nd->bit_field = 0;
    } else { 
        nd->bit_field = cp - rr_rdata;
    }

    return nd;
}

#endif
