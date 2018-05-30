/*
 * Copyright (c) 1995, 1996, 1997 by Trusted Information Systems, Inc.
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
#include "validator-internal.h"

#include <openssl/ossl_typ.h>
#include <openssl/hmac.h>

#include "res_tsig.h"
#include "res_support.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

static int
decode_tsig_key(char *keystr, u_char *key, size_t keysize)
{
    BIO            *b64;
    BIO            *mem;
    BIO            *bio;
    unsigned int   len;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    mem = BIO_new_mem_buf(keystr, -1);
    bio = BIO_push(b64, mem);
    len = BIO_read(bio, key, keysize);
    BIO_free(mem);
    BIO_free(b64);
    return len;
}


struct ns_tsig *
clone_ns_tsig(struct ns_tsig *tsig)
{
    struct ns_tsig *n;

    if (tsig == NULL)
        return NULL;

    n = (struct ns_tsig *) MALLOC (sizeof (struct ns_tsig));
    if (n == NULL)
        return NULL;
    memset(n, 0, sizeof(struct ns_tsig));

    memcpy(n->name_n, tsig->name_n, sizeof(tsig->name_n));
    memcpy(n->alg_n, tsig->alg_n, sizeof(tsig->alg_n));
    n->alg = tsig->alg;
    n->fudge = tsig->fudge;
    n->mac_size = tsig->mac_size;
    n->rdatalen = tsig->rdatalen;
    n->buf_size = tsig->buf_size;

    n->key = (u_char *) MALLOC(tsig->keylen * sizeof(u_char));
    if (n->key == NULL) {
        FREE(n);
        return NULL;
    }
    memcpy(n->key, tsig->key, tsig->keylen);
    n->keylen = tsig->keylen;
    return n;
}

/*
 * Set the TSIG params for this name server
 * Format is:
 * name:alg:fudge:key
 */
int
res_set_ns_tsig(struct name_server *ns, char *tsigstr)
{
    struct ns_tsig *tsig = NULL;
    int rr_hlen, rr_rdatalen;

    char *name_s; 
    char *fudge_s;
    char *key_s;
    const char *alg_s; 
    int i;

    char *buf, *c, *n;
    if (ns == NULL || tsigstr == NULL)
        return SR_TS_CALL_ERROR;

    tsig = (struct ns_tsig *) MALLOC (sizeof(struct ns_tsig));
    if (tsig == NULL)
        return SR_TS_FAIL;

    buf = strdup(tsigstr);
    if (buf == NULL) {
        FREE(tsig);
        return SR_TS_FAIL;
    }
    c = buf;

    /* Parse the tsig string */
    name_s = c;
    if (!(n = strchr(c,':'))) {
        goto err;
    }
    *n = '\0';
    c = n+1;

    alg_s = c;
    if (!(n = strchr(c,':'))) {
        goto err;
    }
    *n = '\0';
    c = n+1;

    fudge_s = c;
    if (!(n = strchr(c,':'))) {
        goto err;
    }
    *n = '\0';
    c = n+1;
    key_s = c;

    for(i = 0; name_s[i]; i++){
        if (isupper(name_s[i]))
            name_s[i] = tolower(name_s[i]);
    }
    if (ns_name_pton(name_s, tsig->name_n, sizeof(tsig->name_n)) == -1) { 
        goto err;
    }

    /* check for alg sanity */
    if (!strcmp(alg_s, "")) {
        alg_s = TSIG_ALG_HMAC_MD5_STR;
        tsig->alg = TSIG_ALG_HMAC_MD5;
        tsig->mac_size = MD5_DIGEST_LENGTH;
    } else if (!strcmp(alg_s, TSIG_ALG_HMAC_MD5_STR)) {
        tsig->alg = TSIG_ALG_HMAC_MD5;
        tsig->mac_size = MD5_DIGEST_LENGTH;
    } else if (!strcmp(alg_s, TSIG_ALG_HMAC_SHA1_STR)) {
        tsig->alg = TSIG_ALG_HMAC_SHA1;
        tsig->mac_size = SHA_DIGEST_LENGTH;
    } else if (!strcmp(alg_s, TSIG_ALG_HMAC_SHA256_STR)) {
        tsig->alg = TSIG_ALG_HMAC_SHA256;
        tsig->mac_size = SHA256_DIGEST_LENGTH;
    } else {
        goto err;
    }
    for(i = 0; alg_s[i]; i++){
        if (isupper(alg_s[i]))
            name_s[i] = tolower(alg_s[i]);
    }
    if (ns_name_pton(alg_s, tsig->alg_n, sizeof(tsig->alg_n)) == -1) { 
        goto err;
    }
   
    /* check for fudge sanity */ 
    if (0 == (tsig->fudge = (u_int16_t)atoi(fudge_s))) {
       tsig->fudge = TSIG_FUDGE_DEFAULT; 
    }

    /* Decode the base64 key */
    tsig->key = (u_char *) MALLOC (strlen(key_s)+1);
    if (tsig->key == NULL) {
        goto err;
    }
    if ((tsig->keylen = decode_tsig_key(key_s, tsig->key, strlen(key_s))) <= 0) {
        FREE(tsig->key);
        goto err;
    }

    rr_hlen = wire_name_length(tsig->name_n) + /*Name*/
                     sizeof(u_int16_t) +  /*type*/
                     sizeof(u_int16_t) +  /*class*/
                     sizeof(u_int32_t);  /*ttl*/

    rr_rdatalen = wire_name_length(tsig->alg_n) + /*alg*/
                    sizeof(u_int32_t) + sizeof(u_int16_t) + /*time signed is u_int48_t*/
                    sizeof(u_int16_t) + /*fudge*/
                    sizeof(u_int16_t) + /*mac size*/
                    tsig->mac_size + /*mac*/
                    sizeof(u_int16_t) + /*original ID*/
                    sizeof(u_int16_t) + /*error*/
                    sizeof(u_int16_t) ; /*other len*/

    tsig->rdatalen = rr_rdatalen;
    tsig->buf_size = rr_hlen + sizeof(u_int16_t) + rr_rdatalen;

    ns->ns_tsig = tsig;
    ns->ns_security_options |= ZONE_USE_TSIG;

    free(buf);
    return SR_TS_OK;

err:
    free(buf);
    FREE(tsig);
    return SR_TS_FAIL;

}

int
res_free_ns_tsig(struct ns_tsig *tsig)
{
    if (tsig != NULL) {
        if (tsig->key)
            FREE(tsig->key);
        FREE(tsig);
    }

    return SR_TS_OK;
}


int
res_tsig_sign(u_char * query,
              size_t query_length,
              struct name_server *ns,
              u_char ** signed_query, 
              size_t *signed_length)
{
    int buflen;
    u_char *cp, *p;
    u_char *hp;
    HEADER *header;
    struct timeval now;
    HMAC_CTX *ctx;
    const EVP_MD *md;
    u_char hash[MAX_DIGEST_LENGTH];
    unsigned int len;
    u_int16_t arcount;

    if (!signed_query || !signed_length)
        return SR_TS_FAIL;
    *signed_query = NULL;
    *signed_length = 0;

    if (query && query_length && query_length > sizeof(HEADER)) {
        if (!(ns->ns_security_options & ZONE_USE_TSIG)) {
            *signed_query = (u_char *) MALLOC(query_length * sizeof(u_char));
            if (*signed_query == NULL) 
                return SR_TS_FAIL;
            memcpy(*signed_query, query, query_length * sizeof(u_char));
            *signed_length = query_length;
            return SR_TS_OK;
        } else if (!ns->ns_tsig) {
            return SR_TS_FAIL;
        }

        switch(ns->ns_tsig->alg) {
            case TSIG_ALG_HMAC_MD5:
               md = EVP_md5();
               break; 
            case TSIG_ALG_HMAC_SHA1:
               md = EVP_sha1();
               break; 
            case TSIG_ALG_HMAC_SHA256:
               md = EVP_sha256();
               break; 
            default:
               return SR_TS_FAIL;
        } 

        ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, ns->ns_tsig->key, ns->ns_tsig->keylen,
                md, NULL);

        /* Create a TSIG RR and add it to the additional section */
        buflen = query_length + ns->ns_tsig->buf_size;
        *signed_query = (u_char *) MALLOC(buflen * sizeof(u_char));
        if (*signed_query == NULL) 
            return SR_TS_FAIL;
        *signed_length = buflen;
        cp = *signed_query;

        p = cp;
        memcpy(cp, query, query_length * sizeof(u_char));
        cp += query_length;
        HMAC_Update(ctx, p, cp-p); 

        /* Bump up the additional section count */
        header = (HEADER *) p;
        arcount = ntohs(header->arcount);
        arcount++;
        header->arcount = htons(arcount);;

        p = cp;
        memcpy(cp, ns->ns_tsig->name_n, wire_name_length(ns->ns_tsig->name_n));
        cp += wire_name_length(ns->ns_tsig->name_n);
        HMAC_Update(ctx, p, cp-p); 

        /* don't digest type */
        RES_PUT16(ns_t_tsig, cp);

        p = cp;
        RES_PUT16(ns_t_any, cp);
        RES_PUT32(0, cp);
        HMAC_Update(ctx, p, cp-p); 

        /* don't digest rdatalen */
        RES_PUT16(ns->ns_tsig->rdatalen, cp);

        p = cp;
        memcpy(cp, ns->ns_tsig->alg_n, wire_name_length(ns->ns_tsig->alg_n));
        cp += wire_name_length(ns->ns_tsig->alg_n);
        HMAC_Update(ctx, p, cp-p); 

        gettimeofday(&now, NULL);
        p = cp;
        RES_PUT48((u_int64_t)now.tv_sec, cp);
        RES_PUT16(ns->ns_tsig->fudge, cp);
        HMAC_Update(ctx, p, cp-p); 

        /* don't digest the mac_size */
        RES_PUT16(ns->ns_tsig->mac_size, cp);

        /* save the location for the hmac */
        hp = cp;
        cp += ns->ns_tsig->mac_size;
    
        /* don't digest the header ID */
        RES_PUT16(ntohs(header->id), cp);

        p = cp;
        RES_PUT16(0, cp);
        RES_PUT16(0, cp);
        HMAC_Update(ctx, p, cp-p); 

        HMAC_Final(ctx, hash, &len);

        if (len != ns->ns_tsig->mac_size) {
            FREE(*signed_query);
            *signed_query = NULL;
            return SR_TS_FAIL;
        }
        memcpy(hp, hash, len);

        HMAC_CTX_cleanup(ctx);
        return SR_TS_OK;

    } else
        return SR_TS_CALL_ERROR;
}

int
res_tsig_verifies(struct name_server *respondent,
                  u_char * answer, size_t answer_length)
{
    u_int16_t arcount;
    HEADER *header = (HEADER *) answer;

    if (!(respondent->ns_security_options & ZONE_USE_TSIG))
        return SR_TS_OK;
    else if (answer_length < sizeof(HEADER))
        return SR_TS_FAIL;
    else if (header->arcount == 0) 
        return SR_TS_FAIL;
    else {
        /* XXX Simply decrement the additional section count for now */
        arcount = ntohs(header->arcount);
        arcount--;
        header->arcount = htons(arcount);;
        res_log(NULL, LOG_INFO, "libsres: ""not checking tsig!");
    }
    return SR_TS_OK;
}
