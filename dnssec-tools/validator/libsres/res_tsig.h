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
#ifndef __RES_TSIG_H__
#define __RES_TSIG_H__

#define SR_TS_UNSET             0
#define SR_TS_OK                1
#define SR_TS_FAIL              -2
#define SR_TS_CALL_ERROR        -3

#define TSIG_ALG_HMAC_MD5       1 
#define TSIG_ALG_HMAC_SHA1      2
#define TSIG_ALG_HMAC_SHA256    3

struct ns_tsig {
    unsigned char name_n[NS_MAXCDNAME];
    unsigned char alg_n[NS_MAXCDNAME];
    u_char *key;
    size_t keylen;
    short alg;
    u_int16_t fudge;
    u_int16_t mac_size;
    u_int16_t rdatalen;
    int buf_size;
};

struct ns_tsig*  clone_ns_tsig(struct ns_tsig *tsig);

int             res_tsig_sign(u_char * query,
                              size_t query_length,
                              struct name_server *ns,
                              u_char ** signed_query,
                              size_t *signed_length);


int             res_free_ns_tsig(struct ns_tsig *tsig);

int             res_tsig_verifies(struct name_server *respondent,
                                  u_char * answer, size_t answer_length);

#endif
