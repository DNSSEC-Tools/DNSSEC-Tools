/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdio.h>

#include <validator.h>
#include "val_parse.h"
#include "crypto/val_rsamd5.h"
#include "val_support.h"

#include <openssl/bio.h>
#include <openssl/evp.h>

/*
 * From RFC 4034
 * Assumes that int is at least 16 bits.
 * First octet of the key tag is the most significant 8 bits of the
 * return value;
 * Second octet of the key tag is the least significant 8 bits of the
 * return value.
 */

unsigned int
keytag (
	const unsigned char key[],  /* the RDATA part of the DNSKEY RR */
	unsigned int keysize  /* the RDLENGTH */
	)
{
    unsigned long ac;     /* assumed to be 32 bits or larger */
    int i;                /* loop index */
    
    for ( ac = 0, i = 0; i < keysize; ++i )
	ac += (i & 1) ? key[i] : key[i] << 8;
    ac += (ac >> 16) & 0xFFFF;
    return ac & 0xFFFF;
}

/*
 * Parse a domain name
 * Returns the number of bytes used by the domain name
 */
int val_parse_dname(const unsigned char *buf, int buflen, int offset,
			   char *dname)
{
    int newoffset;
    int nindex = 0;
    int count = 0;
    int compressed = 0;

    newoffset = offset;
    bzero(dname, sizeof(dname));

    while (buf[newoffset] != 0) {
	int len, i;

	if ((buf[newoffset] & 0x00C0) == 0xC0) { /* domain name compression */

	    newoffset = ((buf[newoffset] & 0x3F) << 8) + buf[newoffset+1];

	    if (!compressed) {
		count += 1;
	    }
	    compressed = 1;
	    continue;
	}

	len = buf[newoffset];

	for (i=1; i<=len; i++) {
	    dname[nindex++] = buf[newoffset+i];
	}

	dname[nindex++] = '.';

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
int val_parse_dnskey_rdata (const unsigned char *buf, int buflen,
			    val_dnskey_rdata_t *rdata)
{
    int index = 0;
    u_char *cp;

    if (!rdata) return -1;

    cp = (u_char *) buf;
    NS_GET16(rdata->flags, cp);
    index += 2;

    rdata->protocol = (u_int8_t)(buf[index]);
    index += 1;

    rdata->algorithm = (u_int8_t)(buf[index]);
    index += 1;

    rdata->public_key_len = (buflen > index) ? (buflen - index): 0;

    if (rdata->public_key_len > 0) {
        rdata->public_key = (u_char *) MALLOC (rdata->public_key_len * sizeof(u_char));
        memcpy (rdata->public_key, buf + index, rdata->public_key_len);
        index += rdata->public_key_len;
    }
	else
		rdata->public_key = NULL;

    if (rdata->algorithm == 1) {
	rdata->key_tag = rsamd5_keytag(buf, buflen);
    }
    else {
	rdata->key_tag = keytag(buf, buflen);
    }
	

    return index;
}


#define TOK_IN_STR() do {					\
	int i = 0;								\
	strcpy (token, "");						\
	while ((sp < ep) && isspace(*sp))		\
		sp++;								\
	if (sp >= ep)							\
		return BAD_ARGUMENT;				\
	while ((sp < ep) && !isspace(*sp)) { 	\
		token[i++] = *sp;					\
		sp++;								\
	}										\
	token[i] = '\0';						\
} while (0)	

/*
 * Parse the dnskey from the string. The string contains the flags, 
 * protocol, algorithm and the base64 key delimited by spaces.
 */
int val_parse_dnskey_string (char *keystr, int keystrlen, 
		val_dnskey_rdata_t **dnskey_rdata)
{
	char *sp = keystr;
	char *ep = sp + keystrlen + 1;
	char token[MAXDNAME];

	if (ep - sp > MAXDNAME)
		return BAD_ARGUMENT;

	(*dnskey_rdata) = (val_dnskey_rdata_t *) MALLOC (sizeof(val_dnskey_rdata_t));
	if((*dnskey_rdata) == NULL)
		return OUT_OF_MEMORY;

	TOK_IN_STR();
	(*dnskey_rdata)->flags = atoi(token);

	TOK_IN_STR();
	(*dnskey_rdata)->protocol = atoi(token);

	TOK_IN_STR();
	(*dnskey_rdata)->algorithm = atoi(token);

	/* 
	 * What follows is the public key in base64.
	 */

	/* Remove any white spaces*/
	char *keyptr = NULL;
	char *cp;
	for(cp = sp; sp < ep; sp++) { 
		if (!isspace(*sp)) {
			if (keyptr == NULL)
				keyptr = cp;
			if (cp != sp) 
				*cp = *sp;
			cp++;
		}
	}
	*cp = '\0';

	int bufsize = ep - keyptr;
	(*dnskey_rdata)->public_key = (u_char *) MALLOC (bufsize * sizeof(char));
	if ((*dnskey_rdata)->public_key == NULL)
		return OUT_OF_MEMORY;

	/* decode the base64 public key */
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *mem = BIO_new_mem_buf(keyptr, -1);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	mem = BIO_push(b64, mem);
	(*dnskey_rdata)->public_key_len = 
		BIO_read(mem, (*dnskey_rdata)->public_key, bufsize);
	BIO_free_all(b64);
	if ((*dnskey_rdata)->public_key_len <= 0) {
		FREE((*dnskey_rdata)->public_key);
		FREE(*dnskey_rdata);	
		return BAD_ARGUMENT;
	}

	/* 
	 * For calculating the keytag, we need the 
	 * complete DNSKEY RDATA in wire format
	 */
	int buflen = (*dnskey_rdata)->public_key_len +
					sizeof(u_int16_t) + /* flags */
						sizeof(u_int8_t) + /* proto */
							sizeof (u_int8_t); /*algo */
	u_char *buf = (u_char *) MALLOC (buflen * sizeof (u_char));
	if (buf == NULL)
		return OUT_OF_MEMORY;

	u_char *bp = buf;
	u_int16_t flags = (*dnskey_rdata)->flags;

	memcpy(bp, &flags, sizeof(u_int16_t));
	bp += sizeof(u_int16_t);
	*bp = (*dnskey_rdata)->protocol;
	bp++;
	*bp = (*dnskey_rdata)->algorithm;
	bp++;
	memcpy(bp, (*dnskey_rdata)->public_key, (*dnskey_rdata)->public_key_len);

	/* Calculate the keytag */
    if ((*dnskey_rdata)->algorithm == 1) {
    	(*dnskey_rdata)->key_tag = rsamd5_keytag(buf, buflen);
    }
    else {
    	(*dnskey_rdata)->key_tag = keytag(buf, buflen);
    }
	(*dnskey_rdata)->next = NULL;
	FREE(buf);

	return NO_ERROR;
}


/*
 * Parse rdata portion of an RRSIG Resource Record.
 * Returns the number of bytes in the RRSIG rdata portion that were parsed.
 */
int val_parse_rrsig_rdata (const unsigned char *buf, int buflen,
			   val_rrsig_rdata_t *rdata)
{
    int index = 0;
    u_char *cp;

    if (!rdata) return -1;

    cp = (u_char *) buf;
    NS_GET16(rdata->type_covered, cp);
    index += 2;

    rdata->algorithm = (u_int8_t)(buf[index]);
    index += 1;

    rdata->labels = (u_int8_t)(buf[index]);
    index += 1;

    cp = (u_char *)(buf + index);
    NS_GET32(rdata->orig_ttl, cp);
    index += 4;

    NS_GET32(rdata->sig_expr, cp);
    index += 4;

    NS_GET32(rdata->sig_incp, cp);
    index += 4;

    NS_GET16(rdata->key_tag, cp);
    index += 2;
    
    index += val_parse_dname(buf, buflen, index, rdata->signer_name);
    
    rdata->signature_len = (buflen > index) ? (buflen - index): 0;

    if (rdata->signature_len > 0) {
        rdata->signature = (u_char *) MALLOC (rdata->signature_len * sizeof(u_char));
        memcpy (rdata->signature, buf + index, rdata->signature_len);
        index += rdata->signature_len;
    }
	else
		rdata->signature = NULL;

    return index;
}

/*
 * Parse rdata portion of a DS Resource Record.
 * Returns the number of bytes in the DS rdata portion that were parsed.
 */
#define DIGEST_SHA_1	1
int val_parse_ds_rdata (const unsigned char *buf, int buflen,
			    val_ds_rdata_t *rdata)
{
    int index = 0;
    u_char *cp;

    if (!rdata) return -1;

    cp = (u_char *) buf;
    NS_GET16(rdata->d_keytag, cp);
    index += 2;

    rdata->d_algo = (u_int8_t)(buf[index]);
    index += 1;

    rdata->d_type = (u_int8_t)(buf[index]);
    index += 1;

	/* Only SHA-1 is understood */
	if(rdata->d_type != DIGEST_SHA_1)
		return -1;

    memcpy (rdata->d_hash, buf + index, sizeof(rdata->d_hash));
    index += sizeof(rdata->d_hash);

    return index;
}

/*
 * Compare if two public keys are identical 
 * Return 0 if they are equal, 1 if not.
 */
int dnskey_compare(val_dnskey_rdata_t *key1, val_dnskey_rdata_t *key2)
{
	
	if (!key1 || !key2)
		return 1;

	if ((key1->flags == key2->flags) &&
		(key1->protocol == key2->protocol) &&
		(key1->algorithm == key2->algorithm) &&
		(key1->key_tag == key2->key_tag) &&
		(key1->public_key_len == key2->public_key_len) &&
		(!memcmp(key1->public_key, key2->public_key, key1->public_key_len)))
			return 0;
	return 1;
}

/*
 * Read ETC_HOSTS and return matching records
 */
struct hosts * parse_etc_hosts (const char *name)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	int read;
	char white[] = " \t\n";
	char fileentry[MAXLINE];
	struct hosts *retval = NULL;
	struct hosts *retval_tail = NULL;
	
	fp = fopen (ETC_HOSTS, "r");
	if (fp == NULL) {
		return NULL;
	}
	
	while ((read = getline (&line, &len, fp)) != -1) {
		char *buf = NULL;
		char *cp = NULL;
		char addr_buf[INET6_ADDRSTRLEN];
		char *domain_name = NULL;
		int matchfound = 0;
		char *alias_list[MAX_ALIAS_COUNT];
		int alias_index = 0;
		
		if ((read > 0) && (line[0] == '#')) continue;
		
		/* ignore characters after # */
		cp = (char *) strtok_r (line, "#", &buf);
		
		if (!cp) continue;
		
		memset(fileentry, 0, MAXLINE);
		memcpy(fileentry, cp, strlen(cp));
		
		/* read the ip address */
		cp = (char *) strtok_r (fileentry, white, &buf);
		if (!cp) continue;
		
		memset(addr_buf, 0, INET6_ADDRSTRLEN);
		memcpy(addr_buf, cp, strlen(cp));
		
		/* read the full domain name */
		cp = (char *) strtok_r (NULL, white, &buf);
		if (!cp) continue;
		
		domain_name = cp;
		
		if (strcasecmp(cp, name) == 0) {
			matchfound = 1;
		}
		
		/* read the aliases */
		memset(alias_list, 0, MAX_ALIAS_COUNT);
		alias_index = 0;
		while ((cp = (char *) strtok_r (NULL, white, &buf)) != NULL) {
			alias_list[alias_index++] = cp;
			if ((!matchfound) && (strcasecmp(cp, name) == 0)) {
				matchfound = 1;
			}
		}
		
		/* match input name with the full domain name and aliases */
		if (matchfound) {
			int i;
			struct hosts *hentry = (struct hosts*) MALLOC (sizeof(struct hosts));
			
			bzero(hentry, sizeof(struct hosts));
			hentry->address = (char *) strdup (addr_buf);
			hentry->canonical_hostname = (char *) strdup(domain_name);
			hentry->aliases = (char **) MALLOC ((alias_index + 1) * sizeof(char *));
			
			for (i=0; i<alias_index; i++) {
				hentry->aliases[i] = (char *) strdup(alias_list[i]);
			}
			
			hentry->aliases[alias_index] = NULL;
			hentry->next = NULL;
			
			if (retval) {
				retval_tail->next = hentry;
				retval_tail = hentry;
			}
			else {
				retval = hentry;
				retval_tail = hentry;
			}
		}
	}
	
	return retval;
}
