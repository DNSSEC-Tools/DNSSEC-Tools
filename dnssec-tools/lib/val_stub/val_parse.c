#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "val_parse.h"
#include "crypto/val_rsamd5.h"

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
        rdata->public_key = (u_char *) malloc (rdata->public_key_len * sizeof(u_char));
        memcpy (rdata->public_key, buf + index, rdata->public_key_len);
        index += rdata->public_key_len;
    }

    if (rdata->algorithm == 1) {
	rdata->key_tag = rsamd5_keytag(buf, buflen);
    }
    else {
	rdata->key_tag = keytag(buf, buflen);
    }
	

    return index;
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
        rdata->signature = (u_char *) malloc (rdata->signature_len * sizeof(u_char));
        memcpy (rdata->signature, buf + index, rdata->signature_len);
        index += rdata->signature_len;
    }

    return index;
}

