/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This file contains functions for parsing certain Resource Records
 */

#include "val_parse.h"

/*
 * Parse a domain name
 * Returns the number of bytes used by the domain name
 */
static int val_parse_dname(const unsigned char *buf, int buflen, int offset,
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
 * Parse rdata
 * Returns the number of bytes in the rdata that were parsed.
 */
static int val_parse_rdata (unsigned char *buf, int buflen, int offset,
			    ns_rr *rr)
{
    int i;
    u_char *cp = buf + offset;

    NS_GET16(rr->rdlength, cp);

    if (rr->rdata) {
	for (i = 0; i<rr->rdlength && i < buflen; i++) {
	    ((char *)(rr->rdata))[i] = buf[offset + 2 + i];
	}
    }

    return rr->rdlength + 2;
}

/*
 * Parse question RR
 * Returns the number of bytes in the RR that were parsed.
 */
int val_parse_qdrr (unsigned char *buf, int buflen, int offset, ns_rr *rr)
{
    int len = 0;
    u_char *cp;

    if (!rr) return -1;

    len  = val_parse_dname(buf, buflen, offset + len, rr->name);

    cp = buf + offset + len;
    NS_GET16(rr->type, cp);
    len += 2;
    
    NS_GET16(rr->rr_class, cp);
    len += 2;
    
    return len;
}

/*
 * Parse answer RR
 * Returns the number of bytes in the RR that were parsed.
 */
int val_parse_anrr (unsigned char *buf, int buflen, int offset, ns_rr *rr)
{
    int len = 0;
    u_char *cp;

    if (!rr) return -1;

    len  = val_parse_dname(buf, buflen, offset + len, rr->name);

    cp = buf + offset + len;
    NS_GET16(rr->type, cp);
    len += 2;

    NS_GET16(rr->rr_class, cp);
    len += 2;

    NS_GET32(rr->ttl, cp);
    len += 4;
    len += val_parse_rdata(buf, buflen, offset + len, rr);
    
    return len;
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
    
    /* XXX TODO: parse signature */
}
