/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This file contains functions for printing debugging information from
 * the validator
 */

#include "val_print.h"
#include <arpa/nameser_compat.h>
#include <arpa/nameser.h>
#include <time.h>

void val_print_header (unsigned char *buf, int buflen)
{
    HEADER *hp;

    hp = (HEADER *) buf;

    printf("Header info:\n");
    printf("\tid = %d,", ntohs(hp->id));
    printf("\topcode = %d,", ntohs(hp->opcode));
    printf("\tqdcount = %d,", ntohs(hp->qdcount));
    printf("\tancount = %d,", ntohs(hp->ancount));
    printf("\tnscount = %d,", ntohs(hp->nscount));
    printf("\tarcount = %d\n", ntohs(hp->arcount));
}

void val_print_buf(unsigned char *buf, int buflen)
{
    int i;
    int allzero = 0;
    for (i=0; i<buflen; i++) {
	if ((i%20) == 0) {
	    printf("\n");
	    if (allzero) {
		break;
	    }
	    allzero = 1;
	}
	printf("%02X", buf[i]);
	if (isprint(buf[i])) {
	    printf("[%c] ");
	}
	else {
	    printf("    ");
	}
	if (buf[i] != 0x00) {
	    allzero = 0;
	}
    }
}

void val_print_rr (const char *prefix, ns_rr *rr)
{
    if (rr) {
	if (!prefix) prefix = "";

	printf("%sDomain Name: %s\n", prefix, rr->name);
	printf("%sType: %d\n", prefix, rr->type);
	printf("%sClass: %d\n", prefix, rr->rr_class);
	printf("%sTTL: %d\n", prefix, rr->ttl);
	printf("%sRDLength: %d\n", prefix, rr->rdlength);
	/* printf("%sRData: \n"); */
    }
}

void val_print_rrsig_rdata (const char *prefix, val_rrsig_rdata_t *rdata)
{
    if (rdata) {
	if (!prefix) prefix = "";
	printf("%sType Covered         = %d\n", prefix, rdata->type_covered);
	printf("%sAlgorithm            = %d\n", prefix, rdata->algorithm);
	printf("%sLabels               = %d\n", prefix, rdata->labels);
	printf("%sOriginal TTL         = %d\n", prefix, rdata->orig_ttl);
	printf("%sSignature Expiration = %s",prefix,ctime(&(rdata->sig_expr)));
	printf("%sSignature Inception  = %s",prefix,ctime(&(rdata->sig_incp)));
	printf("%sKey Tag              = %d\n", prefix,rdata->key_tag);
	printf("%sSigner's Name        = %s\n", prefix,rdata->signer_name);
	/* printf("%sSignature: \n"); */
    }
}
