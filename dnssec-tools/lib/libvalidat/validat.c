/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the C-implementation file for the validator library.
 *
 */

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <resolv.h>
#include <string.h>

#include "validat-config.h"
#include "val_internal.h"
#include "validat.h"
#include "val_parse.h"
#include "val_print.h"

#define BUFLEN      8096
#define RRLEN       4024
#define T_RRSIG     46      /* not defined in arpa/nameser.h yet */

static int val_inited = 0; /* 1: successfully initialized.
			    * 0: not initialized or errors in initialization
			    */


static void errlog(int level, const char *msg)
{
    /* XXX modify this to print to a logfile and
     * to check the log level
     */
    fprintf(stderr, "libvalidat::%s", msg);

} /* end errlog */


/*
 * This function initializes the validator.
 * Returns 0 on success, -1 on failure.
 */
int val_init(void)
{
    /* Read configuration files and trust anchors, if any */

#ifdef HAVE_LIBRESOLV
    /* Initialize the resolver, if any */
    if (res_init() < 0) {
	errlog (1, "val_init(): Error -- could not initialize resolver.\n");
	return -1;
    }

    val_inited = 1;
    return 0;

#else

    errlog (1, "val_init(): Error -- resolver not found.\n");
    return -1;

#endif

} /* end val_init */


/*
 * This function acts as a validator.  Given a domain_name, class,
 * type and rdata, it performs DNSSEC validation and checks if the
 * rdata indeed corresponds to the <domain_name, class, type> tuple.
 *
 * [At present this is a very simple validator ... it just checks
 * for the existence of the RRSIG record for the given domain name,
 * class and type.]
 */
int val_check ( const char *domain_name, int class, int type,
		const char *rdata )
{
    unsigned char buf[BUFLEN];
    int offset, len, i;
    HEADER *hp;
    
    bzero(buf, BUFLEN);

    /* Check if the validator library was initialized */
    if (!val_inited) {
	errlog (1, "val_check(): error validator not initialized properly\n");
	return VAL_NOT_INIT;
    }

    /* Query the RRSIG record */
    if (res_query (domain_name, class, T_RRSIG, buf, BUFLEN) < 0) {
	char errstr[BUFLEN];
	bzero(buf, BUFLEN);
	snprintf(errstr, BUFLEN,
		 "val_check(): error in DNS query for the RRSIG RR of %s\n",
		 domain_name);
	errlog (1, errstr);
	return VAL_FAILURE;
    }

    /*
    printf("RRSIG buf:");
    val_print_buf(buf, BUFLEN);
    */

    /* 
     * 1. Parse buf
     * 2. Multiple RRSIG records may be returned.
     *    Select the one corresponding to 'type'
     * 3. Verify signature in the RDATA portion of the selected RRSIG record
     */

    /*    val_print_header(buf, BUFLEN); */

    offset = sizeof(HEADER);
    hp = (HEADER *) buf;

    for (i = 0; i < ntohs(hp->qdcount); i++) {
	ns_rr rr;
	char rdata[RRLEN];
	bzero(&rr, sizeof(rr));
	bzero(rdata, RRLEN);
	rr.rdata = rdata;

	len = val_parse_qdrr(buf, BUFLEN, offset, &rr);

	printf("Parsed RR: \n");
	val_print_rr("\t", &rr);

	offset += len;
    }

    for (i = 0; i < ntohs(hp->ancount); i++) {
	ns_rr rr;
	char rdata[RRLEN];
	bzero(&rr, sizeof(rr));
	bzero(rdata, RRLEN);
	rr.rdata = rdata;

	len = val_parse_anrr(buf, BUFLEN, offset, &rr);

	printf("Parsed RR: \n");
	val_print_rr("\t", &rr);

	if (ns_rr_type(rr) == T_RRSIG) {

	    val_rrsig_rdata_t rrsig_rdata;
	    bzero(&rrsig_rdata, sizeof(rrsig_rdata));

	    val_parse_rrsig_rdata (ns_rr_rdata(rr), ns_rr_rdlen(rr),
				   &rrsig_rdata);

	    printf("\tRRSIG rdata:\n");
	    val_print_rrsig_rdata ("\t\t", &rrsig_rdata);

	    if (rrsig_rdata.type_covered == type) {
		/* TODO: verify signature */
		errlog (2, "val_check(): succeeded\n");
		return VAL_SUCCESS;
	    }
	}
	offset += len;
    }

    errlog (2, "val_check(): complete\n");

    return VAL_FAILURE;

} /* end val_check */


/*
 * This function acts as a resolver and validator
 *
 * XXX: At present it calls val_check.  A better way would be to add the
 * EDNS0 DO flag to the query and then perform validation.
 */
int val_query ( const char *domain_name, int class, int type,
		unsigned char *answer, int anslen, int *dnssec_status )
{
    
    int retval;

    /* Check if the validator library was initialized */
    if (!val_inited) {
	if (dnssec_status != NULL) {
	    *dnssec_status = VAL_NOT_INIT;
	}
	errlog (1, "val_query(): validator not initialized properly\n");
	return -1;
    }

    /* Query the resolver */
    if ((retval = res_query (domain_name, class, type, answer, anslen)) < 0) {
	errlog (1, "val_query(): error in res_query\n");
	return retval;
    }

    /* Perform DNSSEC validation */
    if (dnssec_status != NULL) {
	*dnssec_status = val_check (domain_name, class, type, answer);
    }

    errlog (2, "val_query(): succeeded\n");
    return 0;

} /* end val_query */
