/*
 * Copyright 2004 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the C-implementation file for the validator library.
 *
 */

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include "validat-config.h"
#include "validat.h"

#define BUFLEN  4096
#define T_RRSIG 46 /* not defined in arpa/nameser.h yet */

static int val_inited = 0; /* 1: successfully initialized.
			    * 0: not initialized or errors in initialization
			    */


void errlog(int level, const char *msg)
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
 * for the existence of the RRSIG record for the given domain name
 * and class.]
 */
int val_check ( const char *domain_name, int class, int type,
		const char *rdata )
{
    char buf[BUFLEN];
    
    bzero(buf, BUFLEN);

    /* Check if the validator library was initialized */
    if (!val_inited) {
	errlog (1, "val_check(): error validator not initialized properly\n");
	return VAL_NOT_INIT;
    }

    /* Query the RRSIG record */
    if (res_query (domain_name, class, T_RRSIG, buf, BUFLEN) < 0) {
	errlog (1, "val_check(): error in DNS query for the RRSIG record\n");
	return VAL_FAILURE;
    }

    /* XXX TODO
     * 1. Parse buf
     * 2. Multiple RRSIG records may be returned.
     *    Select the one corresponding to 'type'
     * 3. Verify signature in the RDATA portion of the selected RRSIG record
     */
    
    errlog (2, "val_check(): succeeded\n");
    return VAL_SUCCESS;

} /* end val_check */


/*
 * This function acts as a resolver and validator
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

    /* Do the resolver query */
    if ((retval = res_query (domain_name, class, type, answer, anslen)) < 0) {
	errlog (1, "val_query(): error in DNS query\n");
	return retval;
    }

    /* Perform DNSSEC validation */
    if (dnssec_status != NULL) {
	*dnssec_status = val_check (domain_name, class, type, answer);
    }

    errlog (2, "val_query(): succeeded\n");
    return 0;

} /* end val_query */
