/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is a header file for data structures and functions for parsing
 * DNSSEC Resource Records.
 */

#ifndef VAL_PARSE_H
#define VAL_PARSE_H

/*
 * Parse a domain name 
 */
int             val_parse_dname(const u_char *buf, size_t buflen,
                                size_t offset, char *dname, size_t *namelen);

/*
 * Parse the rdata portion of a DNSKEY resource record 
 */
int             val_parse_dnskey_rdata(const u_char *buf,
                                       size_t buflen,
                                       val_dnskey_rdata_t * rdata);
/*
 * Parse the dnskey from the string. The string contains the flags, 
 * protocol, algorithm and the base64 key delimited by spaces.
 */
int             val_parse_dnskey_string(char *keystr, size_t keystrlen,
                                        val_dnskey_rdata_t **
                                        dnskey_rdata);
/*
 * Parse the ds from the string. 
 */
int             val_parse_ds_string(char *dsstr, size_t dsstrlen,
                                    val_ds_rdata_t ** ds_rdata);

/*
 * Parse the rdata portion of an RRSIG resource record 
 */
int             val_parse_rrsig_rdata(const u_char *buf, size_t buflen,
                                      val_rrsig_rdata_t * rdata);

/*
 * Parse the rdata portion of an DS resource record 
 */
int             val_parse_ds_rdata(const u_char *buf, size_t buflen,
                                   val_ds_rdata_t * rdata);

#ifdef LIBVAL_NSEC3
val_nsec3_rdata_t *val_parse_nsec3_rdata(u_char * rr_rdata,
                                         size_t rdatalen,
                                         val_nsec3_rdata_t * nd);
#endif


/*
 * Parse the ETC_HOSTS file 
 */
#define MAXLINE 4096
#define MAX_ALIAS_COUNT 2048
struct hosts {
    char           *address;
    char           *canonical_hostname;
    char          **aliases;    /* An array.  The last element is NULL */
    struct hosts   *next;
};

/*
 * A macro to free memory allocated for hosts 
 */
#define FREE_HOSTS(hentry) do { \
	if (hentry) { \
	    int i = 0; \
	    if (hentry->address) free (hentry->address); \
	    if (hentry->canonical_hostname) free (hentry->canonical_hostname); \
	    if (hentry->aliases) { \
		for (i=0; hentry->aliases[i] != 0; i++) { \
		    if (hentry->aliases[i]) free (hentry->aliases[i]); \
		} \
		free (hentry->aliases); \
	    } \
	    free (hentry); \
	} \
} while (0)


#endif
