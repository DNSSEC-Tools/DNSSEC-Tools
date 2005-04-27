/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the implementation file for a wrapper function around the
 * secure resolver and the verifier.  Applications should be able to
 * use this with minimal change.
 */

#include <stdio.h>
#include <resolv.h>
#include <resolver.h>
#include <string.h>
#include <res_errors.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "val_support.h"
#include "res_squery.h"
#include "val_parse.h"
#include "val_verify.h"
#include "val_print.h"
#include "val_query.h"
#include "val_log.h"

#define AUTH_ZONE_INFO          "*"                      /* any zone */
#define RESOLV_CONF             "/etc/resolv.conf"

#define PUT_FIELD(field,fieldlen,buf,indexptr,buflen) do { \
            if ((*indexptr) > (buflen)) {index = -1; goto cleanup;} \
            if (((*indexptr) + (fieldlen)) > (buflen)) {index = -1; goto cleanup;} \
	    memcpy((unsigned char *)(buf) + (*indexptr), (unsigned char *)(field), (fieldlen)); \
	    (*indexptr) += (fieldlen); \
} while(0);

static struct res_policy respol;
static int res_policy_set = 0;

/* Initialize the Resolver Policy */
static int init_respol(struct res_policy *respol)
{
    struct sockaddr_in my_addr;
    struct in_addr  address;
    struct name_server *ns, *head_ns, *tail_ns;
    char *name_server_string = NULL;
    char auth_zone_info[] = AUTH_ZONE_INFO;
    
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    int read;
    char white[] = " \t\n";
    
    if(respol == NULL) 
	return SR_CALL_ERROR;
    
    head_ns = NULL;
    tail_ns = NULL;
    
    fp = fopen(RESOLV_CONF, "r");
    
    if (fp == NULL)
	return SR_INTERNAL_ERROR;
    
    while ((read = getline(&line, &len, fp)) != -1) {
	
        if (strstr(line, "nameserver") == line) {
	    
            char *buf = NULL;
            char *cp = NULL;
	    
            strtok_r(line, white, &buf);
	    
            cp = strtok_r(NULL, white, &buf);
	    
            if (cp) {
		
		ns = (struct name_server *) MALLOC (sizeof(struct name_server));
		if (ns == NULL)
		    return SR_MEMORY_ERROR;
		
		ns->ns_name_n = (u_int8_t *) MALLOC (strlen(auth_zone_info) + 1);
		if(ns->ns_name_n == NULL) 
		    return SR_MEMORY_ERROR;
		
		/* Initialize the rest of the fields */
		ns->ns_tsig_key = NULL;
		ns->ns_security_options = ZONE_USE_NOTHING;
		ns->ns_status = 0;
		ns->ns_next = NULL;
		ns->ns_number_of_addresses = 1;
		
		if (inet_aton (cp, &address) == 0) {
		    return SR_INTERNAL_ERROR;
		}
		
		bzero(&my_addr, sizeof(struct sockaddr));
		my_addr.sin_family = AF_INET;     // host byte order
		my_addr.sin_port = htons(53);     // short, network byte order
		my_addr.sin_addr = address;
		memcpy(ns->ns_address, &my_addr, sizeof(struct sockaddr));
		
		if (head_ns == NULL) {
		    head_ns = ns;
		    tail_ns = ns;
		}
		else {
		    tail_ns->ns_next = ns;
		}
	    }
	}
    }
	
    if (line) free(line);
    if (fp) fclose(fp);
    
    respol->ns = head_ns;
    res_policy_set = 1;
    return SR_UNSET;
}

/*
static void destroy_respol(struct res_policy *respol)
{
	if (respol) free_name_servers(&respol->ns);
}
*/

static void fetch_dnskeys(val_context_t *ctx, const char *dname,
			  u_int16_t class, struct res_policy *respol)
{
    struct rrset_rec *oldkeys;
    struct domain_info dnskey_response;
    bzero(&dnskey_response, sizeof(dnskey_response));
    res_squery (NULL, dname, ns_t_dnskey, class, respol, &dnskey_response);
}


static int compose_answer (struct domain_info *response,
			   unsigned char *ans,
			   int anslen, int dnssec_status)
{
    int index = 0;
    char dname[MAXDNAME];
    HEADER *hp;
    struct rrset_rec *rrset;
    int anbufindex = 0, nsbufindex = 0, arbufindex = 0;
    char *anbuf = NULL, *nsbuf = NULL, *arbuf = NULL;
    char *cp;
    int matching_rrset_found = 0;
    int rrset_found_at_name = 0;

    //    if (!ans || (anslen <= 0) || (dnssec_status != VALIDATE_SUCCESS)) {
    if (!ans || (anslen <= 0)) {
	h_errno = NO_DATA;
	return -1;
    }

    /*** Header section ***/
    hp = (HEADER *) ans;
    bzero(hp, sizeof(HEADER));

    index = sizeof(HEADER);
    if (index > anslen) {
	h_errno = NETDB_INTERNAL;
	return -1;
    }

    /*** Question section ***/
    bzero(dname, MAXDNAME);
    if (ns_name_pton(response->di_requested_name_h, dname, MAXDNAME) < 0) {
	h_errno = NETDB_INTERNAL;
	return -1;
    }
    
    PUT_FIELD(dname, (strlen(dname) + 1), ans, &index, anslen);
    cp = ans + index;
    
    if ((index + 2) > anslen) {h_errno = NETDB_INTERNAL; return -1;}
    NS_PUT16(response->di_requested_type_h, cp);
    index += 2;
    
    if ((index + 2) > anslen) {h_errno = NETDB_INTERNAL; return -1;}
    NS_PUT16(response->di_requested_class_h, cp);
    index += 2;
    hp->qdcount = htons(1);

    /*** Compose the answer, authority and additional sections.  -- Add only those rrsets
     *** -- which have a validate-status of RRSIG_VERIFIED
     ***/

    rrset = response->di_rrset;
    while (rrset) {
	char *buf;
	int * bufindexptr;
	struct rr_rec *rr = rrset->rrs_data;

	/*
	if (rrset->rrs_status != RRSIG_VERIFIED) {
	    rrset = rrset->rrs_next;
	    continue;
	}
	*/

	if ((response->di_requested_class_h == rrset->rrs_class_h) &&
	    (strcasecmp(dname, rrset->rrs_name_n) == 0)) {

	    rrset_found_at_name = 1;

	    if ((response->di_requested_type_h == ns_t_any) || (response->di_requested_type_h == rrset->rrs_type_h))
		matching_rrset_found = 1;
	}

	switch(rrset->rrs_section) {

	case SR_FROM_ANSWER:
	    if (!anbuf) {
		anbuf = (char *) malloc (anslen * sizeof(char));
	    }
	    buf = anbuf;
	    bufindexptr = &anbufindex;
	    break;

	case SR_FROM_AUTHORITY:
	    if (!nsbuf) {
		nsbuf = (char *) malloc (anslen * sizeof(char));
	    }
	    buf = nsbuf;
	    bufindexptr = &nsbufindex;
	    break;

	case SR_FROM_ADDITIONAL:
	    if (!arbuf) {
		arbuf = (char *) malloc (anslen * sizeof(char));
	    }
	    buf = arbuf;
	    bufindexptr = &arbufindex;
	    break;

	default:
	    val_log("Unknown section for rrset ... skipping\n");
	    rrset = rrset->rrs_next;
	    continue;
	}

	while (rr) {

	    PUT_FIELD(rrset->rrs_name_n, (strlen(rrset->rrs_name_n) + 1), buf, bufindexptr, anslen);

	    cp = buf + (*bufindexptr);
	    
	    if (((*bufindexptr) + 2) > anslen) {h_errno = NETDB_INTERNAL; index = -1; goto cleanup;}
	    NS_PUT16(rrset->rrs_type_h, cp);
	    (*bufindexptr) += 2;
	    
	    if (((*bufindexptr) + 2) > anslen) {h_errno = NETDB_INTERNAL; index = -1; goto cleanup;}
	    NS_PUT16(rrset->rrs_class_h, cp);
	    (*bufindexptr) += 2;
	    
	    if (((*bufindexptr) + 4) > anslen) {h_errno = NETDB_INTERNAL; index = -1; goto cleanup;}
	    NS_PUT32(rrset->rrs_ttl_h, cp);
	    (*bufindexptr) += 4;
	    
	    if (((*bufindexptr) + 2) > anslen) {h_errno = NETDB_INTERNAL; index = -1; goto cleanup;}
	    NS_PUT16(rr->rr_rdata_length_h, cp);
	    (*bufindexptr) += 2;
		    
	    PUT_FIELD(rr->rr_rdata, rr->rr_rdata_length_h, buf, bufindexptr, anslen);
	    
	    switch(rrset->rrs_section) {
	    case SR_FROM_ANSWER:
		hp->ancount++;
		break;
	    case SR_FROM_AUTHORITY:
		hp->nscount++;
		break;
	    case SR_FROM_ADDITIONAL:
		hp->arcount++;
		break;
	    default:
		break;
	    }
	    
	    rr = rr->rr_next;
	}

	rrset = rrset->rrs_next;
    }

    memcpy(ans + index, anbuf, anbufindex);
    index += anbufindex;

    memcpy(ans + index, nsbuf, nsbufindex);
    index += nsbufindex;

    memcpy(ans + index, arbuf, arbufindex);
    index += arbufindex;

    hp->ancount = htons(hp->ancount);
    hp->nscount = htons(hp->nscount);
    hp->arcount = htons(hp->arcount);

    hp->qr = 1;
    if (matching_rrset_found) {
	h_errno = NETDB_SUCCESS;
    }
    else if (rrset_found_at_name){
	h_errno = NO_DATA;
    }
    else {
	h_errno = HOST_NOT_FOUND;
    }

 cleanup:
    
    if (anbuf) free(anbuf);
    if (nsbuf) free(nsbuf);
    if (arbuf) free(arbuf);

    return index;
}


/* a naive algorithm to figure out if it is a tld 
 * Return values:
 *   0 = no
 *  -1 = error
 *   1 = yes
 */
static int is_tld (const char *dname)
{
    int len = 0;
    int numdots = 0;
    int i;

    if (!dname) {
	return -1;
    }

    len = strlen(dname);
    // assume dname is fully qualified.  ignore the last dot/character
    for (i=0; i<len-1; i++) {
	if (dname[i] == '.') {
	    numdots++;
	}
    }

    if (numdots == 0) {
	return 1;
    }
    else {
	return 0;
    }

}

/* Returns 0 on success, -1 on failure */
int _val_query ( const char *dname, int class, int type,
		 struct domain_info *response,
		 int *dnssec_status )
{
    char dot = '.';
    val_context_t ctx;
    int ret_val;

    if (!dnssec_status || !response) {
	val_log("_val_query(): no dnssec_status or response objects\n");
	h_errno = NETDB_INTERNAL;
	return -1;
    }

    *dnssec_status = INTERNAL_ERROR;

    if (!res_policy_set) {
	if ((ret_val = init_respol(&respol)) != SR_UNSET) {
	    val_log("_val_query(): error initializing resolver policy\n");
	    h_errno = NETDB_INTERNAL;
	    return -1;
	}
    }
    
    ret_val = res_squery ( &ctx, dname, type, class, &respol, response); 
    val_log("\nres_squery returned %d\n", ret_val);
    val_log("response = \n");
    dump_dinfo(response);
    val_log("context = \n");
    dump_val_context(&ctx);

    /* A brute-force algorithm for finding the DNSKEYs if they
     * were not retrieved earlier.
     * XXX TODO: optimize to fetch DNSKEYs only from the authoritative
     *           zone.
     */
    do {
	(*dnssec_status) = val_verify (&ctx, response);

	if ((*dnssec_status) == DNSKEY_MISSING) {
	    if (dname && (dname[0] != '\0') && !is_tld(dname)) {
		val_log("\nQuerying the domain %s for DNSKEY records.\n",
		       dname);
		
		fetch_dnskeys(&ctx, dname, class, &respol);
	    }
	    if (strchr(dname, dot)) {
		dname = strchr(dname, dot) + 1;
	    }
	    else {
		dname = NULL;
	    }
	}
    } while (((*dnssec_status) == DNSKEY_MISSING) && (dname != NULL));

    h_errno = NETDB_SUCCESS;
    return 0;
}

/*
 * At present this only returns rrsets whose RRSIGs have been
 * successfully verified.
 */
int val_query ( const char *dname, int class, int type,
		unsigned char *ans, int anslen,
		int *dnssec_status )
{
    int len = -1;
    struct domain_info response;

    bzero(&response, sizeof(struct domain_info));

    val_log("val_query called with dname=%s, class=%s, type=%s\n",
	   dname, p_class(class), p_type(type));
    if ( _val_query (dname, class, type, &response, dnssec_status) != -1 ) {
	len = compose_answer(&response, ans, anslen, *dnssec_status);
    }

    /* Cleanup */
    free_domain_info_ptrs(&response);
    // destroy_respol(&respol);

    return len;
}
