/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * A command-line validator.  At present, it's just a verifier.
 */

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <resolver.h>
#include <res_errors.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "val_errors.h"
#include "val_support.h"
#include "res_squery.h"
#include "val_parse.h"
#include "val_verify.h"
#include "val_print.h"

#define BUFLEN 8096

void usage(char *progname) {
    printf("Usage: %s [[CLASS] TYPE] DOMAIN_NAME\n", progname);
    printf("     If CLASS is not provided, it is assumed to be IN\n");
    printf("     If TYPE is not provided, it is assumed to be A\n");
}

#define AUTH_ZONE_INFO          "netsec.tislabs.com."
#define NAME_SERVER_STRING	"158.69.82.5"
#define QUERY_NAME              "dns.wesh.fruits.netsec.tislabs.com."

int init_respol(struct res_policy *respol)
{
	struct sockaddr_in *my_addr;
	struct in_addr  address;
	struct name_server *ns;
	char name_server_string[] = NAME_SERVER_STRING;
	char auth_zone_info[] = AUTH_ZONE_INFO;

	if(respol == NULL) 
		return SR_CALL_ERROR;

	ns = (struct name_server *) MALLOC (sizeof(struct name_server));
	if (ns == NULL)
		return SR_MEMORY_ERROR;

	respol->ns = ns;
	respol->ns->ns_name_n = (u_int8_t *) MALLOC (strlen(auth_zone_info) + 1);
	if(respol->ns->ns_name_n == NULL) 
		return SR_MEMORY_ERROR;
	respol->ns->ns_name_n = (u_int8_t *) MALLOC (strlen(auth_zone_info) + 1);
	if(respol->ns->ns_name_n == NULL) 
		return SR_MEMORY_ERROR;
	/* Initialize the rest of the fields */
	respol->ns->ns_tsig_key = NULL;
	respol->ns->ns_security_options = ZONE_USE_NOTHING;
	respol->ns->ns_status = 0;
	respol->ns->ns_next = NULL;
	respol->ns->ns_number_of_addresses = 1;
	if (inet_aton (name_server_string, &address)==0)
		return SR_INTERNAL_ERROR;
	my_addr = (struct sockaddr_in *) MALLOC (sizeof (struct sockaddr_in));
	if (my_addr == NULL) 
		return SR_MEMORY_ERROR;
	my_addr->sin_family = AF_INET;         // host byte order
	my_addr->sin_port = htons(53);     // short, network byte order
	my_addr->sin_addr = address;
	memcpy(respol->ns->ns_address, my_addr, sizeof(struct sockaddr));

	return SR_UNSET;
}

void destroy_respol(struct res_policy *respol)
{
	if (respol) free_name_servers(&respol->ns);
}

void fetch_dnskeys(val_context_t *context, char *domain_name,
		   u_int16_t class, struct res_policy *respol)
{
    struct rrset_rec *oldkeys;
    struct domain_info dnskey_response;
    bzero(&dnskey_response, sizeof(dnskey_response));
    res_squery (NULL, domain_name, ns_t_dnskey, class, respol, &dnskey_response);
    oldkeys = context->learned_keys;
    context->learned_keys = dnskey_response.di_rrset;
    dnskey_response.di_rrset = oldkeys;
    free_domain_info_ptrs(&dnskey_response);
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

/*
 * A command-line validator
 */
int main(int argc, char *argv[])
{
    char dot = '.';
    struct res_policy respol;
    struct domain_info response;
    int ret_val;
    int class = ns_c_in;
    int type = ns_t_a;
    char *classstr = NULL;
    char *typestr = NULL;
    char *domain_name = NULL;
    unsigned char *buf;
    val_result_t dnssec_status = -1;
    val_context_t context;

    /* Parse input */
    if ((argc < 2) || (argc > 4)){
	usage(argv[0]);
	exit(1);
    }

    if (argc == 2) {
	domain_name = argv[1];
    }
	
    if (argc == 3) {
	typestr = argv[1];
	domain_name = argv[2];
    }

    if (argc == 4) {
	classstr = argv[1];
	typestr = argv[2];
	domain_name = argv[3];
    }

    // printf("domain_name = %s\n", domain_name);

    if (classstr) {
	if (strncasecmp(classstr, "IN", 2) != 0) {
	    printf("Class %s not supported by validate.\n", classstr);
	    exit(1);
	}
	else {
	    // printf("class = ns_c_in\n");
	}
    }

    if (typestr) {
	if (strncasecmp(typestr, "DNSKEY", 6) == 0) {
	    type = ns_t_dnskey;
	    // printf("type = ns_t_dnskey\n");
	}
	else if (strncasecmp(typestr, "RRSIG", 5) == 0) {
	    type = ns_t_rrsig;
	    // printf("type = ns_t_rrsig\n");
	}
	else if (strncasecmp(typestr, "CNAME", 5) == 0) {
	    type = ns_t_cname;
	    // printf("type = ns_t_cname\n");
	}
	else if (strncasecmp(typestr, "AAAA", 4) == 0) {
	    type = ns_t_aaaa;
	    // printf("type = ns_t_aaaa\n");
	}
	else if (strncasecmp(typestr, "NSEC", 4) == 0) {
	    type = ns_t_nsec;
	    // printf("type = ns_t_nsec\n");
	}
	else if (strncasecmp(typestr, "ANY", 3) == 0) {
	    type = ns_t_any;
	    // printf("type = ns_t_any\n");
	}
	else if (strncasecmp(typestr, "TXT", 3) == 0) {
	    type = ns_t_txt;
	    // printf("type = ns_t_txt\n");
	}
	else if (strncasecmp(typestr, "PTR", 3) == 0) {
	    type = ns_t_ptr;
	    // printf("type = ns_t_ptr\n");
	}
	else if (strncasecmp(typestr, "SOA", 3) == 0) {
	    type = ns_t_soa;
	    // printf("type = ns_t_soa\n");
	}
	else if (strncasecmp(typestr, "MX", 2) == 0) {
	    type = ns_t_mx;
	    // printf("type = ns_t_mx\n");
	}
	else if (strncasecmp(typestr, "DS", 2) == 0) {
	    type = ns_t_dnskey;
	    // printf("type = ns_t_ds\n");
	}
	else if (strncasecmp(typestr, "NS", 2) == 0) {
	    type = ns_t_ns;
	    // printf("type = ns_t_ns\n");
	}
	else if (strncasecmp(typestr, "A", 1) == 0) {
	    type = ns_t_a;
	    // printf("type = ns_t_a\n");
	}
	else {
	    printf("Type %s not supported by validate.\n", typestr);
	    exit(1);
	}
    }
    else {
	// printf("type = ns_t_a\n");
    }

    /* Perform validation */
    buf = (unsigned char *) malloc (BUFLEN * sizeof (unsigned char));
    bzero(buf, BUFLEN);

    if ((ret_val = init_respol(&respol)) != SR_UNSET)
	return ret_val;
    
    context.learned_zones = NULL;
    context.learned_keys  = NULL;
    context.learned_ds    = NULL;

    ret_val = res_squery ( &context, domain_name, type, class, &respol, &response); 
    printf("\nres_squery returned %d\n", ret_val);

    /* A brute-force algorithm for finding the DNSKEYs if they
     * were not found
     */
    do {
	dnssec_status = val_verify (&context, &response);
	if (dnssec_status == DNSKEY_MISSING) {
	    if (domain_name && (domain_name[0] != '\0') && !is_tld(domain_name)) {
		printf("\nQuerying the domain %s for DNSKEY records.\n",
		       domain_name);
		
		fetch_dnskeys(&context, domain_name, class, &respol);
	    }
	    if (strchr(domain_name, dot)) {
		domain_name = strchr(domain_name, dot) + 1;
	    }
	    else {
		domain_name = NULL;
	    }
	}
    } while ((dnssec_status == DNSKEY_MISSING) && (domain_name != NULL));

    printf("response = ");
    dump_dinfo(&response);
    printf("context = ");
    dump_val_context(&context);
    printf("dnssec status = %s [%d]\n", p_val_error(dnssec_status), dnssec_status);

    /* Cleanup */
    free_domain_info_ptrs(&response);
    destroy_respol(&respol);
    if (buf) free(buf);

    return ret_val;
}

