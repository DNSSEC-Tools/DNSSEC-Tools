/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * A command-line tool for testing the val_gethostbyname() and
 * val_x_gethostbyname() functions.
 */

#include <stdio.h>
#include <netdb.h>

#include "val_api.h"
#include "val_log.h"

int main(int argc, char *argv[])
{
	struct hostent *hentry = NULL;
	int i;
	char *alias;
	int dnssec_status;
	char buf[INET6_ADDRSTRLEN];
	int index;
	int extended = 0;
	
	if (argc < 2) {
		printf ("Usage: %s [-x] <hostname>\n", argv[0]);
		exit(1);
	}
	
	index = 1;
	
	if (strcasecmp(argv[index], "-x") == 0) {
		extended = 1;
		index++;
	}
	
	if (extended) {
		hentry = val_x_gethostbyname(NULL, argv[index]);
		dnssec_status = val_get_hostent_dnssec_status(hentry);
	}
	else {
		hentry = val_gethostbyname(argv[index]);
		dnssec_status = val_get_hostent_dnssec_status(hentry);
	}
	
	if (extended)
		printf("val_x_gethostbyname(%s) returned:", argv[index]);
	else
		printf("val_gethostbyname(%s) returned:", argv[index]);
	
	if (hentry != NULL) {
		printf("\n\th_name = %s\n", hentry->h_name);
		printf("\th_aliases = %d\n", hentry->h_aliases);
		if (hentry->h_aliases) {
			for (i=0; hentry->h_aliases[i] != 0; i++) {
				printf("\th_aliases[%d] = %s\n", i, hentry->h_aliases[i]);
			} 
		}
		else
			printf ("\th_aliases is NULL\n");
		if (hentry->h_addrtype == AF_INET) {
			printf("\th_addrtype = AF_INET\n");
		}
		else if (hentry->h_addrtype == AF_INET6) {
			printf("\th_addrtype = AF_INET6\n");
		}
		else {
			printf("\th_addrtype = %d\n", hentry->h_addrtype);
		}
		printf("\th_length = %d\n", hentry->h_length);
		for (i=0; hentry->h_addr_list[i] != 0; i++) {
			bzero(buf, INET6_ADDRSTRLEN);
			printf("\th_addr_list[%d] = %s\n", i,
			       inet_ntop(hentry->h_addrtype,
					 hentry->h_addr_list[i],
					 buf, INET6_ADDRSTRLEN));
		}
	}
	else {
	   	printf(" hentry is NULL\n"); 
        }
	printf("DNSSEC status = %s\n", p_val_error(dnssec_status));
	printf("val_h_errno = %s\n", hstrerror(val_h_errno));
	val_freehostent(hentry);
}
