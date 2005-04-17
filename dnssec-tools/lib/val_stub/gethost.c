/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * A command-line tool for testing the val_gethostbyname() function.
 */

#include <stdio.h>
#include <netdb.h>

#include "val_api.h"

int main(int argc, char *argv[])
{
	struct hostent *hentry = NULL;
	int i;
	char *alias;
	int dnssec_status;
	char buf[INET6_ADDRSTRLEN];

	if (argc < 2) {
	    printf ("Usage: %s <hostname>\n", argv[0]);
	    exit(1);
	}

	hentry = val_gethostbyname(argv[1], &dnssec_status);

	if (hentry != NULL) {
	    printf("val_gethostbyname(%s) returned:\n", argv[1]);
	    printf("\th_name = %s\n", hentry->h_name);
	    printf("\th_aliases = %d\n", hentry->h_aliases);
	    if (hentry->h_aliases) {
		for (i=0; hentry->h_aliases[i] != 0; i++) {
	            printf("\th_aliases[%d] = %s\n", i, hentry->h_aliases[i]);
		} 
	    }
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
	    printf("gethostbyname(%s) returned NULL\n", argv[1]);
        }
	printf("DNSSEC status = %s\n", p_val_error(dnssec_status));
	printf("val_h_errno = %s\n", hstrerror(val_h_errno));
	FREE_HOSTENT(hentry);
}
