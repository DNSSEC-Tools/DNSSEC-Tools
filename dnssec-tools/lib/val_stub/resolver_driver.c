/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 

#include <stdio.h>
#include <arpa/nameser.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <resolver.h>
#include <res_errors.h>
#include <support.h>

#include "val_support.h"
#include "res_squery.h"
#include "validator.h"
#include "val_x_query.h"
#include "val_log.h"

#include "val_errors.h"
#include "val_print.h"

#define QUERY_NAME "dns.wesh.fruits.netsec.tislabs.com."

//#define QUERY_NAME "nutshell.tislabs.com."
//#define QUERY_TYPE ns_t_a
//#define QUERY_CLASS ns_c_in

#define QUERY_TYPE ns_t_a
#define QUERY_CLASS ns_c_in

int main()
{

	char *name = QUERY_NAME;
	const u_int16_t type = QUERY_TYPE;
	const u_int16_t class = QUERY_CLASS;
	int ret_val;

	struct response_t resp;
	int respcount = 1;
	int buflen = 256;
	int i;

	resp.response = (u_int8_t *) malloc (buflen * sizeof(u_int8_t));
	resp.response_length = &buflen;

	ret_val = val_x_query( NULL, name, type, class, 0, &resp, &respcount);

	if (ret_val == NO_ERROR) {
		printf ("Total number of RRsets available = %d\n", respcount);
		for (i=0; i<respcount; i++) {
			printf("Validation Result = %d \n", resp.validation_result);
			print_response (resp.response, *resp.response_length);
		}
	}
	else 
		printf ("No answers returned\n");

	free(resp.response);
	return ret_val;
}
