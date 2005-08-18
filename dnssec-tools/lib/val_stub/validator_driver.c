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
#include "validator.h"

#include "val_support.h"
#include "val_x_query.h"
#include "val_log.h"
#include "val_errors.h"
#include "val_print.h"

/* Test for validation with recursion */
#define QUERY_NAME "dns.wesh.fruits.netsec.tislabs.com."
#define QUERY_TYPE ns_t_a

/* Test for non-existence */
//#define QUERY_NAME "dns1.wesh.fruits.netsec.tislabs.com."
//#define QUERY_TYPE ns_t_a

/* Test for validation without recursion + CNAME */
//#define QUERY_NAME "apple.fruits.netsec.tislabs.com."
//#define QUERY_TYPE ns_t_a

/* Test for multiple answers */
//#define QUERY_NAME "fruits.netsec.tislabs.com."
//#define QUERY_TYPE ns_t_any

/* Wild-card test */
//#define QUERY_NAME "jackfruit.fruits.netsec.tislabs.com."
//#define QUERY_TYPE ns_t_a


#define QUERY_CLASS ns_c_in

#define ANS_COUNT 3 
#define BUFSIZE 2048 

int main()
{

	char *name = QUERY_NAME;
	const u_int16_t type = QUERY_TYPE;
	const u_int16_t class = QUERY_CLASS;
	int ret_val;

	struct response_t resp[ANS_COUNT];
	int respcount = ANS_COUNT;
	int i;

	for (i = 0; i< ANS_COUNT; i++) {
		resp[i].response = (u_int8_t *) MALLOC (BUFSIZE * sizeof (u_int8_t *));
		if (resp[i].response == NULL)
			return OUT_OF_MEMORY;
		resp[i].response_length = BUFSIZE;
	}

	ret_val = val_x_query( NULL, name, class, type, 0, resp, &respcount);

	if (ret_val == NO_ERROR) {
		printf ("Total number of RRsets available = %d\n", respcount);
		for (i=0; i<respcount; i++) {
			printf("Validation Result = %d \n", resp[i].validation_result);
			printf("Validation Result = %s \n", p_val_error(resp[i].validation_result));
			print_response (resp[i].response, resp[i].response_length);
		}
	}
	else { 
		printf ("Error encountered:  %d \n", ret_val);
		if (ret_val == NO_SPACE) { 
			printf("Total number of answers available = %d\n", respcount);
			printf("Printing first %d\n", ANS_COUNT);
			for (i=0; i<ANS_COUNT; i++) {
				printf("Validation Result = %d \n", resp[i].validation_result);
				printf("Validation Result = %s \n", p_val_error(resp[i].validation_result));
				print_response (resp[i].response, resp[i].response_length);
			}
		}
	}

	for (i = 0; i< ANS_COUNT; i++) 
		FREE(resp[i].response);

	return ret_val;
}
