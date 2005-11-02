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

struct testcase_st {
	const char *desc;
	const char *qn;
	const u_int16_t qc;	
	const u_int16_t qt;	
};

static const struct testcase_st testcases[] = {

#if 1
	/* Test for resolution error (ensure no "search" in resolv.conf) */
	{"Checking name failure", "dns", ns_c_in, ns_t_a},
#endif

#if 1
	/* Test for non-existence */
	{"Checking non-existence proofs", "dns1.wesh.fruits.netsec.tislabs.com.", ns_c_in, ns_t_a}, 
#endif

#if 1
	/* Test for validation without recursion + CNAME */
	{"Testing CNAME and same-level validation", "apple.fruits.netsec.tislabs.com.", ns_c_in, ns_t_a},
#endif

#if 1
	/* Test for validation with recursion */
	{"Testing validation up the chain", "dns.wesh.fruits.netsec.tislabs.com.", ns_c_in, ns_t_a},
#endif

#if 1
	/* Test for multiple answers */
	{"Checking validation of multiple answers returned with ANY", "fruits.netsec.tislabs.com.", ns_c_in, ns_t_any},
#endif

#if 1
	/* Wild-card test */
	{"Checking validation with a wildcard match", "jackfruit.fruits.netsec.tislabs.com.", ns_c_in, ns_t_a},
#endif

#if 1
	/* Wild-card, non-existent type */
	{"Checking if wildcard with a different type matches", "jackfruit.fruits.netsec.tislabs.com.", ns_c_in, ns_t_cname},
#endif

#if 0
	/* Test for bad class */
	{"Testing bad class", "dns.wesh.fruits.netsec.tislabs.com.", 15, ns_t_a},
#endif

	{NULL, NULL, 0, 0},
};

#define ANS_COUNT 3 
#define BUFSIZE 2048 

int sendquery(const char *desc, const char *name, const u_int16_t class, const u_int16_t type)
{
	int ret_val;
	
	struct response_t resp[ANS_COUNT];
	int respcount = ANS_COUNT;
	int i;

	printf("Description: %s\n", desc);

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

void main()
{
	int i;
	for (i= 0 ; testcases[i].desc != NULL; i++) {
		printf("*********** Test case: %d ***************** \n", i+1);
		sendquery(testcases[i].desc, testcases[i].qn, testcases[i].qc, testcases[i].qt);
		printf("*********** End Test case: %d ***************** \n\n\n", i+1);
	}
}
