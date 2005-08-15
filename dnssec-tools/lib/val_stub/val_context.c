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
#include "val_policy.h"
#include "val_x_query.h"
#include "val_log.h"
#include "val_errors.h"

val_context_t *get_context(const char *label)
{
	val_context_t *newcontext;

	newcontext = (val_context_t *) MALLOC (sizeof(val_context_t));
	if (newcontext == NULL)
		return NULL;

	/* Read the Resolver configuration file */	
	if (read_res_config_file(newcontext) != NO_ERROR) {
		FREE (newcontext);
		return NULL;
	}

	/* Read the validator configuration file */ 
	memset(newcontext->e_pol, 0, MAX_POL_TOKEN * sizeof(policy_entry_t));
	newcontext->pol_overrides = NULL;
	newcontext->cur_override = NULL;
	if (read_val_config_file(newcontext, label) != NO_ERROR) {
		destroy_respol(newcontext);
		FREE (newcontext);	
		return NULL;
	}
	/* Over-ride with the first policy that we find in our list*/
	OVERRIDE_POLICY(newcontext, newcontext->pol_overrides); 

	return newcontext;

}


void destroy_context(val_context_t *context)
{
	if(context == NULL)
		return;

	destroy_respol(context);
	destroy_valpol(context);

	FREE(context);
}

