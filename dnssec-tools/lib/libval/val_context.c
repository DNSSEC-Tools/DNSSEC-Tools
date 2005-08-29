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
#include <validator.h>

#include "val_support.h"
#include "val_policy.h"
#include "val_x_query.h"
#include "val_log.h"

int get_context(char *label, val_context_t **newcontext)
{
	int retval;

	*newcontext = (val_context_t *) MALLOC (sizeof(val_context_t));
	if (*newcontext == NULL)
		return OUT_OF_MEMORY;

	/* Read the Resolver configuration file */	
	if ((retval = read_res_config_file(*newcontext)) != NO_ERROR) {
		FREE (*newcontext);
		return retval;
	}

	/* Read the validator configuration file */ 
	memset((*newcontext)->e_pol, 0, MAX_POL_TOKEN * sizeof(policy_entry_t));
	(*newcontext)->pol_overrides = NULL;
	(*newcontext)->cur_override = NULL;
	if ((retval = read_val_config_file(*newcontext, label)) != NO_ERROR) {
		destroy_respol(*newcontext);
		FREE (*newcontext);	
		return retval;
	}
	/* Over-ride with the first policy that we find in our list*/
	OVERRIDE_POLICY(*newcontext, (*newcontext)->pol_overrides); 

	return NO_ERROR;

}


void destroy_context(val_context_t *context)
{
	if(context == NULL)
		return;

	destroy_respol(context);
	destroy_valpol(context);

	FREE(context);
}

