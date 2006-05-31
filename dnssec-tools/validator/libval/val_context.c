/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#include "../../dnssec-tools-config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <resolver.h>
#include <validator.h>
#include "val_support.h"
#include "val_policy.h"
#include "val_assertion.h"

int val_get_context(char *label, val_context_t **newcontext)
{
	int retval;

	*newcontext = (val_context_t *) MALLOC (sizeof(val_context_t));
	if (*newcontext == NULL)
		return OUT_OF_MEMORY;

    (*newcontext)->q_list = NULL;
	(*newcontext)->a_list = NULL;

	if(snprintf((*newcontext)->id, VAL_CTX_IDLEN-1, "%u", (unsigned)(*newcontext)) < 0)
		strcpy((*newcontext)->id, "libval");

	if ((retval = read_root_hints_file(*newcontext)) != NO_ERROR) {
		FREE (*newcontext);
		return retval;
	}

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


void val_free_context(val_context_t *context)
{
	if(context == NULL)
		return;

	destroy_respol(context);
	destroy_valpol(context);

	free_query_chain(context->q_list);
	free_assertion_chain(context->a_list);

	FREE(context);
}

/*
 * At this point, the override list should have a sorted list 
 * of labels. When doing the override, we must use all policy
 * fragments that are "relevant"
 */
int val_switch_policy_scope(val_context_t *ctx, char *label)
{
	struct policy_overrides *cur, *t;
	int retval;

	if (ctx) {

		if(label == NULL) {
			/* switch to first override */
			memset(ctx->e_pol, 0, MAX_POL_TOKEN * sizeof(policy_entry_t));
			OVERRIDE_POLICY(ctx, ctx->pol_overrides);
			return NO_ERROR;
		}

		for(cur = ctx->pol_overrides; 
			 cur && strcmp(cur->label, label); 
			  cur = cur->next); 
		if (cur) {
			/* cur is the exact match */
			memset(ctx->e_pol, 0, MAX_POL_TOKEN * sizeof(policy_entry_t));
			for (t = ctx->pol_overrides; t != cur->next; t = t->next) {
				/* Override only if this is relevant */
				int relevant, label_count;
				if (NO_ERROR != (retval = (check_relevance(label, t->label, &label_count, &relevant)))) 
						return retval;
				if(relevant)	
					OVERRIDE_POLICY(ctx, t);
			}
			return NO_ERROR;
		}
	}
	return UNKNOWN_LOCALE;
}

