/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#include "validator-config.h"

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

int val_create_context(char *label, val_context_t **newcontext)
{
	int retval;

        if (newcontext == NULL)
            return VAL_BAD_ARGUMENT;

	*newcontext = (val_context_t *) MALLOC (sizeof(val_context_t));
	if (*newcontext == NULL)
		return VAL_OUT_OF_MEMORY;

    (*newcontext)->q_list = NULL;
	(*newcontext)->a_list = NULL;

	if(snprintf((*newcontext)->id, VAL_CTX_IDLEN-1, "%u", (unsigned)(*newcontext)) < 0)
		strcpy((*newcontext)->id, "libval");

	if ((retval = read_root_hints_file(*newcontext)) != VAL_NO_ERROR) {
		FREE (*newcontext);
                *newcontext = NULL;
		return retval;
	}

	/* Read the Resolver configuration file */	
	if ((retval = read_res_config_file(*newcontext)) != VAL_NO_ERROR) {
		FREE (*newcontext);
                *newcontext = NULL;
		return retval;
	}

	/* Read the validator configuration file */ 
	memset((*newcontext)->e_pol, 0, MAX_POL_TOKEN * sizeof(policy_entry_t));
	(*newcontext)->pol_overrides = NULL;
	(*newcontext)->cur_override = NULL;
	if ((retval = read_val_config_file(*newcontext, label)) != VAL_NO_ERROR) {
		destroy_respol(*newcontext);
		FREE (*newcontext);	
                *newcontext = NULL;
		return retval;
	}
	/* Switch to correct policy */
	if(VAL_NO_ERROR != (retval = val_switch_policy_scope(*newcontext, label))) {
		val_free_context(*newcontext);
		*newcontext = NULL;
		return retval;
	}

	return VAL_NO_ERROR;
}


void val_free_context(val_context_t *context)
{
	if(context == NULL)
		return;

	destroy_respol(context);
	destroy_valpol(context);

	free_query_chain(context->q_list);
	free_authentication_chain(context->a_list);

	FREE(context);
}

/*
 * At this point, the override list should have a sorted list 
 * of labels. When doing the override, we must use all policy
 * fragments that are "relevant"
 */
int val_switch_policy_scope(val_context_t *ctx, char *label)
{
	struct policy_overrides *t;
	int retval;

	if (ctx) {

		if(label == NULL) {
			/* switch to first override */
			memset(ctx->e_pol, 0, MAX_POL_TOKEN * sizeof(policy_entry_t));
			OVERRIDE_POLICY(ctx, ctx->pol_overrides);
			return VAL_NO_ERROR;
		}

		/* cur is the exact match */
		memset(ctx->e_pol, 0, MAX_POL_TOKEN * sizeof(policy_entry_t));
		for (t = ctx->pol_overrides; t != NULL; t = t->next) {
			/* Override only if this is relevant */
			int relevant, label_count;
			if (VAL_NO_ERROR != (retval = (check_relevance(label, t->label, &label_count, &relevant)))) 
					return retval;
			if(relevant)	
				OVERRIDE_POLICY(ctx, t);
		}
		return VAL_NO_ERROR;
	}
	return VAL_NO_POLICY;
}

