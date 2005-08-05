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

#include "val_support.h"
#include "val_resquery.h"
#include "val_policy.h"
#include "val_x_query.h"
#include "val_log.h"
#include "val_errors.h"

#include "validator.h"

#define AUTH_ZONE_INFO "fruits.netsec.tislabs.com"
// NOT AUTHORITATIVE FOR DS IN PARENT
#define NAME_SERVER_STRING	"158.69.82.20"
// QUERYING A RECURSIVE SERVER
//#define NAME_SERVER_STRING	"168.150.236.43"

#define OVERRIDE_POLICY(ctx, override)   do {		\
	struct policy_list *c;							\
	if (ctx && override) {							\
		ctx->cur_override = override;				\
		for (c = override->plist; c; c = c->next)	\
			ctx->e_pol[c->index] = c->pol;			\
	}												\
} while (0)

static int init_respol(struct res_policy *respol)
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
	memset(respol->ns->ns_name_n, 0, strlen(auth_zone_info) + 1);
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


static void destroy_respol(struct res_policy *respol)
{
	if (respol) free_name_servers(&respol->ns);
	FREE(respol);
}


val_context_t *get_context(const char *label)
{
	int ret_val;
	struct res_policy *newpol;
	val_context_t *newcontext;

	newcontext = (val_context_t *) MALLOC (sizeof(val_context_t));
	if (newcontext == NULL)
		return NULL;

	newpol = (struct res_policy *) MALLOC (sizeof(struct res_policy));
	if(newpol == NULL) {
		FREE (newcontext);
		return NULL;
	}

	if ((ret_val = init_respol(newpol)) != SR_UNSET) {
		FREE (newpol);
		FREE (newcontext);	
		return NULL;
	}

	newcontext->resolver_policy = newpol;

	memset(newcontext->e_pol, 0, MAX_POL_TOKEN * sizeof(policy_entry_t));
	newcontext->pol_overrides = NULL;
	newcontext->cur_override = NULL;
	if (read_config_file(newcontext, label) != SR_UNSET) {
		FREE (newpol);
		FREE (newcontext);	
		return NULL;
	}
	/* Over-ride with the first policy that we find in our list*/
	OVERRIDE_POLICY(newcontext, newcontext->pol_overrides); 

	return newcontext;
}


int switch_effective_policy(val_context_t *ctx, const char *label)
{
	struct policy_overrides *cur, *t;
	if (ctx) {
		for(cur = ctx->pol_overrides; 
			 cur && !strcmp(cur->label, label); 
			  cur = cur->next); 
		if (cur) {
			for (t = ctx->pol_overrides; t != cur->next; t = t->next)
				OVERRIDE_POLICY(ctx, t);
			return NO_ERROR;
		}
	}
	return UNKNOWN_LOCALE;
}

void destroy_context(val_context_t *context)
{
	if(context == NULL)
		return;

	destroy_respol(context->resolver_policy);
	destroy_policy(context);

	FREE(context);
}

