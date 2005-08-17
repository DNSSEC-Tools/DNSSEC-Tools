/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

/* 
 * Read the contents of the validator configuration file and 
 * update the validator context.
 */

#include <stdio.h>
#include <sys/types.h>
#include <regex.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "val_parse.h"
#include "val_errors.h"
#include "val_context.h"
#include "val_policy.h"
#include "val_support.h"

#include "validator.h"

/* forward declaration */
static int get_token ( FILE *conf_ptr,
				int *line_number,
				char *conf_token,
				int conf_limit,
				int *endst);


/*
 ***************************************************************
 * These are the generic parsing and free-up routines
 * used in parsing the validator configuration file
 ***************************************************************
 */




/*
 ***************************************************************
 * The following are the parsing and freeup routines for 
 * different policy fragments in the validator configuration
 * file
 **************************************************************
 */
static struct policy_conf_element conf_elem_array[] = {
	{POL_TRUST_ANCHOR_STR, parse_trust_anchor, free_trust_anchor},
	{POL_PREFERRED_SEP_STR, parse_preferred_sep, free_preferred_sep},	
	{POL_MUST_VERIFY_COUNT_STR, parse_must_verify_count, free_must_verify_count},
	{POL_PREFERRED_ALGO_DATA_STR, parse_preferred_algo_data, free_preferred_algo_data},	
	{POL_PREFERRED_ALGO_KEYS_STR, parse_preferred_algo_keys, free_preferred_algo_keys},
	{POL_PREFERRED_ALGO_DS_STR, parse_preferred_algo_ds, free_preferred_algo_ds},	
	{POL_CLOCK_SKEW_STR, parse_clock_skew, free_clock_skew},	
	{POL_EXPIRED_SIGS_STR, parse_expired_sigs, free_expired_sigs},
	{POL_USE_TCP_STR, parse_use_tcp, free_use_tcp},			
	{POL_ZONE_SE_STR, parse_zone_security_expectation, free_zone_security_expectation},			
#ifdef DLV
	{POL_DLV_TRUST_POINTS_STR, parse_dlv_trust_points, free_dlv_trust_points},
	{POL_DLV_MAX_LINKS_STR, parse_dlv_max_links, free_dlv_max_links},
#endif
};


int parse_trust_anchor(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	char token[TOKEN_MAX];
	u_char zone_n[MAXCDNAME];
	struct trust_anchor_policy *ta_pol, *ta_head, *ta_cur, *ta_prev;
	int retval;
	int name_len;
	int endst = 0;

	ta_head = NULL;

	while (!endst) {	

		/* Read the zone for which this trust anchor applies */
		if(NO_ERROR != (retval = get_token ( fp, line_number, token, TOKEN_MAX, &endst)))
			return retval;
		if (feof(fp))
			break;
		if (endst) {
			if (!strcmp(token, ""))
				break;
			/* missing the zone name */
			return CONF_PARSE_ERROR;
		}

   		if (ns_name_pton(token, zone_n, MAXCDNAME-1) == -1)
       		return CONF_PARSE_ERROR; 

		/* XXX We may want to have another token that specifies if 
		 * XXX this is a DS or a DNSKEY
		 * XXX Assume public key for now
		 */
		/* Read the public key */
		if(NO_ERROR != (retval = get_token ( fp, line_number, token, TOKEN_MAX, &endst)))
			return retval;
		if (feof(fp))
			return CONF_PARSE_ERROR;
		if (endst) {
			if (!strcmp(token, ""))
				/* missing a public key */
				return CONF_PARSE_ERROR;
		}
		/* Remove leading and trailing quotation marks */
		if ((token[0] != '\"') || 
				(strlen(token) <= 1) || 
					token[strlen(token) - 1] != '\"')
			return CONF_PARSE_ERROR;
		token[strlen(token) - 1] = '\0';
		char *pkstr = &token[1];


		// Parse the public key
		val_dnskey_rdata_t *dnskey_rdata;
		if (NULL == (dnskey_rdata = 
			(val_dnskey_rdata_t *) MALLOC (sizeof(val_dnskey_rdata_t))))
				return OUT_OF_MEMORY;
        if (NO_ERROR != (retval = val_parse_dnskey_string (pkstr, strlen(pkstr), dnskey_rdata)))
			return retval;

		ta_pol = (struct trust_anchor_policy *) MALLOC (sizeof(struct trust_anchor_policy));
		if (ta_pol == NULL)
			return OUT_OF_MEMORY;
		name_len = wire_name_length (zone_n);
		memcpy (ta_pol->zone_n, zone_n, name_len);
		ta_pol->publickey = dnskey_rdata;	

		/* Store trust anchors in decreasing zone name length */
		ta_prev = NULL;
		for(ta_cur = ta_head; ta_cur; ta_prev=ta_cur, ta_cur=ta_cur->next) 
			if (wire_name_length(ta_cur->zone_n) <= name_len)
				break;
		if (ta_prev) {
			/* store after ta_prev */
			ta_pol->next = ta_prev->next;
			ta_prev->next = ta_pol;
		}
		else {
			ta_pol->next = ta_head;
			ta_head = ta_pol;
		}
	} 

	*pol_entry = (policy_entry_t)(ta_head);
	
	return NO_ERROR;
}

int free_trust_anchor(policy_entry_t *pol_entry)
{
	struct trust_anchor_policy *ta_head, *ta_cur, *ta_next;

	if (pol_entry == NULL)
		return NO_ERROR;

	ta_head = (struct trust_anchor_policy *)(*pol_entry);
	ta_cur = ta_head;
	while (ta_cur) {
		ta_next = ta_cur->next;
		/* Free the val_dnskey_rdata_t structure */
		FREE (ta_cur->publickey->public_key);
		FREE (ta_cur->publickey);
		FREE (ta_cur);
		ta_cur = ta_next;
	}		

	*pol_entry = NULL;

	return NO_ERROR;
}



int parse_preferred_sep(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return NOT_IMPLEMENTED;
}
int free_preferred_sep(policy_entry_t *pol_entry)
{
	return NOT_IMPLEMENTED;
}
int parse_must_verify_count(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return NOT_IMPLEMENTED;
}
int free_must_verify_count(policy_entry_t *pol_entry)
{
	return NOT_IMPLEMENTED;
}
int parse_preferred_algo_data(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return NOT_IMPLEMENTED;
}
int free_preferred_algo_data(policy_entry_t *pol_entry)
{
	return NOT_IMPLEMENTED;
}
int parse_preferred_algo_keys(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return NOT_IMPLEMENTED;
}
int free_preferred_algo_keys(policy_entry_t *pol_entry)
{
	return NOT_IMPLEMENTED;
}
int parse_preferred_algo_ds(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return NOT_IMPLEMENTED;
}
int free_preferred_algo_ds(policy_entry_t *pol_entry)
{
	return NOT_IMPLEMENTED;
}
int parse_clock_skew(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return NOT_IMPLEMENTED;
}
int free_clock_skew(policy_entry_t *pol_entry)
{
	return NOT_IMPLEMENTED;
}
int parse_expired_sigs(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return NOT_IMPLEMENTED;
}
int free_expired_sigs(policy_entry_t *pol_entry)
{
	return NOT_IMPLEMENTED;
}
int parse_use_tcp(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return NOT_IMPLEMENTED;
}
int free_use_tcp(policy_entry_t *pol_entry)
{
	return NOT_IMPLEMENTED;
}

int parse_zone_security_expectation(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	char token[TOKEN_MAX];
	u_char zone_n[MAXCDNAME];
	struct zone_se_policy *zse_pol, *zse_head, *zse_cur, *zse_prev;
	int retval;
	int name_len;
	int endst = 0;
	int zone_status;

	zse_head = NULL;

	while (!endst) {	

		/* Read the zone for which this trust anchor applies */
		if(NO_ERROR != (retval = get_token ( fp, line_number, token, TOKEN_MAX, &endst)))
			return retval;
		if (feof(fp))
			break;
		if (endst) {
			if (!strcmp(token, ""))
				break;
			/* missing the zone name */
			return CONF_PARSE_ERROR;
		}

   		if (ns_name_pton(token, zone_n, MAXCDNAME-1) == -1)
       		return CONF_PARSE_ERROR; 

		/* Read the zone status */
		if(NO_ERROR != (retval = get_token ( fp, line_number, token, TOKEN_MAX, &endst)))
			return retval;
		if (feof(fp))
			return CONF_PARSE_ERROR;
		if (endst) {
			if (!strcmp(token, ""))
				/* missing the zone status */
				return CONF_PARSE_ERROR;
		}
		if (!strcmp(token, ZONE_SE_YES))
			zone_status = 1;
		else if (!strcmp(token, ZONE_SE_NO))
			zone_status = 0;
		else
			return CONF_PARSE_ERROR;

		zse_pol = (struct zone_se_policy *) MALLOC (sizeof(struct trust_anchor_policy));
		if (zse_pol == NULL)
			return OUT_OF_MEMORY;
		name_len = wire_name_length (zone_n);
		memcpy (zse_pol->zone_n, zone_n, name_len);
		zse_pol->trusted = zone_status;	

		/* Store trust anchors in decreasing zone name length */
		zse_prev = NULL;
		for(zse_cur = zse_head; zse_cur; zse_prev=zse_cur, zse_cur=zse_cur->next) 
			if (wire_name_length(zse_cur->zone_n) <= name_len)
				break;
		if (zse_prev) {
			/* store after zse_prev */
			zse_pol->next = zse_prev->next;
			zse_prev->next = zse_pol;
		}
		else {
			zse_pol->next = zse_head;
			zse_head = zse_pol;
		}
	} 

	*pol_entry = (policy_entry_t)(zse_head);
	
	return NO_ERROR;
}

int free_zone_security_expectation(policy_entry_t *pol_entry)
{
	struct zone_se_policy *zse_head, *zse_cur, *zse_next;

	if (pol_entry == NULL)
		return NO_ERROR;

	zse_head = (struct zone_se_policy *)(*pol_entry);
	zse_cur = zse_head;
	while (zse_cur) {
		zse_next = zse_cur->next;
		FREE (zse_cur);
		zse_cur = zse_next;
	}		

	*pol_entry = NULL;

	return NO_ERROR;
}


#ifdef DLV
int parse_dlv_trust_points(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return NOT_IMPLEMENTED;
}
int free_dlv_trust_points(policy_entry_t *pol_entry)
{
	return NOT_IMPLEMENTED;
}
int parse_dlv_max_links(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return NOT_IMPLEMENTED;
}
int free_dlv_max_links(policy_entry_t *pol_entry)
{
	return NOT_IMPLEMENTED;
}
#endif

/*
 ***************************************************************
 * The following are the higher-level parsing and freeup 
 * routines 
 **************************************************************
 */
/*
 * Read the contents of the file from the current location
 * and obtain a "token". Tokens are delimited by whitespace.
 * Ignore tokens that begin on a new line and have a 
 * leading '#' comment character
 */ 
static int get_token ( FILE *conf_ptr,
				int *line_number,
				char *conf_token,
				int conf_limit, 
				int *endst)
{
	char        c;
	int         i = 0;
	int         escaped = 0;
	int         quoted = 0;
	int         comment = 0;
	int         newline = 0;
	int         retval;
    
	*endst = 0;            
	strcpy (conf_token, "");

	if (*line_number == 1)
		newline = 1;

	do { 
		while (isspace (c=fgetc(conf_ptr))) {
			if (feof(conf_ptr)) return NO_ERROR;
			if (c == '\n') {
				(*line_number)++;
				newline = 1;
			}
		}

		conf_token[i++] = c;
		/* Ignore lines that begin with comments */
		if(newline && conf_token[0] == COMMENT) {
			char *linebuf = NULL;
			int linelen;
			comment = 1;
			/* read off the remainder of the line */ 
			if(-1 == (retval = getline(&linebuf, &linelen, conf_ptr))) {
				if (feof(conf_ptr))
					return NO_ERROR;
				else
					return retval;
			}
			if (linebuf != NULL)
				FREE (linebuf);
			(*line_number)++;
		}
	} while (comment);

	if (c=='\\') escaped = 1 ;
	else if (c=='"') quoted = 1;
                                                       
	/* Collect non-blanks and escaped blanks */
	while ((!isspace (c=fgetc(conf_ptr)) && (c != END_STMT)) || escaped || quoted)
	{
		if (escaped)
		{
			if (feof(conf_ptr)) return CONF_PARSE_ERROR;
			escaped = 0;
		}
		else if (quoted)
		{
			if (feof(conf_ptr)) {
				conf_token[i]= '\0';
				return CONF_PARSE_ERROR;
			}
			if (c == '\n') return CONF_PARSE_ERROR;
			if (c == '"') quoted = 0;
		}
		else	
		{
			if (feof(conf_ptr)) return NO_ERROR;
			if (c=='\\') escaped = 1 ;
			else if (c=='"') quoted = 1;
		}

		if (c == '\n') (*line_number)++;
		if (i > conf_limit-1) return CONF_PARSE_ERROR;
		conf_token[i++] = c;
	}
	if (c == '\n') (*line_number)++;
	conf_token[i]= '\0';

	if (c == END_STMT)
		*endst = 1;

	return NO_ERROR;
}

/*
 * check the relevance of a policy label against the given
 * policy "scope" label. This is essentially strstr() but
 * we also determine how many leading "levels" (strings 
 * delimited by ':') are present before the exact match is
 * obtained.
 */
static int check_relevance(char *label, const char *scope, int *label_count, int *relevant)
{
	char *c, *tmpstr;

	*label_count = 1;
	*relevant = 1;

	/* Check if this level is relevant */
	if (scope != NULL) {

		tmpstr= (char *) MALLOC ((strlen(scope) +1 ) * sizeof(char));
		if(tmpstr == NULL)
			return OUT_OF_MEMORY;
		c = tmpstr;

		while (strcmp(c, scope)) {
			if (NULL == strsep(&c, LVL_DELIM)) {
				*relevant = 0;
				break;
			}
			(*label_count)++;	
		}

		FREE(tmpstr);
	}
	else {
		char *c = label;
		/* A NULL scope is always relevant */
		if (!strcmp(label, LVL_DELIM)) {
			/* This is the default policy */
			*label_count = 0;
		}
		else {
			/* count the number of levels in the label */
			while(strstr(c, LVL_DELIM)) {
				(*label_count)++;
				c++;
			}
		}
	}
	return NO_ERROR;
}

/*
 * Get the next relevant {label, keyword, data} fragment 
 * from the configuration file file
 */
static int get_next_policy_fragment(FILE *fp, const char *scope, 
				struct policy_fragment **pol_frag, int *line_number)
{
	char token[TOKEN_MAX];
	int retval;
	char *keyword, *label;
	int relevant = 0;
	int index, label_count;
	int endst;
	policy_entry_t pol = NULL;

	while (!relevant) {

		/* free up previous iteration policy */
		if (pol != NULL) {
			conf_elem_array[index].free(pol);
			pol = NULL;
		}

		if (NO_ERROR != (retval = get_token(fp, line_number, token, TOKEN_MAX, &endst)))
			return retval;
		if (feof(fp))
			return NO_ERROR;
		if (endst)
			return CONF_PARSE_ERROR;
		label = (char *) MALLOC (strlen(token) + 1);
		if (label == NULL)
			return OUT_OF_MEMORY;
		strcpy(label, token);

		/* read the keyword */
		if (NO_ERROR != (retval = get_token(fp, line_number, token, TOKEN_MAX, &endst)))
			return retval;
		if (feof(fp) || endst) {
			FREE (label);
			return CONF_PARSE_ERROR;
		}
		keyword = token;
		
		/* parse the remaining contents according to the keyword */	
		for (index=0; index<MAX_POL_TOKEN; index++) {
			if (!strcmp(keyword, conf_elem_array[index].keyword)) {

				if(conf_elem_array[index].parse(fp, &pol, line_number) != NO_ERROR) {
					FREE (label); 
					return CONF_PARSE_ERROR;
				}
				break;
			}
		}

		if (index == MAX_POL_TOKEN) {
			FREE (label); 
			return CONF_PARSE_ERROR;
		}

		if (NO_ERROR != (retval = (check_relevance(label, scope, &label_count, &relevant)))) {
			FREE (label);
			return retval;
		}
	} 

	*pol_frag = (struct policy_fragment *) MALLOC (sizeof (struct policy_fragment));
	if (*pol_frag == NULL) 
		return OUT_OF_MEMORY;
	(*pol_frag)->label = label; 
	(*pol_frag)->label_count = label_count;
	(*pol_frag)->index = index;
	(*pol_frag)->pol = pol;
	
	return NO_ERROR;
}

/*
 * This list is ordered from general to more specific --
 * so "mozilla" < "sendmail" < "browser:mozilla"
 */
static int store_policy_overrides(val_context_t *ctx, struct policy_fragment **pfrag)
{
	struct policy_overrides *cur, *prev, *newp;
	struct policy_list *entry;

	/* search for a node with this label */
	cur = prev = NULL;
	for(cur=ctx->pol_overrides; 
			(cur && 
			(cur->label_count <= (*pfrag)->label_count) &&
			 (strcmp(cur->label, (*pfrag)->label) < 0)); prev=cur, cur=cur->next); 

	if ((cur == NULL) || (strcmp(cur->label, (*pfrag)->label) > 0)) {
		newp = (struct policy_overrides *) MALLOC (sizeof(struct policy_overrides));
		if (newp == NULL)
			return OUT_OF_MEMORY;

		newp->label = (*pfrag)->label;
		newp->label_count = (*pfrag)->label_count;
		newp->plist = NULL;

		if (prev) {
			newp->next = prev->next;
			prev->next = newp;	
		}
		else {
			newp->next = cur;
			ctx->pol_overrides = newp;
		}
	}
	else  {
		/* exact match */
		newp = cur;
		FREE ((*pfrag)->label);
	}

	/* Add this entry to the list */	
	entry = (struct policy_list *) MALLOC (sizeof(struct policy_list));
	if (entry == NULL)
		return OUT_OF_MEMORY;
	entry->index = (*pfrag)->index;
	entry->pol = (*pfrag)->pol;
	entry->next = newp->plist;
	newp->plist = entry;

	(*pfrag)->label = NULL;
	(*pfrag)->pol = NULL;
	FREE(*pfrag);

	return NO_ERROR;
}

void destroy_valpol(val_context_t *ctx)
{
    int i;
    struct policy_overrides *cur;
    for (i = 0; i< MAX_POL_TOKEN; i++)
            ctx->e_pol[i] = NULL;

    for (cur = ctx->pol_overrides; cur; cur = cur->next) {
            FREE (cur->label);
            conf_elem_array[cur->plist->index].free(&cur->plist->pol);
            FREE (cur->plist);
            FREE (cur);
    }
	ctx->pol_overrides = NULL;
	ctx->cur_override = NULL;

}
/*
 * Make sense of the validator configuration file
 */
int read_val_config_file(val_context_t *ctx, const char *scope)
{
	FILE *fp;
	struct policy_fragment *pol_frag = NULL;
	int retval;
	int line_number = 1;

	/* free up existing policies */
	destroy_valpol(ctx);

	fp = fopen(VAL_CONFIGURATION_FILE, "r");
	if (fp == NULL) {
		perror(VAL_CONFIGURATION_FILE);
		return NO_POLICY;
	}

	while (NO_ERROR == (retval = get_next_policy_fragment(fp, scope, &pol_frag, &line_number))) {
		if (feof(fp))
			return NO_ERROR;
		/* Store this fragment as an override, consume pol_frag */ 
		store_policy_overrides(ctx, &pol_frag);
	}

	printf ("Error in line %d of file %s\n", line_number, VAL_CONFIGURATION_FILE);
	return retval;
}	

/*
 * At this point, the override list should have a sorted list 
 * of labels. When doing the override, we must use all policy
 * fragments that are "relevant"
 */
int switch_effective_policy(val_context_t *ctx, const char *label)
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
				if (NO_ERROR != (retval = (check_relevance(t->label, label, &label_count, &relevant)))) 
						return retval;
				if(relevant)	
					OVERRIDE_POLICY(ctx, t);
			}
			return NO_ERROR;
		}
	}
	return UNKNOWN_LOCALE;
}


/*
 ****************************************************
 * Following routines handle parsing of the resolver 
 * configuration file
 ****************************************************
 */

void destroy_respol(val_context_t *ctx)
{
	free_name_servers(&ctx->nslist);
}


static int init_respol(struct name_server **nslist)
{
	struct sockaddr_in my_addr;
	struct in_addr  address;
	char auth_zone_info[MAXDNAME];
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    int read;
	struct name_server *ns_head = NULL;
	struct name_server *ns = NULL;

	*nslist = NULL;

	strcpy(auth_zone_info, DEFAULT_ZONE);

	fp = fopen(RESOLV_CONF, "r");
	if (fp == NULL){
		perror(RESOLV_CONF);
		return NO_POLICY;
	}
	while ((read = getline(&line, &len, fp)) != -1) {
                                                                                                                             
		char *buf = NULL;
		char *cp = NULL;
    	char white[] = " \t\n";

		if (strstr(line, "nameserver") == line) {

			strtok_r(line, white, &buf);
			cp = strtok_r(NULL, white, &buf);
			if (cp == NULL) {
				perror(RESOLV_CONF);
				goto err;
			}

			ns = (struct name_server *) MALLOC (sizeof(struct name_server));
			if (ns == NULL)
				goto err;

			/* Convert auth_zone_info to its on-the-wire format */

			ns->ns_name_n = (u_int8_t *) MALLOC (MAXCDNAME);
			if(ns->ns_name_n == NULL) 
				return OUT_OF_MEMORY;
   			if (ns_name_pton(auth_zone_info, ns->ns_name_n, MAXCDNAME-1) == -1) {
				FREE (ns->ns_name_n); 
				FREE (ns);
				goto err;
			}

			/* Initialize the rest of the fields */
			ns->ns_tsig_key = NULL;
			ns->ns_security_options = ZONE_USE_NOTHING;
			ns->ns_status = 0;
			ns->ns_next = NULL;
			ns->ns_number_of_addresses = 0;
			if (inet_aton (cp, &address)==0)
				goto err;
   	    	bzero(&my_addr, sizeof(struct sockaddr));
			my_addr.sin_family = AF_INET;         // host byte order
			my_addr.sin_port = htons(DNS_PORT);     // short, network byte order
			my_addr.sin_addr = address;
			memcpy(ns->ns_address, &my_addr, sizeof(struct sockaddr));

			if (ns_head == NULL) 
				ns_head = ns;
			else {
				ns->ns_next = ns_head;
				ns_head = ns;
			}
		}
		else if (strstr(line, "zone") == line) {
			if (ns == NULL)	
				goto err;
			strtok_r(line, white, &buf);
			cp = strtok_r(NULL, white, &buf);
			if (cp == NULL) {
				perror(RESOLV_CONF);
				goto err;
			}
   			if (ns_name_pton(cp, ns->ns_name_n, MAXCDNAME-1) == -1) 
				goto err;
		}
    	if (line) {
			free(line);
			line = NULL;
		}
	}

	*nslist = ns_head;

	fclose(fp);
	return NO_ERROR;

err:
	free_name_servers(&ns_head);
	free(line);
	fclose(fp);
	return CONF_PARSE_ERROR;
}


int read_res_config_file(val_context_t *ctx)
{
	int ret_val;

	if ((ret_val = init_respol(&ctx->nslist)) != NO_ERROR) 
		return ret_val;

	return NO_ERROR;
}


