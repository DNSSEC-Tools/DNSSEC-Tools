/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

/* 
 * Read the contents of the validator configuration file and 
 * update the validator context.
 */
#include "validator-config.h"

#include <stdio.h>
#include <sys/types.h>
#include <regex.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#if defined(sun) && !defined(__EXTENSIONS__)
extern char *strtok_r(char *, const char *, char **);
#endif
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/file.h>
#include <resolv.h>

#include <validator.h>
#include "val_policy.h"
#include "val_support.h"
#include "val_cache.h"
#include "val_resquery.h"
#include "val_log.h"
#include "res_debug.h"


/* forward declaration */
static int get_token ( FILE *conf_ptr,
				int *line_number,
				char *conf_token,
				int conf_limit,
				int *endst, 
				char comment_c, 
				char endstmt_c);

/*
 ***************************************************************
 * These are functions to read/set the location of the resolver
 * configuration and root.hints files.
 ***************************************************************
 */
static char *resolver_config = NULL;
static char *root_hints = NULL;
static char *dnsval_conf = NULL;

char *
resolver_config_get(void)
{
   if (NULL == resolver_config)
      resolver_config = strdup(RESOLV_CONF);

   return resolver_config;
}

int
resolver_config_set(const char *name)
{
   char *new_name = strdup(name);

   if (NULL == new_name)
      return 1;

   if (NULL != resolver_config)
      free(resolver_config);

   resolver_config = new_name;

   return 0;
}

char *
root_hints_get(void)
{
   if (NULL == root_hints)
      root_hints = strdup(ROOT_HINTS);

   return root_hints;
}

int
root_hints_set(const char *name)
{
   char *new_name = strdup(name);

   if (NULL == new_name)
      return 1;

   if (NULL != root_hints)
      free(root_hints);

   root_hints = new_name;

   return 0;
}

char *
dnsval_conf_get(void)
{
   if (NULL == dnsval_conf)
      dnsval_conf = strdup(VAL_CONFIGURATION_FILE);

   return dnsval_conf;
}

int
dnsval_conf_set(const char *name)
{
   char *new_name = strdup(name);

   if (NULL == new_name)
      return 1;

   if (NULL != dnsval_conf)
      free(dnsval_conf);

   dnsval_conf = new_name;

   return 0;
}

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
static const struct policy_conf_element conf_elem_array[] = {
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
	u_char zone_n[NS_MAXCDNAME];
	struct trust_anchor_policy *ta_pol, *ta_head, *ta_cur, *ta_prev;
	int retval;
	int name_len;
	int endst = 0;

	ta_head = NULL;

	while (!endst) {	

		/* Read the zone for which this trust anchor applies */
		if(VAL_NO_ERROR != (retval = get_token ( fp, line_number, token, TOKEN_MAX, &endst, CONF_COMMENT, CONF_END_STMT)))
			return retval;
		if (endst && (strlen(token) == 1))
			break;
		if (feof(fp))
			return VAL_CONF_PARSE_ERROR;

   		if (ns_name_pton(token, zone_n, NS_MAXCDNAME-1) == -1)
       		return VAL_CONF_PARSE_ERROR; 

		/* XXX We may want to have another token that specifies if 
		 * XXX this is a DS or a DNSKEY
		 * XXX Assume public key for now
		 */
		/* Read the public key */
		if(VAL_NO_ERROR != (retval = get_token ( fp, line_number, token, TOKEN_MAX, &endst, CONF_COMMENT, CONF_END_STMT)))
			return retval;
		if (feof(fp) && !endst)
			return VAL_CONF_PARSE_ERROR;
		/* Remove leading and trailing quotation marks */
		if ((token[0] != '\"') || 
				(strlen(token) <= 1) || 
					token[strlen(token) - 1] != '\"')
			return VAL_CONF_PARSE_ERROR;
		token[strlen(token) - 1] = '\0';
		char *pkstr = &token[1];


		// Parse the public key
		val_dnskey_rdata_t *dnskey_rdata;
        if (VAL_NO_ERROR != (retval = val_parse_dnskey_string (pkstr, strlen(pkstr), &dnskey_rdata)))
			return retval;

		ta_pol = (struct trust_anchor_policy *) MALLOC (sizeof(struct trust_anchor_policy));
		if (ta_pol == NULL)
			return VAL_OUT_OF_MEMORY;
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
	
	return VAL_NO_ERROR;
}

int free_trust_anchor(policy_entry_t *pol_entry)
{
	struct trust_anchor_policy *ta_head, *ta_cur, *ta_next;

	if (pol_entry == NULL)
		return VAL_NO_ERROR;

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

	return VAL_NO_ERROR;
}



int parse_preferred_sep(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return VAL_NOT_IMPLEMENTED;
}
int free_preferred_sep(policy_entry_t *pol_entry)
{
	return VAL_NOT_IMPLEMENTED;
}
int parse_must_verify_count(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return VAL_NOT_IMPLEMENTED;
}
int free_must_verify_count(policy_entry_t *pol_entry)
{
	return VAL_NOT_IMPLEMENTED;
}
int parse_preferred_algo_data(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return VAL_NOT_IMPLEMENTED;
}
int free_preferred_algo_data(policy_entry_t *pol_entry)
{
	return VAL_NOT_IMPLEMENTED;
}
int parse_preferred_algo_keys(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return VAL_NOT_IMPLEMENTED;
}
int free_preferred_algo_keys(policy_entry_t *pol_entry)
{
	return VAL_NOT_IMPLEMENTED;
}
int parse_preferred_algo_ds(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return VAL_NOT_IMPLEMENTED;
}
int free_preferred_algo_ds(policy_entry_t *pol_entry)
{
	return VAL_NOT_IMPLEMENTED;
}
int parse_clock_skew(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return VAL_NOT_IMPLEMENTED;
}
int free_clock_skew(policy_entry_t *pol_entry)
{
	return VAL_NOT_IMPLEMENTED;
}
int parse_expired_sigs(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return VAL_NOT_IMPLEMENTED;
}
int free_expired_sigs(policy_entry_t *pol_entry)
{
	return VAL_NOT_IMPLEMENTED;
}
int parse_use_tcp(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return VAL_NOT_IMPLEMENTED;
}
int free_use_tcp(policy_entry_t *pol_entry)
{
	return VAL_NOT_IMPLEMENTED;
}

int parse_zone_security_expectation(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	char token[TOKEN_MAX];
	u_char zone_n[NS_MAXCDNAME];
	struct zone_se_policy *zse_pol, *zse_head, *zse_cur, *zse_prev;
	int retval;
	int name_len;
	int endst = 0;
	int zone_status;

	zse_head = NULL;

	while (!endst) {	

		/* Read the zone for which this trust anchor applies */
		if(VAL_NO_ERROR != (retval = get_token ( fp, line_number, token, TOKEN_MAX, &endst, CONF_COMMENT, CONF_END_STMT)))
			return retval;
		if (endst && (strlen(token) == 1))
			break;
		if (feof(fp)) 
			return VAL_CONF_PARSE_ERROR;

   		if (ns_name_pton(token, zone_n, NS_MAXCDNAME-1) == -1)
       		return VAL_CONF_PARSE_ERROR; 

		/* Read the zone status */
		if(VAL_NO_ERROR != (retval = get_token ( fp, line_number, token, TOKEN_MAX, &endst, CONF_COMMENT, CONF_END_STMT)))
			return retval;
		if (feof(fp) && !endst)
			return VAL_CONF_PARSE_ERROR;
		if (!strcmp(token, ZONE_SE_IGNORE_MSG))
			zone_status = ZONE_SE_IGNORE;
		else if (!strcmp(token, ZONE_SE_DO_VAL_MSG))
			zone_status = ZONE_SE_DO_VAL;
		else if (!strcmp(token, ZONE_SE_UNTRUSTED_MSG))
			zone_status = ZONE_SE_UNTRUSTED;
		else
			return VAL_CONF_PARSE_ERROR;

		zse_pol = (struct zone_se_policy *) MALLOC (sizeof(struct trust_anchor_policy));
		if (zse_pol == NULL)
			return VAL_OUT_OF_MEMORY;
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
	
	return VAL_NO_ERROR;
}

int free_zone_security_expectation(policy_entry_t *pol_entry)
{
	struct zone_se_policy *zse_head, *zse_cur, *zse_next;

	if (pol_entry == NULL)
		return VAL_NO_ERROR;

	zse_head = (struct zone_se_policy *)(*pol_entry);
	zse_cur = zse_head;
	while (zse_cur) {
		zse_next = zse_cur->next;
		FREE (zse_cur);
		zse_cur = zse_next;
	}		

	return VAL_NO_ERROR;
}


#ifdef DLV
int parse_dlv_trust_points(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return VAL_NOT_IMPLEMENTED;
}
int free_dlv_trust_points(policy_entry_t *pol_entry)
{
	return VAL_NOT_IMPLEMENTED;
}
int parse_dlv_max_links(FILE *fp, policy_entry_t *pol_entry, int *line_number)
{
	return VAL_NOT_IMPLEMENTED;
}
int free_dlv_max_links(policy_entry_t *pol_entry)
{
	return VAL_NOT_IMPLEMENTED;
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

#define READ_COMMENT_LINE(conf_ptr) do {\
	char linebuf[MAX_LINE_SIZE+1];\
	comment = 1;\
	conf_token[i] = '\0';\
	i = 0;\
	/* read off the remainder of the line */ \
	if(NULL == fgets(linebuf, MAX_LINE_SIZE, conf_ptr)) {\
		if (feof(conf_ptr)) { \
			if (escaped || quoted) \
				return VAL_CONF_PARSE_ERROR;\
		}\
		return VAL_NO_ERROR;\
	}\
	(*line_number)++;\
} while(0)

static int get_token ( FILE *conf_ptr,
				int *line_number,
				char *conf_token,
				int conf_limit, 
				int *endst,
				char comment_c,
				char endstmt_c)
{
	int        c;
	int         i = 0;
	int         escaped = 0;
	int         quoted = 0;
	int         comment = 0;
    
	*endst = 0;            
	strcpy (conf_token, "");

	do { 
		while (isspace (c=fgetc(conf_ptr))) {
			if (c == EOF) return VAL_NO_ERROR;
			if (c == '\n') {
				(*line_number)++;
			}
		}

		conf_token[i++] = c;
		/* Ignore lines that begin with comments */
		if (conf_token[0] == comment_c)
			READ_COMMENT_LINE(conf_ptr);
		else
			comment = 0;
	} while (comment);

	if (c == endstmt_c) {
		*endst = 1;
		conf_token[i]= '\0';
		return VAL_NO_ERROR;
	}

	if (c=='\\') escaped = 1 ;
	else if (c=='"') quoted = 1;

	/* Collect non-blanks and escaped blanks */
	while ((!isspace (c=fgetc(conf_ptr)) && (c != endstmt_c)) || escaped || quoted)
	{
		if (c == comment_c) {
			conf_token[i]= '\0';
			READ_COMMENT_LINE(conf_ptr);
			return VAL_NO_ERROR;
		}

		if (escaped)
		{
			if (feof(conf_ptr)) return VAL_CONF_PARSE_ERROR;
			escaped = 0;
		}
		else if (quoted)
		{
			if (feof(conf_ptr)) {
				conf_token[i]= '\0';
				return VAL_CONF_PARSE_ERROR;
			}
			if (c == '\n') return VAL_CONF_PARSE_ERROR;
			if (c == '"') quoted = 0;
		}
		else	
		{
			if (feof(conf_ptr)) return VAL_NO_ERROR;
			if (c=='\\') escaped = 1 ;
			else if (c=='"') quoted = 1;
		}

		if (c == '\n') (*line_number)++;
		if (i > conf_limit-1) return VAL_CONF_PARSE_ERROR;
		conf_token[i++] = c;
	}
	if (c == endstmt_c) *endst = 1;
	else if (c == '\n') (*line_number)++;

	conf_token[i]= '\0';
	return VAL_NO_ERROR;
}

/*
 * check the relevance of a policy label against the given
 * policy "scope" label. This is essentially strstr() but
 * we also determine how many leading "levels" (strings 
 * delimited by ':') are present before the exact match is
 * obtained.
 */
int check_relevance(char *label, char *scope, int *label_count, int *relevant)
{
	int label_len;
	char *c, *p;

	*relevant = 1;

	/* a "default" label is always relevant */
	if (!strcmp(label, LVL_DELIM)) {
		*label_count = 0;
		return VAL_NO_ERROR;
	}

	*label_count = 1;
	c = label;

	/* Check if this level is relevant */
	if (scope != NULL) {
		label_len = strlen(label);
		while (strcmp(c, scope)) {
			/* read ahead past the next delimiter */
			if(NULL == (p = strstr(c, LVL_DELIM))) {
				*relevant = 0;
				break;
			}
			c = p+1;
			(*label_count)++;	
		}

	}
	else {
		/* A NULL scope is always relevant */
		/* count the number of levels in the label */
		while(strstr(c, LVL_DELIM)) {
			(*label_count)++;
			c++;
		}
	}
	return VAL_NO_ERROR;
}

/*
 * Get the next relevant {label, keyword, data} fragment 
 * from the configuration file file
 */
static int get_next_policy_fragment(FILE *fp, char *scope, 
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
			conf_elem_array[index].free(&pol);
			pol = NULL;
		}

		if (VAL_NO_ERROR != (retval = get_token(fp, line_number, token, TOKEN_MAX, &endst, CONF_COMMENT, CONF_END_STMT)))
			return retval;
		if (feof(fp))
			return VAL_NO_ERROR;
		if (endst)
			return VAL_CONF_PARSE_ERROR;
		label = (char *) MALLOC (strlen(token) + 1);
		if (label == NULL)
			return VAL_OUT_OF_MEMORY;
		strcpy(label, token);

		/* read the keyword */
		if (VAL_NO_ERROR != (retval = get_token(fp, line_number, token, TOKEN_MAX, &endst, CONF_COMMENT, CONF_END_STMT)))
			return retval;
		if (feof(fp) || endst) {
			FREE (label);
			return VAL_CONF_PARSE_ERROR;
		}
		keyword = token;
		
		/* parse the remaining contents according to the keyword */	
		for (index=0; index<MAX_POL_TOKEN; index++) {
			if (!strcmp(keyword, conf_elem_array[index].keyword)) {

				if(conf_elem_array[index].parse(fp, &pol, line_number) != VAL_NO_ERROR) {
					FREE (label); 
					return VAL_CONF_PARSE_ERROR;
				}
				break;
			}
		}

		if (index == MAX_POL_TOKEN) {
			FREE (label); 
			return VAL_CONF_PARSE_ERROR;
		}

		if (VAL_NO_ERROR != (retval = (check_relevance(label, scope, &label_count, &relevant)))) {
			FREE (label);
			return retval;
		}
	} 

	*pol_frag = (struct policy_fragment *) MALLOC (sizeof (struct policy_fragment));
	if (*pol_frag == NULL) 
		return VAL_OUT_OF_MEMORY;
	(*pol_frag)->label = label; 
	(*pol_frag)->label_count = label_count;
	(*pol_frag)->index = index;
	(*pol_frag)->pol = pol;
	
	return VAL_NO_ERROR;
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
			return VAL_OUT_OF_MEMORY;

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
		return VAL_OUT_OF_MEMORY;
	entry->index = (*pfrag)->index;
	entry->pol = (*pfrag)->pol;
	entry->next = newp->plist;
	newp->plist = entry;

	(*pfrag)->label = NULL;
	(*pfrag)->pol = NULL;
	FREE(*pfrag);

	return VAL_NO_ERROR;
}

void destroy_valpol(val_context_t *ctx)
{
	int i;
	struct policy_overrides *cur, *prev;
	for (i = 0; i< MAX_POL_TOKEN; i++)
			ctx->e_pol[i] = NULL;

	prev = NULL;
	for (cur = ctx->pol_overrides; cur; prev = cur, cur = cur->next) {
			FREE (cur->label);
			conf_elem_array[cur->plist->index].free(&(cur->plist->pol));
			FREE (cur->plist);
			if (prev != NULL)
				FREE (prev);
	}
	if (prev != NULL)
		FREE (prev);
	ctx->pol_overrides = NULL;
	ctx->cur_override = NULL;

}
/*
 * Make sense of the validator configuration file
 */
int read_val_config_file(val_context_t *ctx, char *scope)
{
	FILE *fp;
	int fd;
	char *dnsval_conf;
	struct flock fl;
	struct policy_fragment *pol_frag = NULL;
	int retval;
	int line_number = 1;

	dnsval_conf = dnsval_conf_get();
	if (NULL == dnsval_conf)
		return VAL_INTERNAL_ERROR;

	/* free up existing policies */
	destroy_valpol(ctx);

	val_log(ctx, LOG_DEBUG, "Reading validator policy from %s", dnsval_conf);
	fd = open(dnsval_conf, O_RDONLY);
	if (fd == -1) {
		perror(dnsval_conf);
		return VAL_CONF_NOT_FOUND;
	}
	memset(&fl, 0, sizeof (fl));
	fl.l_type = F_RDLCK;
	fcntl(fd, F_SETLKW, &fl);
	fl.l_type = F_UNLCK;

	fp = fdopen(fd, "r");
	if(fp == NULL) {
		fcntl(fd, F_SETLKW, &fl);
		close(fd);
		return VAL_INTERNAL_ERROR;
	}

	val_log(ctx, LOG_DEBUG, "Reading next policy fragment");
	while (VAL_NO_ERROR == (retval = get_next_policy_fragment(fp, scope, &pol_frag, &line_number))) {
		if (feof(fp)) {
			fcntl(fd, F_SETLKW, &fl);
			fclose(fp);
			return VAL_NO_ERROR;
		}
		/* Store this fragment as an override, consume pol_frag */ 
		store_policy_overrides(ctx, &pol_frag);
	}

	val_log(ctx, LOG_ERR, "Error in line %d of file %s\n", line_number, dnsval_conf);
	fcntl(fd, F_SETLKW, &fl);
	fclose(fp);
	return retval;
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


int read_res_config_file(val_context_t *ctx)
{
	struct sockaddr_in serv_addr;
	struct in_addr  address;
	char auth_zone_info[NS_MAXDNAME];
	char *resolv_conf;
	FILE * fp;
	int fd;
	struct flock fl;
	char line[MAX_LINE_SIZE+1];
	struct name_server *ns_head = NULL;
	struct name_server *ns_tail = NULL;
	struct name_server *ns = NULL;

	ctx->nslist = NULL;

	strcpy(auth_zone_info, DEFAULT_ZONE);

	resolv_conf = resolver_config_get();
	if (NULL == resolv_conf)
		return VAL_INTERNAL_ERROR;

	val_log(ctx, LOG_DEBUG, "Reading resolver policy from %s", resolv_conf);
	fd = open(resolv_conf, O_RDONLY);
	if (fd == -1) {
		perror(resolv_conf);
		return VAL_CONF_NOT_FOUND;
	}
	fl.l_type = F_RDLCK;
	fcntl(fd, F_SETLKW, &fl);
	fl.l_type = F_UNLCK;

	fp = fdopen(fd, "r");
	if(fp == NULL) {
		fcntl(fd, F_SETLKW, &fl);
		close(fd);
		return VAL_INTERNAL_ERROR;
	}

	while (NULL != fgets(line, MAX_LINE_SIZE, fp)) {
																															 
		char *buf = NULL;
		char *cp = NULL;
		char white[] = " \t\n";

		if (strncmp(line, "nameserver", strlen("nameserver")) == 0) {

			strtok_r(line, white, &buf);
			cp = strtok_r(NULL, white, &buf);
			if (cp == NULL) {
				perror(resolv_conf);
				goto err;
			}

			ns = (struct name_server *) MALLOC (sizeof(struct name_server));
			if (ns == NULL)
				goto err;

			/* Convert auth_zone_info to its on-the-wire format */

			ns->ns_name_n = (u_int8_t *) MALLOC (NS_MAXCDNAME);
			if(ns->ns_name_n == NULL) 
				return VAL_OUT_OF_MEMORY;
			if (ns_name_pton(auth_zone_info, ns->ns_name_n, NS_MAXCDNAME-1) == -1) {
				FREE (ns->ns_name_n); 
				ns->ns_name_n = NULL;
				FREE (ns);
				ns = NULL;
				goto err;
			}

			/* Initialize the rest of the fields */
			ns->ns_tsig = NULL;
			ns->ns_security_options = ZONE_USE_NOTHING;
			ns->ns_status = 0;

			ns->ns_retrans = RES_TIMEOUT;
			ns->ns_retry = RES_RETRY;
			ns->ns_options = RES_DEFAULT | RES_RECURSE | RES_DEBUG;

			ns->ns_next = NULL;
			ns->ns_number_of_addresses = 0;

			if (inet_pton(AF_INET, cp, &address) != 1)
				goto err;
			bzero(&serv_addr, sizeof(struct sockaddr));
			serv_addr.sin_family = AF_INET;         // host byte order
			serv_addr.sin_port = htons(DNS_PORT);     // short, network byte order
			serv_addr.sin_addr = address;
			memcpy(ns->ns_address, &serv_addr, sizeof(struct sockaddr));

			if (ns_tail == NULL) {
				ns_head = ns;
				ns_tail = ns;
			}
			else {
				ns_tail->ns_next = ns;
				ns_tail = ns;
			}
		}
		else if (strncmp(line, "zone", strlen("zone")) == 0) {
			if (ns == NULL)	
				goto err;
			strtok_r(line, white, &buf);
			cp = strtok_r(NULL, white, &buf);
			if (cp == NULL) {
				perror(resolv_conf);
				goto err;
			}
			if (ns_name_pton(cp, ns->ns_name_n, NS_MAXCDNAME-1) == -1) 
				goto err;
		}
	}

	fcntl(fd, F_SETLKW, &fl);
	fclose(fp);

	if (ns_head == NULL) {
		get_root_ns(&ns_head);
		if(ns_head == NULL) 
			return VAL_CONF_NOT_FOUND;
	}

	ctx->nslist = ns_head;

	return VAL_NO_ERROR;

err:
	val_log (ctx, LOG_ERR, "Parse error in file %s\n", resolv_conf);
	free_name_servers(&ns_head);

	fcntl(fd, F_SETLKW, &fl);
	fclose(fp);
	return VAL_CONF_PARSE_ERROR;
}

/* parse the contents of the root.hints file into resource records */
int read_root_hints_file(val_context_t *ctx) 
{
	struct rrset_rec *root_info = NULL;
	FILE *fp;
	char token[TOKEN_MAX];
	char *root_hints;
	u_char zone_n[NS_MAXCDNAME];
	u_char rdata_n[NS_MAXCDNAME];
	int endst = 0;
	int line_number = 0;
	u_int16_t type_h, class_h;	
	int success;
	u_long ttl_h;
	int retval;
    u_int16_t           rdata_len_h;

	root_hints = root_hints_get();
	if (NULL == root_hints)
		return VAL_INTERNAL_ERROR;

	fp = fopen (root_hints, "r");
	if (fp == NULL) {
		return VAL_NO_ERROR;
	}

	/* name */
	if(VAL_NO_ERROR != (retval = get_token ( fp, &line_number, token, TOKEN_MAX, &endst, ZONE_COMMENT, ZONE_END_STMT)))
		return retval;

	while (!feof(fp)) {
   		if (ns_name_pton(token, zone_n, NS_MAXCDNAME-1) == -1)
       		return VAL_CONF_PARSE_ERROR; 
		
		/* ttl */
		if (feof(fp))
			return VAL_CONF_PARSE_ERROR;
		if(VAL_NO_ERROR != (retval = get_token ( fp, &line_number, token, TOKEN_MAX, &endst, ZONE_COMMENT, ZONE_END_STMT)))
			return retval;
		if (-1 == ns_parse_ttl(token, &ttl_h))
			return VAL_CONF_PARSE_ERROR;

		/* class */
		if (feof(fp))
			return VAL_CONF_PARSE_ERROR;
		if(VAL_NO_ERROR != (retval = get_token ( fp, &line_number, token, TOKEN_MAX, &endst, ZONE_COMMENT, ZONE_END_STMT)))
			return retval;
		class_h = res_nametoclass(token, &success);
		if (!success)
			return VAL_CONF_PARSE_ERROR;

		/* type */
		if (feof(fp))
			return VAL_CONF_PARSE_ERROR;
		if(VAL_NO_ERROR != (retval = get_token ( fp, &line_number, token, TOKEN_MAX, &endst, ZONE_COMMENT, ZONE_END_STMT)))
			return retval;
		type_h = res_nametotype(token, &success);
		if (!success)
			return VAL_CONF_PARSE_ERROR;

		if (feof(fp))
			return VAL_CONF_PARSE_ERROR;
		if(VAL_NO_ERROR != (retval = get_token ( fp, &line_number, token, TOKEN_MAX, &endst, ZONE_COMMENT, ZONE_END_STMT)))
			return retval;
		if(type_h == ns_t_a) {
			struct in_addr address;
			if (inet_pton(AF_INET, token, &address) != 1)
				return VAL_CONF_PARSE_ERROR;
			rdata_len_h = sizeof(struct in_addr);
        	memcpy (rdata_n, &address, rdata_len_h);
		}
		else if (type_h == ns_t_ns) {
   			if (ns_name_pton(token, rdata_n, NS_MAXCDNAME-1) == -1)
       			return VAL_CONF_PARSE_ERROR; 
			rdata_len_h = wire_name_length(rdata_n);
		}
		else 
			continue;

		SAVE_RR_TO_LIST(NULL, root_info, zone_n, type_h, type_h, ns_c_in, ttl_h, rdata_n, rdata_len_h, VAL_FROM_UNSET, 0); 

		/* name */
		if(VAL_NO_ERROR != (retval = get_token ( fp, &line_number, token, TOKEN_MAX, &endst, ZONE_COMMENT, ZONE_END_STMT)))
			return retval;
	}

	fclose(fp);

	return stow_root_info(root_info);
}

/*
 * Read ETC_HOSTS and return matching records
 */
struct hosts * parse_etc_hosts (const char *name)
{
	FILE *fp;
	char line[MAX_LINE_SIZE+1];
	char white[] = " \t\n";
	char fileentry[MAXLINE];
	struct hosts *retval = NULL;
	struct hosts *retval_tail = NULL;
	
	fp = fopen (ETC_HOSTS, "r");
	if (fp == NULL) {
		return NULL;
	}

	while (fgets (line, MAX_LINE_SIZE, fp) != NULL) {
		char *buf = NULL;
		char *cp = NULL;
		char addr_buf[INET6_ADDRSTRLEN];
		char *domain_name = NULL;
		int matchfound = 0;
		char *alias_list[MAX_ALIAS_COUNT];
		int alias_index = 0;
		
		if (line[0] == '#') continue;
		
		/* ignore characters after # */
		cp = (char *) strtok_r (line, "#", &buf);
		
		if (!cp) continue;
		
		memset(fileentry, 0, MAXLINE);
		memcpy(fileentry, cp, strlen(cp));
		
		/* read the ip address */
		cp = (char *) strtok_r (fileentry, white, &buf);
		if (!cp) continue;
		
		memset(addr_buf, 0, INET6_ADDRSTRLEN);
		memcpy(addr_buf, cp, strlen(cp));
		
		/* read the full domain name */
		cp = (char *) strtok_r (NULL, white, &buf);
		if (!cp) continue;
		
		domain_name = cp;
		
		if (strcasecmp(cp, name) == 0) {
			matchfound = 1;
		}
		
		/* read the aliases */
		memset(alias_list, 0, MAX_ALIAS_COUNT);
		alias_index = 0;
		while ((cp = (char *) strtok_r (NULL, white, &buf)) != NULL) {
			alias_list[alias_index++] = cp;
			if ((!matchfound) && (strcasecmp(cp, name) == 0)) {
				matchfound = 1;
			}
		}
		
		/* match input name with the full domain name and aliases */
		if (matchfound) {
			int i;
			struct hosts *hentry = (struct hosts*) MALLOC (sizeof(struct hosts));
			
			bzero(hentry, sizeof(struct hosts));
			hentry->address = (char *) strdup (addr_buf);
			hentry->canonical_hostname = (char *) strdup(domain_name);
			hentry->aliases = (char **) MALLOC ((alias_index + 1) * sizeof(char *));
			
			for (i=0; i<alias_index; i++) {
				hentry->aliases[i] = (char *) strdup(alias_list[i]);
			}
			
			hentry->aliases[alias_index] = NULL;
			hentry->next = NULL;
			
			if (retval) {
				retval_tail->next = hentry;
				retval_tail = hentry;
			}
			else {
				retval = hentry;
				retval_tail = hentry;
			}
		}
	}

	fclose(fp);
	
	return retval;
}
