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
#include <stdarg.h>
#include <sys/types.h>
#include <regex.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/file.h>
#include <resolv.h>
#ifndef VAL_NO_THREADS
#include <pthread.h>
#endif

#include <validator/resolver.h>
#include <validator/validator.h>
#include "val_policy.h"
#include "val_support.h"
#include "val_cache.h"
#include "val_resquery.h"
#include "val_context.h"
#include "val_assertion.h"


/*
 * forward declaration 
 */
int      val_get_token(FILE * conf_ptr,
                          int *line_number,
                          char *conf_token,
                          int conf_limit,
                          int *endst, char comment_c, char endstmt_c);
/*
 ***************************************************************
 * These are functions to read/set the location of the resolver
 * configuration and root.hints files.
 ***************************************************************
 */
static char    *resolv_conf = NULL;
static char    *root_hints = NULL;
static char    *dnsval_conf = NULL;

static int      atexit_reg = 0;

static void
policy_cleanup(void)
{
    if (NULL != resolv_conf)
        free(resolv_conf);

    if (NULL != root_hints)
        free(root_hints);

    if (NULL != dnsval_conf)
        free(dnsval_conf);
}


char           *
resolv_conf_get(void)
{
    if (NULL == resolv_conf) {
        if (0 == atexit_reg) {
            atexit_reg = 1;
            atexit(policy_cleanup);
        }
        resolv_conf = strdup(VAL_RESOLV_CONF);
    }

    return strdup(resolv_conf);
}

int
resolv_conf_set(const char *name)
{
    char           *new_name = strdup(name);

    if (NULL == new_name)
        return 1;

    if (NULL != resolv_conf)
        free(resolv_conf);
    else if (0 == atexit_reg) {
        atexit_reg = 1;
        atexit(policy_cleanup);
    }
    resolv_conf = new_name;

    return 0;
}

char           *
root_hints_get(void)
{
    if (NULL == root_hints) {
        if (0 == atexit_reg) {
            atexit_reg = 1;
            atexit(policy_cleanup);
        }

        root_hints = strdup(VAL_ROOT_HINTS);
    }

    return strdup(root_hints);
}

int
root_hints_set(const char *name)
{
    char           *new_name = strdup(name);

    if (NULL == new_name)
        return 1;

    if (NULL != root_hints)
        free(root_hints);
    else if (0 == atexit_reg) {
        atexit_reg = 1;
        atexit(policy_cleanup);
    }

    root_hints = new_name;

    return 0;
}

char           *
dnsval_conf_get(void)
{
    if (NULL == dnsval_conf)
        dnsval_conf = strdup(VAL_CONFIGURATION_FILE);

    return strdup(dnsval_conf);
}

int
dnsval_conf_set(const char *name)
{
    char           *new_name = strdup(name);

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
const struct policy_conf_element conf_elem_array[MAX_POL_TOKEN] = {
    {POL_TRUST_ANCHOR_STR, parse_trust_anchor, free_trust_anchor},
    {POL_PREFERRED_SEP_STR, parse_preferred_sep, free_preferred_sep},
    {POL_MUST_VERIFY_COUNT_STR, parse_must_verify_count,
     free_must_verify_count},
    {POL_PREFERRED_ALGORITHM_DATA_STR, parse_preferred_algo_data,
     free_preferred_algo_data},
    {POL_PREFERRED_ALGORITHM_KEYS_STR, parse_preferred_algo_keys,
     free_preferred_algo_keys},
    {POL_PREFERRED_ALGORITHM_DS_STR, parse_preferred_algo_ds,
     free_preferred_algo_ds},
    {POL_CLOCK_SKEW_STR, parse_clock_skew, free_clock_skew},
    {POL_EXPIRED_SIGS_STR, parse_expired_sigs, free_expired_sigs},
    {POL_USE_TCP_STR, parse_use_tcp, free_use_tcp},
    {POL_ZONE_SE_STR, parse_zone_security_expectation,
     free_zone_security_expectation},
#ifdef LIBVAL_NSEC3
    {POL_NSEC3_MAX_ITER_STR, parse_nsec3_max_iter, free_nsec3_max_iter},
#endif
#ifdef DLV
    {POL_DLV_TRUST_POINTS_STR, parse_dlv_trust_points,
     free_dlv_trust_points},
    {POL_DLV_MAX_LINKS_STR, parse_dlv_max_links, free_dlv_max_links},
#endif
};


int
parse_trust_anchor(FILE * fp, policy_entry_t * pol_entry, int *line_number)
{
    char            token[TOKEN_MAX];
    u_char          zone_n[NS_MAXCDNAME];
    struct trust_anchor_policy *ta_pol, *ta_head, *ta_cur, *ta_prev;
    int             retval;
    int             name_len;
    int             endst = 0;

    if ((fp == NULL) || (pol_entry == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    ta_head = NULL;

    while (!endst) {
        char           *pkstr;
        val_dnskey_rdata_t *dnskey_rdata;

        /*
         * Read the zone for which this trust anchor applies 
         */
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(fp, line_number, token, sizeof(token), &endst,
                       CONF_COMMENT, CONF_END_STMT))) {
            goto err;
        }
        if (endst && (strlen(token) == 1))
            break;
        if (feof(fp)) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }

        if (ns_name_pton(token, zone_n, sizeof(zone_n)) == -1) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }

        /*
         * XXX We may want to have another token that specifies if 
         * XXX this is a DS or a DNSKEY
         * XXX Assume public key for now
         */
        /*
         * Read the public key 
         */
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(fp, line_number, token, sizeof(token), &endst,
                       CONF_COMMENT, CONF_END_STMT)))
            goto err;
        if (feof(fp) && !endst) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }
        /*
         * Remove leading and trailing quotation marks 
         */
        if ((token[0] != '\"') ||
            (strlen(token) <= 1) || token[strlen(token) - 1] != '\"') {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }
        token[strlen(token) - 1] = '\0';
        pkstr = &token[1];


        // Parse the public key
        if (VAL_NO_ERROR !=
            (retval =
             val_parse_dnskey_string(pkstr, strlen(pkstr), &dnskey_rdata)))
            goto err;

        ta_pol = (struct trust_anchor_policy *)
            MALLOC(sizeof(struct trust_anchor_policy));
        if (ta_pol == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        name_len = wire_name_length(zone_n);
        memcpy(ta_pol->zone_n, zone_n, name_len);
        ta_pol->publickey = dnskey_rdata;

        /*
         * Store trust anchors in decreasing zone name length 
         */
        ta_prev = NULL;
        for (ta_cur = ta_head; ta_cur;
             ta_prev = ta_cur, ta_cur = ta_cur->next)
            if (wire_name_length(ta_cur->zone_n) <= name_len)
                break;
        if (ta_prev) {
            /*
             * store after ta_prev 
             */
            ta_pol->next = ta_prev->next;
            ta_prev->next = ta_pol;
        } else {
            ta_pol->next = ta_head;
            ta_head = ta_pol;
        }
    }

    *pol_entry = (policy_entry_t) (ta_head);

    return VAL_NO_ERROR;

  err:
    while ((ta_prev = ta_head)) {       /* double parens keep compiler happy) */
        ta_head = ta_head->next;
        FREE(ta_prev);
    }

    return retval;
}

int
free_trust_anchor(policy_entry_t * pol_entry)
{
    struct trust_anchor_policy *ta_head, *ta_cur, *ta_next;

    if (pol_entry == NULL)
        return VAL_NO_ERROR;

    ta_head = (struct trust_anchor_policy *) (*pol_entry);
    ta_cur = ta_head;
    while (ta_cur) {
        ta_next = ta_cur->next;
        /*
         * Free the val_dnskey_rdata_t structure 
         */
        FREE(ta_cur->publickey->public_key);
        FREE(ta_cur->publickey);
        FREE(ta_cur);
        ta_cur = ta_next;
    }

    return VAL_NO_ERROR;
}



int
parse_preferred_sep(FILE * fp, policy_entry_t * pol_entry,
                    int *line_number)
{
    return VAL_NOT_IMPLEMENTED;
}

int
free_preferred_sep(policy_entry_t * pol_entry)
{
    return VAL_NOT_IMPLEMENTED;
}

int
parse_must_verify_count(FILE * fp, policy_entry_t * pol_entry,
                        int *line_number)
{
    return VAL_NOT_IMPLEMENTED;
}

int
free_must_verify_count(policy_entry_t * pol_entry)
{
    return VAL_NOT_IMPLEMENTED;
}

int
parse_preferred_algo_data(FILE * fp, policy_entry_t * pol_entry,
                          int *line_number)
{
    return VAL_NOT_IMPLEMENTED;
}

int
free_preferred_algo_data(policy_entry_t * pol_entry)
{
    return VAL_NOT_IMPLEMENTED;
}

int
parse_preferred_algo_keys(FILE * fp, policy_entry_t * pol_entry,
                          int *line_number)
{
    return VAL_NOT_IMPLEMENTED;
}

int
free_preferred_algo_keys(policy_entry_t * pol_entry)
{
    return VAL_NOT_IMPLEMENTED;
}

int
parse_preferred_algo_ds(FILE * fp, policy_entry_t * pol_entry,
                        int *line_number)
{
    return VAL_NOT_IMPLEMENTED;
}

int
free_preferred_algo_ds(policy_entry_t * pol_entry)
{
    return VAL_NOT_IMPLEMENTED;
}

int
parse_clock_skew(FILE * fp, policy_entry_t * pol_entry, int *line_number)
{
    return VAL_NOT_IMPLEMENTED;
}

int
free_clock_skew(policy_entry_t * pol_entry)
{
    return VAL_NOT_IMPLEMENTED;
}

int
parse_expired_sigs(FILE * fp, policy_entry_t * pol_entry, int *line_number)
{
    return VAL_NOT_IMPLEMENTED;
}

int
free_expired_sigs(policy_entry_t * pol_entry)
{
    return VAL_NOT_IMPLEMENTED;
}

int
parse_use_tcp(FILE * fp, policy_entry_t * pol_entry, int *line_number)
{
    return VAL_NOT_IMPLEMENTED;
}

int
free_use_tcp(policy_entry_t * pol_entry)
{
    return VAL_NOT_IMPLEMENTED;
}

int
parse_zone_security_expectation(FILE * fp, policy_entry_t * pol_entry,
                                int *line_number)
{
    char            token[TOKEN_MAX];
    u_char          zone_n[NS_MAXCDNAME];
    struct zone_se_policy *zse_pol, *zse_head, *zse_cur, *zse_prev;
    int             retval;
    int             name_len;
    int             endst = 0;
    int             zone_status;

    if ((fp == NULL) || (pol_entry == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    zse_head = NULL;

    while (!endst) {

        /*
         * Read the zone for which this trust anchor applies 
         */
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(fp, line_number, token, sizeof(token), &endst,
                       CONF_COMMENT, CONF_END_STMT)))
            goto err;
        if (endst && (strlen(token) == 1))
            break;
        if (feof(fp)) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }

        if (ns_name_pton(token, zone_n, sizeof(zone_n)) == -1) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }

        /*
         * Read the zone status 
         */
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(fp, line_number, token, sizeof(token), &endst,
                       CONF_COMMENT, CONF_END_STMT)))
            goto err;
        if (feof(fp) && !endst) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }
        if (!strcmp(token, ZONE_SE_IGNORE_MSG))
            zone_status = ZONE_SE_IGNORE;
        else if (!strcmp(token, ZONE_SE_TRUSTED_MSG))
            zone_status = ZONE_SE_TRUSTED;
        else if (!strcmp(token, ZONE_SE_DO_VAL_MSG))
            zone_status = ZONE_SE_DO_VAL;
        else if (!strcmp(token, ZONE_SE_UNTRUSTED_MSG))
            zone_status = ZONE_SE_UNTRUSTED;
        else {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }

        zse_pol = (struct zone_se_policy *)
            MALLOC(sizeof(struct trust_anchor_policy));
        if (zse_pol == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        name_len = wire_name_length(zone_n);
        memcpy(zse_pol->zone_n, zone_n, name_len);
        zse_pol->trusted = zone_status;

        /*
         * Store trust anchors in decreasing zone name length 
         */
        zse_prev = NULL;
        for (zse_cur = zse_head; zse_cur;
             zse_prev = zse_cur, zse_cur = zse_cur->next)
            if (wire_name_length(zse_cur->zone_n) <= name_len)
                break;
        if (zse_prev) {
            /*
             * store after zse_prev 
             */
            zse_pol->next = zse_prev->next;
            zse_prev->next = zse_pol;
        } else {
            zse_pol->next = zse_head;
            zse_head = zse_pol;
        }
    }

    *pol_entry = (policy_entry_t) (zse_head);

    return VAL_NO_ERROR;

  err:
    while ((zse_prev = zse_head)) {     /* double parens keep compiler happy */
        zse_head = zse_head->next;
        FREE(zse_prev);
    }

    return retval;
}

int
free_zone_security_expectation(policy_entry_t * pol_entry)
{
    struct zone_se_policy *zse_cur, *zse_next;

    if ((pol_entry == NULL) || (*pol_entry == NULL))
        return VAL_NO_ERROR;

    zse_cur = (struct zone_se_policy *) (*pol_entry);
    while (zse_cur) {
        zse_next = zse_cur->next;
        FREE(zse_cur);
        zse_cur = zse_next;
    }

    (*pol_entry) = NULL;

    return VAL_NO_ERROR;
}


#ifdef LIBVAL_NSEC3
int
parse_nsec3_max_iter(FILE * fp, policy_entry_t * pol_entry,
                     int *line_number)
{
    struct nsec3_max_iter_policy *pol, *head, *cur, *prev;
    int             retval;
    int             endst = 0;

    char            token[TOKEN_MAX];
    u_char          zone_n[NS_MAXCDNAME];
    int             nsec3_iter;
    int             name_len;

    if ((fp == NULL) || (pol_entry == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    head = NULL;

    while (!endst) {

        /*
         * Read the zone for which this trust anchor applies 
         */
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(fp, line_number, token, sizeof(token), &endst,
                       CONF_COMMENT, CONF_END_STMT)))
            goto err;
        if (endst && (strlen(token) == 1))
            break;
        if (feof(fp)) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }
        if (ns_name_pton(token, zone_n, sizeof(zone_n)) == -1) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }

        /*
         * Read the corresponding value 
         */
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(fp, line_number, token, sizeof(token), &endst,
                       CONF_COMMENT, CONF_END_STMT)))
            goto err;
        if (feof(fp) && !endst) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }

        nsec3_iter = atoi(token);

        pol = (struct nsec3_max_iter_policy *)
            MALLOC(sizeof(struct nsec3_max_iter_policy));
        if (pol == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        name_len = wire_name_length(zone_n);
        memcpy(pol->zone_n, zone_n, name_len);
        pol->iter = nsec3_iter;

        /*
         * Store trust anchors in decreasing zone name length 
         */
        prev = NULL;
        for (cur = head; cur; prev = cur, cur = cur->next)
            if (wire_name_length(cur->zone_n) <= name_len)
                break;
        if (prev) {
            /*
             * store after prev 
             */
            pol->next = prev->next;
            prev->next = pol;
        } else {
            pol->next = head;
            head = pol;
        }
    }

    *pol_entry = (policy_entry_t) (head);

    return VAL_NO_ERROR;

  err:
    while ((prev = head)) {     /* double parens keep compiler happy */
        head = head->next;
        FREE(prev);
    }

    return retval;
}

int
free_nsec3_max_iter(policy_entry_t * pol_entry)
{
    struct nsec3_max_iter_policy *cur, *next;

    if ((pol_entry == NULL) || (*pol_entry == NULL))
        return VAL_NO_ERROR;

    cur = (struct nsec3_max_iter_policy *) (*pol_entry);
    while (cur) {
        next = cur->next;
        FREE(cur);
        cur = next;
    }

    (*pol_entry) = NULL;

    return VAL_NO_ERROR;
}
#endif

#ifdef DLV
int
parse_dlv_trust_points(FILE * fp, policy_entry_t * pol_entry,
                       int *line_number)
{
    return VAL_NOT_IMPLEMENTED;
}

int
free_dlv_trust_points(policy_entry_t * pol_entry)
{
    return VAL_NOT_IMPLEMENTED;
}

int
parse_dlv_max_links(FILE * fp, policy_entry_t * pol_entry,
                    int *line_number)
{
    return VAL_NOT_IMPLEMENTED;
}

int
free_dlv_max_links(policy_entry_t * pol_entry)
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

int
val_get_token(FILE * conf_ptr,
          int *line_number,
          char *conf_token,
          int conf_limit, int *endst, char comment_c, char endstmt_c)
{
    int             c;
    int             i = 0;
    int             escaped = 0;
    int             quoted = 0;
    int             comment = 0;

    if ((conf_ptr == NULL) || (line_number == NULL) ||
        (conf_token == NULL) || (endst == NULL))
        return VAL_BAD_ARGUMENT;

    *endst = 0;
    strcpy(conf_token, "");

    do {
        while (isspace(c = fgetc(conf_ptr))) {
            if (c == EOF)
                return VAL_NO_ERROR;
            if (c == '\n') {
                (*line_number)++;
            }
        }
        if (c == EOF)
            return VAL_NO_ERROR;

        conf_token[i++] = c;
        /*
         * Ignore lines that begin with comments 
         */
        if (conf_token[0] == comment_c)
            READ_COMMENT_LINE(conf_ptr);
        else
            comment = 0;
    } while (comment);

    if (c == endstmt_c) {
        *endst = 1;
        conf_token[i] = '\0';
        return VAL_NO_ERROR;
    }

    if (c == '\\')
        escaped = 1;
    else if (c == '"')
        quoted = 1;

    /*
     * Collect non-blanks and escaped blanks 
     */
    while ((!isspace(c = fgetc(conf_ptr)) && (c != endstmt_c)) || escaped
           || quoted) {
        if (c == comment_c) {
            conf_token[i] = '\0';
            READ_COMMENT_LINE(conf_ptr);
            return VAL_NO_ERROR;
        }

        if (escaped) {
            if (feof(conf_ptr))
                return VAL_CONF_PARSE_ERROR;
            escaped = 0;
        } else if (quoted) {
            if (feof(conf_ptr)) {
                conf_token[i] = '\0';
                return VAL_CONF_PARSE_ERROR;
            }
            if (c == '\n')
                return VAL_CONF_PARSE_ERROR;
            if (c == '"')
                quoted = 0;
        } else {
            if (feof(conf_ptr))
                return VAL_NO_ERROR;
            if (c == '\\')
                escaped = 1;
            else if (c == '"')
                quoted = 1;
        }

        if (c == '\n')
            (*line_number)++;
        if (i > conf_limit - 1)
            return VAL_CONF_PARSE_ERROR;
        conf_token[i++] = c;
    }
    if (c == endstmt_c)
        *endst = 1;
    else if (c == '\n')
        (*line_number)++;

    conf_token[i] = '\0';
    return VAL_NO_ERROR;
}

/*
 * check the relevance of a policy label against the given
 * policy "scope" label. This is essentially strstr() but
 * we also determine how many leading "levels" (strings 
 * delimited by ':') are present before the exact match is
 * obtained.
 */
int
check_relevance(char *label, char *scope, int *label_count, int *relevant)
{
    char           *c, *p, *e;

    /*
     * sanity check; NULL scope is OK 
     */
    if ((label == NULL) || (label_count == NULL) || (relevant == NULL))
        return VAL_BAD_ARGUMENT;

    *relevant = 1;

    c = scope;
    *label_count = 1;

    /*
     * a NULL scope is always relevant 
     */
    if (c == NULL) {
        if (!strcmp(label, LVL_DELIM))
            *label_count = 0;
        return VAL_NO_ERROR;
    }

    e = c + strlen(scope);

    /*
     * Check if this is relevant 
     */
    while ((c < e) && (NULL != (p = strstr(c, LVL_DELIM)))) {

        if (((p != c) && (!strncmp(label, c, p - c))) ||
            (!strcmp(label, LVL_DELIM)))
            return VAL_NO_ERROR;

        (*label_count)++;
        c = p + 1;
    }

    /*
     * See if the remaining string is an exact match 
     */
    if (!strcmp(label, c))
        return VAL_NO_ERROR;

    *relevant = 0;
    return VAL_NO_ERROR;
}

/*
 * Get the next relevant {label, keyword, data} fragment 
 * from the configuration file file
 */
static int
get_next_policy_fragment(FILE * fp, char *scope,
                         struct policy_fragment **pol_frag,
                         int *line_number)
{
    char            token[TOKEN_MAX];
    int             retval;
    char           *keyword, *label = NULL;
    int             relevant = 0;
    int             label_count;
    int             endst;
    policy_entry_t  pol = NULL;
    int             index = 0;

    if ((fp == NULL) || (pol_frag == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    while (!relevant) {

        /*
         * free up previous iteration policy 
         */
        if (pol != NULL) {
            conf_elem_array[index].free(&pol);
            pol = NULL;
        }

        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(fp, line_number, token, sizeof(token), &endst,
                       CONF_COMMENT, CONF_END_STMT)))
            return retval;
        if (feof(fp))
            return VAL_NO_ERROR;
        if (endst)
            return VAL_CONF_PARSE_ERROR;
        if (label != NULL)
            FREE(label);
        label = (char *) MALLOC(strlen(token) + 1);
        if (label == NULL)
            return VAL_OUT_OF_MEMORY;
        strcpy(label, token);

        /*
         * The : character can only appear in the label 
         * if this is the default policy 
         */
        if (strstr(label, LVL_DELIM) && strcmp(label, LVL_DELIM)) {
            FREE(label);
            return VAL_CONF_PARSE_ERROR;
        }

        /*
         * read the keyword 
         */
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(fp, line_number, token, sizeof(token), &endst,
                       CONF_COMMENT, CONF_END_STMT))) {
            FREE(label);
            return retval;
        }
        if (feof(fp) || endst) {
            FREE(label);
            return VAL_CONF_PARSE_ERROR;
        }
        keyword = token;

        /*
         * parse the remaining contents according to the keyword 
         */
        for (index = 0; index < MAX_POL_TOKEN; index++) {
            if (!strcmp(keyword, conf_elem_array[index].keyword)) {

                if (conf_elem_array[index].parse(fp, &pol, line_number) !=
                    VAL_NO_ERROR) {
                    FREE(label);
                    return VAL_CONF_PARSE_ERROR;
                }
                break;
            }
        }

        if (index == MAX_POL_TOKEN) {
            FREE(label);
            return VAL_CONF_PARSE_ERROR;
        }

        if (VAL_NO_ERROR !=
            (retval =
             (check_relevance(label, scope, &label_count, &relevant)))) {
            FREE(label);
            return retval;
        }
    }

    *pol_frag =
        (struct policy_fragment *) MALLOC(sizeof(struct policy_fragment));
    if (*pol_frag == NULL) {
        if (label != NULL)
            FREE(label);
        return VAL_OUT_OF_MEMORY;
    }
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
static int
store_policy_overrides(val_context_t * ctx, 
                       struct policy_overrides **overrides, 
                       struct policy_fragment **pfrag)
{
    struct policy_overrides *cur, *prev, *newp;
    struct policy_list *e;

    if ((ctx == NULL) || (overrides == NULL) || (pfrag == NULL) || (*pfrag == NULL))
        return VAL_BAD_ARGUMENT;

    /*
     * search for a node with this label 
     */
    cur = prev = NULL;
    newp = NULL;

    for (cur = *overrides;
         cur && (cur->label_count <= (*pfrag)->label_count);
         cur = cur->next) {

        if (!strcmp(cur->label, (*pfrag)->label)) {
            /*
             * exact match; 
             */
            newp = cur;
            FREE((*pfrag)->label);
            (*pfrag)->label = NULL;
            break;
        }
        prev = cur;
    }

    if (newp == NULL) {

        newp = (struct policy_overrides *)
            MALLOC(sizeof(struct policy_overrides));
        if (newp == NULL)
            return VAL_OUT_OF_MEMORY;

        newp->label = (*pfrag)->label;
        newp->label_count = (*pfrag)->label_count;
        newp->plist = NULL;

        if (prev) {
            newp->next = prev->next;
            prev->next = newp;
        } else {
            newp->next = cur;
            *overrides = newp;
        }
    }

    /*
     * Add this entry to the list 
     */
    for (e = newp->plist; e; e = e->next) {
        if (e->index == (*pfrag)->index) {
            val_log(ctx, LOG_WARNING,
                    "Duplicate policy definition; using latest");
            conf_elem_array[e->index].free(&e->pol);
            break;
        }
    }

    if (!e) {
        e = (struct policy_list *) MALLOC(sizeof(struct policy_list));
        if (e == NULL)
            return VAL_OUT_OF_MEMORY;
        e->index = (*pfrag)->index;
        e->next = newp->plist;
        newp->plist = e;
    }

    e->pol = (*pfrag)->pol;
    (*pfrag)->pol = NULL;
    FREE(*pfrag);

    return VAL_NO_ERROR;
}

static void
destroy_valpolovr(struct policy_overrides **po)
{
    struct policy_overrides *cur, *prev;

    if ((NULL == po) || (NULL == *po))
        return;

    cur = *po;
    while (cur) {
        struct policy_list *plist, *plist_next;

        prev = cur;
        cur = cur->next;

        FREE(prev->label);
        for (plist = prev->plist; plist; plist = plist_next) {
            plist_next = plist->next;
            if ((plist->pol != NULL) && (plist->index < MAX_POL_TOKEN))
                conf_elem_array[plist->index].free(&(plist->pol));
            FREE(plist);
        }
        FREE(prev);
    }
    *po = NULL;
}

void
destroy_valpol(val_context_t * ctx)
{
    int             i;

    if (ctx == NULL)
        return;

    for (i = 0; i < MAX_POL_TOKEN; i++)
        ctx->e_pol[i] = NULL;

    destroy_valpolovr(&ctx->pol_overrides);

    ctx->cur_override = NULL;

}



/*
 * Make sense of the validator configuration file
 */
int
read_val_config_file(val_context_t * ctx, char *scope)
{
    FILE           *fp;
    int             fd;
    char           *dnsval_conf;
    struct flock    fl;
    struct policy_fragment *pol_frag = NULL;
    int             retval;
    int             line_number = 1;
    struct policy_overrides *overrides = NULL;
    struct stat sb;
   
    if (ctx == NULL)
        return VAL_BAD_ARGUMENT;
    
    dnsval_conf = ctx->dnsval_conf;
    if (NULL == dnsval_conf)
        return VAL_INTERNAL_ERROR;

    if (0 != stat(dnsval_conf, &sb)) 
        return VAL_CONF_NOT_FOUND;

    ctx->v_timestamp = sb.st_mtime;
    
    fd = open(dnsval_conf, O_RDONLY);
    if (fd == -1) {
        val_log(ctx, LOG_ERR, "Could not open validator conf file for reading: %s",
                dnsval_conf);
        return VAL_CONF_NOT_FOUND;
    }
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_RDLCK;
    fcntl(fd, F_SETLKW, &fl);
    fl.l_type = F_UNLCK;

    fp = fdopen(fd, "r");
    if (fp == NULL) {
        fcntl(fd, F_SETLKW, &fl);
        close(fd);
        val_log(ctx, LOG_ERR, "Could not open validator conf file for reading: %s",
                dnsval_conf);
        return VAL_INTERNAL_ERROR;
    }

    val_log(ctx, LOG_NOTICE, "Reading validator policy from %s",
            dnsval_conf);
    val_log(ctx, LOG_DEBUG, "Reading next policy fragment");
    while (VAL_NO_ERROR ==
           (retval =
            get_next_policy_fragment(fp, scope, &pol_frag,
                                     &line_number))) {
        if (feof(fp)) {
            retval = VAL_NO_ERROR;
            break;
        }
        /*
         * Store this fragment as an override, consume pol_frag 
         */
        store_policy_overrides(ctx, &overrides, &pol_frag);
    }

    fcntl(fd, F_SETLKW, &fl);
    fclose(fp);

    if (retval != VAL_NO_ERROR) {
        val_log(ctx, LOG_ERR, "Error in line %d of file %s", line_number,
                dnsval_conf);
    } else {
        if (scope == NULL) {
            /*
             * Use the first policy as the default (only) policy 
             */
            if (overrides)
                destroy_valpolovr(&overrides->next);
        }
    }

    CTX_LOCK_VALPOL_EX(ctx);
    destroy_valpol(ctx);
    ctx->pol_overrides = overrides;
    OVERRIDE_POLICY(ctx);

    /* 
     * Re-initialize caches 
     */
    free_query_chain(ctx->q_list);
    free_authentication_chain(ctx->a_list);

    ctx->q_list = NULL;
    ctx->a_list = NULL;

    CTX_UNLOCK_VALPOL(ctx);

    val_log(ctx, LOG_DEBUG, "Done reading validator configuration");

    return retval;
}


/*
 ****************************************************
 * Following routines handle parsing of the resolver 
 * configuration file
 ****************************************************
 */

void
destroy_respol(val_context_t * ctx)
{
    if ((ctx != NULL) && (ctx->nslist != NULL)) {
        free_name_servers(&ctx->nslist);
        ctx->nslist = NULL;
    }
}

static int
parse_name_server(val_context_t *ctx, char *cp, struct name_server **ns)
{ 
    struct sockaddr_in serv_addr;
    struct in_addr  address;

    if (cp ==  NULL || ns == NULL)
        return VAL_BAD_ARGUMENT;

    *ns = (struct name_server *) MALLOC(sizeof(struct name_server));
    if (*ns == NULL)
        return VAL_OUT_OF_MEMORY; 

    if (ns_name_pton(DEFAULT_ZONE, (*ns)->ns_name_n, 
                sizeof((*ns)->ns_name_n)) == -1) {
        FREE(*ns);
        *ns = NULL;
        return VAL_CONF_PARSE_ERROR; 
    }

    /*
     * Initialize the rest of the fields 
     */
    (*ns)->ns_tsig = NULL;
    (*ns)->ns_security_options = ZONE_USE_NOTHING;
    (*ns)->ns_status = 0;

    (*ns)->ns_retrans = RES_TIMEOUT;
    (*ns)->ns_retry = RES_RETRY;
    (*ns)->ns_options = RES_DEFAULT | RES_RECURSE | RES_DEBUG;

    (*ns)->ns_next = NULL;
    (*ns)->ns_number_of_addresses = 0;

    if (inet_pton(AF_INET, cp, &address) != 1) {
        /*
         * drop ipv6 addresses and keep parsing 
         */
        if (inet_pton(AF_INET6, cp, &address) == 1) {
            val_log(ctx, LOG_WARNING,
                    "Parse warning: IPv6 nameserver addresses not handled yet, skipping.");
            FREE(*ns);
            *ns = NULL;
            return VAL_NO_ERROR;
        } else
            return VAL_CONF_PARSE_ERROR; 
    }

    bzero(&serv_addr, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;     // host byte order
    serv_addr.sin_port = htons(DNS_PORT);       // short, network byte order
    serv_addr.sin_addr = address;

    (*ns)->ns_address = NULL;
    CREATE_NSADDR_ARRAY((*ns)->ns_address, 1);
    if ((*ns)->ns_address == NULL) {
        FREE(*ns);
        *ns = NULL;
        return VAL_OUT_OF_MEMORY;
    }
    (*ns)->ns_number_of_addresses = 1;

    memcpy((*ns)->ns_address[0], &serv_addr,
           sizeof(struct sockaddr_in));
    (*ns)->ns_number_of_addresses = 1;
    return VAL_NO_ERROR;
}

int
read_res_config_file(val_context_t * ctx)
{
    char           *resolv_config;
    FILE           *fp;
    int             fd;
    struct flock    fl;
    char            line[MAX_LINE_SIZE + 1];
    struct name_server *ns_head = NULL;
    struct name_server *ns_tail = NULL;
    struct name_server *ns = NULL;
    u_int8_t zone_n[NS_MAXCDNAME];
    struct stat sb;

    if (ctx == NULL)
        return VAL_BAD_ARGUMENT;

    resolv_config = ctx->resolv_conf;
    if (NULL == resolv_config)
        return VAL_INTERNAL_ERROR;

    if (0 != stat(resolv_config, &sb)) 
        return VAL_CONF_NOT_FOUND;

    ctx->r_timestamp = sb.st_mtime;

    fd = open(resolv_config, O_RDONLY);
    if (fd == -1) {
        val_log(ctx, LOG_ERR, "Could not open resolver conf file for reading: %s",
                resolv_conf);
        return VAL_CONF_NOT_FOUND;
    }
    fl.l_type = F_RDLCK;
    fcntl(fd, F_SETLKW, &fl);
    fl.l_type = F_UNLCK;

    fp = fdopen(fd, "r");
    if (fp == NULL) {
        fcntl(fd, F_SETLKW, &fl);
        close(fd);
        val_log(ctx, LOG_ERR, "Could not open resolver conf file for reading: %s",
                resolv_conf);
        return VAL_INTERNAL_ERROR;
    }

    val_log(ctx, LOG_NOTICE, "Reading resolver policy from %s", resolv_config);

    while (NULL != fgets(line, MAX_LINE_SIZE, fp)) {

        char           *buf = NULL;
        char           *cp = NULL;
        char            white[] = " \t\n";

        if (strncmp(line, "nameserver", strlen("nameserver")) == 0) {

            strtok_r(line, white, &buf);
            cp = strtok_r(NULL, white, &buf);
            if (cp == NULL) {
                goto err;
            }
            
            ns = NULL;
            if (VAL_NO_ERROR != parse_name_server(ctx, cp, &ns))
                goto err;
            if (ns != NULL) {
                if (ns_tail == NULL) {
                    ns_head = ns;
                    ns_tail = ns;
                } else {
                    ns_tail->ns_next = ns;
                    ns_tail = ns;
                }
            }
        } else if (strncmp(line, "forward", strlen("forward")) == 0) { 
            strtok_r(line, white, &buf);
            cp = strtok_r(NULL, white, &buf);
            if (cp == NULL) 
                goto err;
            if (ns_name_pton(cp, zone_n, sizeof(zone_n)) == -1)
                goto err;
                
            cp = strtok_r(NULL, white, &buf);
            if (cp == NULL) 
                goto err;
            ns = NULL;
            if (VAL_NO_ERROR != parse_name_server(ctx, cp, &ns))
                goto err;
            if (ns != NULL) {
                store_ns_for_zone(zone_n, ns);
            }
        }
    }

    fcntl(fd, F_SETLKW, &fl);
    fclose(fp);

    /*
     * Check if we have root hints 
     */
    if (ns_head == NULL) {
        if (!ctx->root_ns) {
            val_log(ctx, LOG_ERR, "Resolver configuration is empty, but root-hints was not found");
            return VAL_CONF_NOT_FOUND;
        }
    } 

    CTX_LOCK_RESPOL_EX(ctx);
    destroy_respol(ctx);
    ctx->nslist = ns_head;
    CTX_UNLOCK_RESPOL(ctx);

    val_log(ctx, LOG_DEBUG, "Done reading resolver configuration");
    return VAL_NO_ERROR;

  err:
    val_log(ctx, LOG_ERR, "Error encountered while reading file %s", resolv_config);
    free_name_servers(&ns_head);

    fcntl(fd, F_SETLKW, &fl);
    fclose(fp);
    return VAL_CONF_PARSE_ERROR;
}

/*
 * parse the contents of the root.hints file into resource records 
 */
int
read_root_hints_file(val_context_t * ctx)
{
    struct rrset_rec *root_info = NULL;
    FILE           *fp;
    char            token[TOKEN_MAX];
    char           *root_hints;
    u_char          zone_n[NS_MAXCDNAME];
    u_char          rdata_n[NS_MAXCDNAME];
    u_char          root_zone_n[NS_MAXCDNAME];
    int             endst = 0;
    int             line_number = 0;
    u_int16_t       type_h, class_h;
    int             success;
    u_long          ttl_h;
    int             retval;
    u_int16_t       rdata_len_h;
    struct rrset_rec *rr_set;
    struct name_server *ns_list = NULL;
    struct name_server *pending_glue = NULL;    
    struct stat sb;
    int have_type;

    class_h = 0;
    have_type = 0;

    if (ctx == NULL)
        return VAL_BAD_ARGUMENT;
    
    root_hints = ctx->root_conf;
    /* 
     *  Root hints are not necessary. Only needed if our resolv.conf is empty. 
     * Flag the error at that time
     */
    if (NULL == root_hints)
        return VAL_NO_ERROR;
    if (0 != stat(root_hints, &sb)) 
        return VAL_NO_ERROR;

    ctx->h_timestamp = sb.st_mtime;

    fp = fopen(root_hints, "r");
    if (fp == NULL) {
        val_log(ctx, LOG_ERR, "Could not open root hints file for reading: %s",
            root_hints);
        return VAL_NO_ERROR;
    }

    val_log(ctx, LOG_NOTICE, "Reading root hints from %s",
            root_hints);
    /*
     * name 
     */
    if (VAL_NO_ERROR !=
        (retval =
         val_get_token(fp, &line_number, token, sizeof(token), &endst,
                   ZONE_COMMENT, ZONE_END_STMT))) {
        fclose(fp);
        goto err;
    }

    while (!feof(fp)) {
        if (ns_name_pton(token, zone_n, sizeof(zone_n)) == -1) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }

        /*
         * ttl 
         */
        if (feof(fp)) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(fp, &line_number, token, sizeof(token), &endst,
                       ZONE_COMMENT, ZONE_END_STMT))) {
            goto err;
            
        }
        if (-1 == ns_parse_ttl(token, &ttl_h)) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }

        /*
         * class 
         */
        if (feof(fp)) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(fp, &line_number, token, sizeof(token), &endst,
                       ZONE_COMMENT, ZONE_END_STMT))) {
            goto err;
        }
        class_h = res_nametoclass(token, &success);
        if (!success) {
            if(class_h == 0) {
                retval = VAL_CONF_PARSE_ERROR;
                goto err;
            }
            have_type = 1;
        }
        
        if (!have_type) {
            /*
             * type 
             */
            if (feof(fp)) {
                retval = VAL_CONF_PARSE_ERROR;
                goto err;
            }
            if (VAL_NO_ERROR !=
                (retval =
                val_get_token(fp, &line_number, token, sizeof(token), &endst,
                       ZONE_COMMENT, ZONE_END_STMT))) {
                goto err;
            }
        }

        have_type = 0;
        type_h = res_nametotype(token, &success);
        if (!success) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }

        if (feof(fp)) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(fp, &line_number, token, sizeof(token), &endst,
                       ZONE_COMMENT, ZONE_END_STMT))) {
            goto err;
        }
        if (type_h == ns_t_a) {
            struct in_addr  address;
            if (inet_pton(AF_INET, token, &address) != 1) {
                retval = VAL_CONF_PARSE_ERROR;
                goto err;
            }
            rdata_len_h = sizeof(struct in_addr);
            memcpy(rdata_n, &address, rdata_len_h);
        } else if (type_h == ns_t_ns) {
            if (ns_name_pton(token, rdata_n, sizeof(rdata_n)) == -1) {
                retval = VAL_CONF_PARSE_ERROR;
                goto err;
            }
            rdata_len_h = wire_name_length(rdata_n);
        } else
            continue;

        //        SAVE_RR_TO_LIST(NULL, &root_info, zone_n, type_h, type_h, ns_c_in,
        //                        ttl_h, NULL, rdata_n, rdata_len_h, VAL_FROM_UNSET, 0,
        //                        zone_n);
        rr_set = find_rr_set(NULL, &root_info, zone_n, type_h, type_h,
                             ns_c_in, ttl_h, NULL, rdata_n, VAL_FROM_UNSET,
                             0, zone_n);
        if (rr_set == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        if (type_h != ns_t_rrsig) {
            /** Add this record to its chain of rr_rec's. */
            retval = add_to_set(rr_set, rdata_len_h, rdata_n);
        } else {
            /** Add this record to the sig of rrset_rec. */
            retval = add_as_sig(rr_set, rdata_len_h, rdata_n);
        }
        if (retval != VAL_NO_ERROR) {
            goto err;
        }
        // end save_rr_to_list

        /*
         * name 
         */
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(fp, &line_number, token, sizeof(token), &endst,
                       ZONE_COMMENT, ZONE_END_STMT))) {
            goto err;
        }
    }


    memset(root_zone_n, 0, sizeof(root_zone_n)); /** on-the-wire encoding for root zone **/

    if (VAL_NO_ERROR !=
        (retval =
         res_zi_unverified_ns_list(&ns_list, root_zone_n, root_info,
                                   &pending_glue))) {

        goto err;
    }

    /*
     * We are not interested in fetching glue for the root 
     */
    free_name_servers(&pending_glue);

#if 0
    {
    struct name_server *tempns;
    for(tempns = ns_list; tempns; tempns= tempns->ns_next) {
        printf ("Root name servers for %s :\n", tempns->ns_name_n);
        struct sockaddr_in  *s=(struct sockaddr_in*)(tempns->ns_address[0]);
        printf("%s\n", inet_ntoa(s->sin_addr)); 
    }
    }
#endif

    CTX_LOCK_RESPOL_EX(ctx);
    if (ctx->root_ns)
        free_name_servers(&ctx->root_ns);
    ctx->root_ns = ns_list;
    CTX_UNLOCK_RESPOL(ctx);

    res_sq_free_rrset_recs(&root_info);

    val_log(ctx, LOG_DEBUG, "Done reading root hints");
    fclose(fp);

    return retval;

  err:

    fclose(fp);
    res_sq_free_rrset_recs(&root_info);
    val_log(ctx, LOG_ERR, "Error encountered while reading file %s", root_hints);
    return retval;
}

/*
 * Read ETC_HOSTS and return matching records
 */
struct hosts   *
parse_etc_hosts(const char *name)
{
    FILE           *fp;
    char            line[MAX_LINE_SIZE + 1];
    char            white[] = " \t\n";
    char            fileentry[MAXLINE];
    struct hosts   *retval = NULL;
    struct hosts   *retval_tail = NULL;

    if (name == NULL)
        return NULL;

    fp = fopen(ETC_HOSTS, "r");
    if (fp == NULL) {
        return NULL;
    }

    while (fgets(line, MAX_LINE_SIZE, fp) != NULL) {
        char           *buf = NULL;
        char           *cp = NULL;
        char            addr_buf[INET6_ADDRSTRLEN];
        char           *domain_name = NULL;
        int             matchfound = 0;
        char           *alias_list[MAX_ALIAS_COUNT];
        int             alias_index = 0;
        int             i;
        struct hosts   *hentry;

        if (line[0] == '#')
            continue;

        /*
         * ignore characters after # 
         */
        cp = (char *) strtok_r(line, "#", &buf);

        if (!cp)
            continue;

        memset(fileentry, 0, MAXLINE);
        strncpy(fileentry, cp, sizeof(fileentry));

        /*
         * read the ip address 
         */
        cp = (char *) strtok_r(fileentry, white, &buf);
        if (!cp)
            continue;

        memset(addr_buf, 0, INET6_ADDRSTRLEN);
        strncpy(addr_buf, cp, sizeof(addr_buf));

        /*
         * read the full domain name 
         */
        cp = (char *) strtok_r(NULL, white, &buf);
        if (!cp)
            continue;

        domain_name = cp;

        if (strcasecmp(cp, name) == 0) {
            matchfound = 1;
        }

        /*
         * read the aliases 
         */
        memset(alias_list, 0, MAX_ALIAS_COUNT);
        alias_index = 0;
        while ((cp = (char *) strtok_r(NULL, white, &buf)) != NULL) {
            alias_list[alias_index++] = cp;
            if ((!matchfound) && (strcasecmp(cp, name) == 0)) {
                matchfound = 1;
            }
        }

        if (!matchfound)
            continue;

        /*
         * match input name with the full domain name and aliases 
         */
        hentry = (struct hosts *) MALLOC(sizeof(struct hosts));
        if (hentry == NULL)
            break;              /* return results so far */

        bzero(hentry, sizeof(struct hosts));
        hentry->address = (char *) strdup(addr_buf);
        hentry->canonical_hostname = (char *) strdup(domain_name);
        hentry->aliases =
            (char **) MALLOC((alias_index + 1) * sizeof(char *));
        if ((hentry->aliases == NULL) || (hentry->address == NULL)
            || (hentry->canonical_hostname == NULL)) {
            if (hentry->address != NULL)
                free(hentry->address);
            if (hentry->canonical_hostname != NULL)
                free(hentry->canonical_hostname);
            if (hentry->aliases != NULL)
                free(hentry->aliases);
            free(hentry);
            break;              /* return results so far */
        }

        for (i = 0; i < alias_index; i++) {
            hentry->aliases[i] = (char *) strdup(alias_list[i]);
            if (hentry->aliases[i] == NULL)
                break;          /* return results so far */
        }
        for (; i <= alias_index; i++) {
            hentry->aliases[i] = NULL;
        }
        hentry->next = NULL;

        if (retval) {
            retval_tail->next = hentry;
            retval_tail = hentry;
        } else {
            retval = hentry;
            retval_tail = hentry;
        }
    }

    fclose(fp);

    return retval;
}
