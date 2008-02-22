/*
 * Copyright 2005-2007 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
/*
 * DESCRIPTION
 * Read the contents of the resolver, validator and root.hints configuration 
 * files and update the validator context.
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
#include <validator/validator-internal.h>
#include "val_policy.h"
#include "val_support.h"
#include "val_cache.h"
#include "val_resquery.h"
#include "val_context.h"
#include "val_assertion.h"

#define READ_POL_FOR_ZONE(buf_ptr, end_ptr, line_number, endst, retval, err, token)  do {\
    /*\
     * Read the corresponding value \
     */\
    if (VAL_NO_ERROR != (retval =\
         val_get_token(buf_ptr, end_ptr, line_number, token, sizeof(token), endst,\
                       CONF_COMMENT, CONF_END_STMT)))\
        return retval;\
} while (0)

#define STORE_POLICY_ENTRY_IN_LIST(pol, head) do {\
    policy_entry_t *prev, *cur, *next;\
    while (pol) {\
        next = pol->next;\
        int name_len = wire_name_length(pol->zone_n);\
        /*\
         * Store according to decreasing zone name length \
         */\
        prev = NULL;\
        for (cur = head; cur;\
            prev = cur, cur = cur->next)\
            if (wire_name_length(cur->zone_n) <= name_len)\
                break;\
        if (prev) {\
            /*\
             * store after prev \
             */\
            pol->next = prev->next;\
            prev->next = pol;\
        } else {\
            pol->next = head;\
            head = pol;\
        }\
        pol = next;\
    }\
} while (0)


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


int free_policy_entry(policy_entry_t *pol_entry, int index)
{
    policy_entry_t *cur, *next;

    if (pol_entry == NULL)
        return VAL_NO_ERROR;

    cur = pol_entry;
    while (cur) {
        next = cur->next;
        /*
         * Free the val_dnskey_rdata_t structure 
         */
        conf_elem_array[index].free(cur);
        FREE(cur);
        cur = next;
    }

    return VAL_NO_ERROR;

}

/*
 ***************************************************************
 * The following are the parsing and freeup routines for 
 * different policy fragments in the validator configuration
 * file
 **************************************************************
 */
const struct policy_conf_element conf_elem_array[MAX_POL_TOKEN] = {
    {POL_TRUST_ANCHOR_STR, parse_trust_anchor, free_trust_anchor},
    {POL_CLOCK_SKEW_STR, parse_clock_skew, free_clock_skew},
    {POL_PROV_UNSEC_STR, parse_prov_unsecure_status, 
     free_prov_unsecure_status},
    {POL_ZONE_SE_STR, parse_zone_security_expectation,
     free_zone_security_expectation},
#ifdef LIBVAL_NSEC3
    {POL_NSEC3_MAX_ITER_STR, parse_nsec3_max_iter, free_nsec3_max_iter},
#endif
#ifdef LIBVAL_DLV
    {POL_DLV_TRUST_POINTS_STR, parse_dlv_trust_points,
     free_dlv_trust_points},
#endif
};

/*
 * parse additional data (public key) for the trust anchor policy 
 */
int
parse_trust_anchor(char **buf_ptr, char *end_ptr, policy_entry_t * pol_entry, 
                   int *line_number, int *endst)
{
    char            ta_token[TOKEN_MAX];
    struct trust_anchor_policy *ta_pol;
    int             retval;
    char           *pkstr;
    char           *endptr;
    val_dnskey_rdata_t *dnskey_rdata;
    val_ds_rdata_t *ds_rdata;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (pol_entry == NULL) || (line_number == NULL) || (endst == NULL))
        return VAL_BAD_ARGUMENT;

    READ_POL_FOR_ZONE(buf_ptr, end_ptr, line_number, endst, retval, err, ta_token);
        
    ta_pol = (struct trust_anchor_policy *)
            MALLOC(sizeof(struct trust_anchor_policy));
    if (ta_pol == NULL) {
        return VAL_OUT_OF_MEMORY;
    }
    ta_pol->publickey = NULL;
    ta_pol->ds = NULL;

    /*
     * XXX We may want to have another token that specifies if 
     * XXX this is a DS or a DNSKEY
     * XXX Assume public key for now
     */
    pkstr = &ta_token[0];
    endptr = pkstr + strlen(ta_token);
    
    /* Check if we have a DS record */
    if (!strncasecmp(pkstr, DS_STR, strlen(DS_STR))) {
        pkstr += strlen(DS_STR);
        if (pkstr > endptr) {
            FREE(ta_pol);
            return VAL_CONF_PARSE_ERROR;
        }
        if (VAL_NO_ERROR !=
            (retval =
                 val_parse_ds_string(pkstr, strlen(pkstr), &ds_rdata))) {
            FREE(ta_pol);
            return retval;
        }
        ta_pol->ds = ds_rdata;

    } else {
        if (!strncasecmp(pkstr, DNSKEY_STR, strlen(DNSKEY_STR))) {
            pkstr += strlen(DNSKEY_STR);
        }
        if (pkstr > endptr) {
            FREE(ta_pol);
            return VAL_CONF_PARSE_ERROR;
        }
               
       /* 
        *  Treat as though we have a DNSKEY, even if neither 
        *  DNSKEY nor DS is specified (backwards compatibility
        */ 
        if (VAL_NO_ERROR !=
            (retval =
                 val_parse_dnskey_string(pkstr, strlen(pkstr), &dnskey_rdata))) {
            FREE(ta_pol);
            return retval;
        }
        ta_pol->publickey = dnskey_rdata;
    }

    pol_entry->pol = ta_pol;

    return VAL_NO_ERROR;
}

int
free_trust_anchor(policy_entry_t * pol_entry)
{
    if (pol_entry && pol_entry->pol) {
        struct trust_anchor_policy *ta_pol = (struct trust_anchor_policy *)(pol_entry->pol);

        if (ta_pol->publickey) {
            if (ta_pol->publickey->public_key)
                FREE(ta_pol->publickey->public_key);
            FREE(ta_pol->publickey);
        } else if (ta_pol->ds) {
            FREE(ta_pol->ds);
        }
        FREE(ta_pol);
    }

    return VAL_NO_ERROR;
}

/*
 * parse additional data (time in seconds, -1 for ignore) for the clock skew policy 
 */
int
parse_clock_skew(char **buf_ptr, char *end_ptr, policy_entry_t * pol_entry, 
                 int *line_number, int *endst)
{
    char            cs_token[TOKEN_MAX];
    struct clock_skew_policy  *cs_pol;
    int             retval;
    int       clock_skew;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (pol_entry == NULL) || (line_number == NULL) || (endst == NULL))
        return VAL_BAD_ARGUMENT;

    READ_POL_FOR_ZONE(buf_ptr, end_ptr, line_number, endst, retval, err, cs_token);

    cs_pol = (struct clock_skew_policy *)
            MALLOC(sizeof(struct clock_skew_policy));
    if (cs_pol == NULL) {
        return VAL_OUT_OF_MEMORY;
    }
    clock_skew = (int)strtol(cs_token, (char **)NULL, 10);
    cs_pol->clock_skew = clock_skew;

    pol_entry->pol = cs_pol;

    return VAL_NO_ERROR;
}

int
free_clock_skew(policy_entry_t * pol_entry)
{
    if (pol_entry && pol_entry->pol) {
        FREE(pol_entry->pol);
    }
    return VAL_NO_ERROR;
}

/*
 * parse additional data (trusted or untrusted) for the provably insecure status 
 */
int
parse_prov_unsecure_status(char **buf_ptr, char *end_ptr, policy_entry_t * pol_entry, 
                           int *line_number, int *endst)
{
    char            pu_token[TOKEN_MAX];
    struct prov_unsecure_policy *pu_pol;
    int             retval;
    int             zone_status;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || (pol_entry == NULL) || 
        (line_number == NULL) || (endst == NULL))
        return VAL_BAD_ARGUMENT;

    READ_POL_FOR_ZONE(buf_ptr, end_ptr, line_number, endst, retval, err, pu_token);

    if (!strcmp(pu_token, ZONE_PU_TRUSTED_MSG))
        zone_status = ZONE_PU_TRUSTED;
    else if (!strcmp(pu_token, ZONE_PU_UNTRUSTED_MSG))
        zone_status = ZONE_PU_UNTRUSTED;
    else {
        return VAL_CONF_PARSE_ERROR;
    }

    pu_pol = (struct prov_unsecure_policy *)
            MALLOC(sizeof(struct prov_unsecure_policy));
    if (pu_pol == NULL) {
        return VAL_OUT_OF_MEMORY;
    }
    pu_pol->trusted = zone_status;
    pol_entry->pol = pu_pol;

    return VAL_NO_ERROR;
}

int
free_prov_unsecure_status(policy_entry_t * pol_entry)
{
    if (pol_entry && pol_entry->pol) {
        FREE(pol_entry->pol);
    }
    return VAL_NO_ERROR;
}

/*
 * parse additional data (ignore, trusted, validate, untrusted) 
 * for the zone security expectation policy 
 */
int
parse_zone_security_expectation(char **buf_ptr, char *end_ptr, policy_entry_t * pol_entry, 
                                int *line_number, int *endst)
{
    char            se_token[TOKEN_MAX];
    struct zone_se_policy *zse_pol;
    int             retval;
    int             zone_status;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (pol_entry == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    READ_POL_FOR_ZONE(buf_ptr, end_ptr, line_number, endst, retval, err, se_token);

    if (!strcmp(se_token, ZONE_SE_IGNORE_MSG))
        zone_status = ZONE_SE_IGNORE;
    else if (!strcmp(se_token, ZONE_SE_TRUSTED_MSG))
        zone_status = ZONE_SE_TRUSTED;
    else if (!strcmp(se_token, ZONE_SE_DO_VAL_MSG))
        zone_status = ZONE_SE_DO_VAL;
    else if (!strcmp(se_token, ZONE_SE_UNTRUSTED_MSG))
        zone_status = ZONE_SE_UNTRUSTED;
    else {
        return VAL_CONF_PARSE_ERROR;
    }

    zse_pol = (struct zone_se_policy *)
            MALLOC(sizeof(struct trust_anchor_policy));
    if (zse_pol == NULL) {
        return VAL_OUT_OF_MEMORY;
    }
    zse_pol->trusted = zone_status;

    pol_entry->pol = zse_pol;

    return VAL_NO_ERROR;
}

int
free_zone_security_expectation(policy_entry_t * pol_entry)
{
    if (pol_entry && pol_entry->pol) {
        FREE(pol_entry->pol);
    }
    return VAL_NO_ERROR;
}


#ifdef LIBVAL_NSEC3
/*
 * parse additional data (max number of iterations allowed) 
 * for the zone nsec3 iterations policy 
 */
int
parse_nsec3_max_iter(char **buf_ptr, char *end_ptr, policy_entry_t * pol_entry, 
                     int *line_number, int *endst)
{
    struct nsec3_max_iter_policy *pol;
    int             retval;

    char            iter_token[TOKEN_MAX];
    int             nsec3_iter;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || (pol_entry == NULL) || 
        (line_number == NULL) || (endst == NULL))
        return VAL_BAD_ARGUMENT;

    READ_POL_FOR_ZONE(buf_ptr, end_ptr, line_number, endst, retval, err, iter_token);

    pol = (struct nsec3_max_iter_policy *)
            MALLOC(sizeof(struct nsec3_max_iter_policy));
    if (pol == NULL) {
        return  VAL_OUT_OF_MEMORY;
    }
    nsec3_iter = (int)strtol(iter_token, (char **)NULL, 10);
    pol->iter = nsec3_iter;
    
    pol_entry->pol = pol;

    return VAL_NO_ERROR;
}

int
free_nsec3_max_iter(policy_entry_t * pol_entry)
{
    if (pol_entry && pol_entry->pol) {
        FREE(pol_entry->pol);
    }
    return VAL_NO_ERROR;
}
#endif

#ifdef LIBVAL_DLV
/*
 * parse additional data (targetted zone) 
 * for the DLV policy 
 */
int
parse_dlv_trust_points(char **buf_ptr, char *end_ptr, policy_entry_t * pol_entry, 
                       int *line_number, int *endst)
{
    char            dlv_token[TOKEN_MAX];
    struct dlv_policy *dlv_pol;
    int             retval;
    int             len;
    u_int8_t        zone_n[NS_MAXCDNAME];

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (pol_entry == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    READ_POL_FOR_ZONE(buf_ptr, end_ptr, line_number, endst, retval, err, dlv_token);
    if (ns_name_pton(dlv_token, zone_n, NS_MAXCDNAME) == -1) {
        return VAL_BAD_ARGUMENT;
    }

    /* The dlv token is the name of the DLV trust point */
    
    dlv_pol = (struct dlv_policy *)
            MALLOC(sizeof(struct dlv_policy));
    if (dlv_pol == NULL) {
        return VAL_OUT_OF_MEMORY;
    }
    len = wire_name_length(zone_n);
    dlv_pol->trust_point = (u_int8_t *) MALLOC (len * sizeof(u_int8_t));
    if (dlv_pol->trust_point == NULL) {
        FREE(dlv_pol);
        return VAL_OUT_OF_MEMORY;
    }
    memcpy(dlv_pol->trust_point, zone_n, len);

    pol_entry->pol = dlv_pol;

    return VAL_NO_ERROR;
}

int
free_dlv_trust_points(policy_entry_t * pol_entry)
{
    if (pol_entry && pol_entry->pol) {
        u_int8_t *tp = ((struct dlv_policy *)(pol_entry->pol))->trust_point;
        if (tp)
            FREE(tp);
        FREE(pol_entry->pol);
    }
    return VAL_NO_ERROR;
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
 * leading comment character
 */

#define READ_COMMENT_LINE(buf_ptr, end_ptr) do {\
	/* read off the remainder of the line */ \
    for (; (*buf_ptr < end_ptr) && (**buf_ptr != '\n'); (*buf_ptr)++);\
    if (*buf_ptr < end_ptr) {\
	    (*line_number)++;\
        (*buf_ptr)++;\
    }\
} while(0)

int
val_get_token(char **buf_ptr,
              char *end_ptr,
              int *line_number,
              char *conf_token,
              int conf_limit, int *endst, 
              const char *comment_c, char endstmt_c)
{
    int             i = 0;
    int             quoted = 0;
    int             escaped = 0;
    int             comment = 0;
    char            c;
    int             j = 0;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || 
        (end_ptr == NULL) || (line_number == NULL) ||
        (conf_token == NULL) || (endst == NULL))
        return VAL_BAD_ARGUMENT;

    *endst = 0;
    strcpy(conf_token, "");

    /* Read first legitimate character */
    do {
        while (*buf_ptr < end_ptr &&
               isspace(**buf_ptr)) {
            if (**buf_ptr == '\n') {
                (*line_number)++;
            }
            (*buf_ptr)++;
        }
        
        if ((*buf_ptr) >= end_ptr)
            return VAL_NO_ERROR;

        /*
         * Ignore lines that begin with comments 
         */
        comment = 0;
        for (j=0; j < strlen(comment_c); j++) {
            if (**buf_ptr == comment_c[j]) {
                READ_COMMENT_LINE(buf_ptr, end_ptr);
                comment = 1;
                break;
            }
        }
    } while (comment);

    i = 0;

    while (*buf_ptr < end_ptr && 
           (!isspace((c = **buf_ptr)) || quoted || escaped)) {
           
        (*buf_ptr)++;
        if (i == conf_limit)
            return VAL_CONF_PARSE_ERROR;

        switch (c) {

            case '"' :
                if (quoted)
                    quoted = 0;
                else
                    quoted = 1;
                break;

            case '\\' :
                escaped = 1;
                break;

            case '\n' :
                if (!escaped) {
                    goto done;
                }
                (*line_number)++;
                break;
    
            default:
                if (c == endstmt_c) {
                    *endst = 1;
                    goto done;
                } else {
                    /* Check if this is a comment character */
                    for (j=0; j < strlen(comment_c); j++) {
                        if (c == comment_c[j]) {
                            READ_COMMENT_LINE(buf_ptr, end_ptr);
                            goto done;
                        }
                    }     
                }
                if (!isspace(c))
                    escaped = 0;
                conf_token[i++] = c;
                break;
        }
    }

done:
    conf_token[i] = '\0';
    if (quoted || 
        (*buf_ptr >= end_ptr && escaped)) {

        return VAL_CONF_PARSE_ERROR;
    }
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

    if (!strcmp(label, LVL_DELIM))
        *label_count = 0;

    /*
     * NULL scopes and default labels are always relevant 
     */
    if (c == NULL || (*label_count == 0)) {
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

static int
parse_local_answer_gopt(char **buf_ptr, char *end_ptr, int *line_number, 
                        int *endst, global_opt_t *g_opt) 
{
    char            token[TOKEN_MAX];
    int retval;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (g_opt == NULL) || (endst == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    if (VAL_NO_ERROR != (retval = 
        val_get_token(buf_ptr, end_ptr, line_number, 
                      token, sizeof(token), endst,
                      CONF_COMMENT, CONF_END_STMT))) {
        return retval;
    }
    if ((endst && (strlen(token) == 0)) ||
        (*buf_ptr >= end_ptr)) { 
        return VAL_CONF_PARSE_ERROR;
    }

    if (!strcmp(token, TRUST_LOCAL_GOPT_YES_STR))
        g_opt->local_is_trusted = 1;
    else if (!strcmp(token, TRUST_LOCAL_GOPT_NO_STR))
        g_opt->local_is_trusted = 0;
    else
        return VAL_CONF_PARSE_ERROR;
    
    return VAL_NO_ERROR;
}

static int
parse_edns0_size_gopt(char **buf_ptr, char *end_ptr, int *line_number, 
                      int *endst, global_opt_t *g_opt) 
{
    char            token[TOKEN_MAX];
    int retval;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (g_opt == NULL) || (endst == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    if (VAL_NO_ERROR != (retval = 
        val_get_token(buf_ptr, end_ptr, line_number, 
                      token, sizeof(token), endst,
                      CONF_COMMENT, CONF_END_STMT))) {
        return retval;
    }
    if ((endst && (strlen(token) == 0)) ||
        (*buf_ptr >= end_ptr)) { 
        return VAL_CONF_PARSE_ERROR;
    }

    g_opt->edns0_size = strtol(token, (char **)NULL, 10);
    
    return VAL_NO_ERROR;
}
    
static int
get_global_options(char **buf_ptr, char *end_ptr, 
                   int *line_number, global_opt_t **g_opt) 
{
    int endst = 0;
    char            token[TOKEN_MAX];
    int retval;
   
    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (g_opt == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    *g_opt = (global_opt_t *) MALLOC (sizeof (global_opt_t));
    if (*g_opt == NULL)
        return VAL_OUT_OF_MEMORY;
    (*g_opt)->local_is_trusted = 0;
    (*g_opt)->edns0_size = EDNS_UDP_SIZE;
    
    while (!endst) {
        /*
         * read the option type 
         */
        if (VAL_NO_ERROR != (retval = 
            val_get_token(buf_ptr, end_ptr, line_number, 
                          token, sizeof(token), &endst,
                          CONF_COMMENT, CONF_END_STMT))) {
            goto err;
        }
        if (endst && (strlen(token) == 0)) {
            break;
        }
        if (*buf_ptr >= end_ptr) { 
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }

        /* parse the option value based on the type */
        if (!strcmp(token, GOPT_TRUST_LOCAL_STR)) {
            if (VAL_NO_ERROR != 
                    (retval = parse_local_answer_gopt(buf_ptr, end_ptr,
                                                      line_number, &endst, *g_opt))) {
                goto err;
            }
        } else if (!strcmp(token, GOPT_EDNS0_SIZE_STR)) {
            if (VAL_NO_ERROR != 
                    (retval = parse_edns0_size_gopt(buf_ptr, end_ptr,
                                                    line_number, &endst, *g_opt))) {
                goto err;
            }
        } else {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }
    }

    return VAL_NO_ERROR;

err:
    FREE (*g_opt);
    *g_opt = NULL;
    return retval;
}

/*
 * Get the next relevant {label, keyword, data} fragment 
 * from the configuration file file
 */
static int
get_next_policy_fragment(char **buf_ptr, char *end_ptr, char *scope,
                         struct policy_fragment **pol_frag,
                         int *line_number, int *g_opt_seen, int *include_seen)
{
    char            token[TOKEN_MAX];
    int             retval;
    char           *keyword, *label = NULL;
    int             relevant = 0;
    int             label_count;
    int             endst = 0;
    policy_entry_t  *pol = NULL;
    int             index = 0;
    u_char          zone_n[NS_MAXCDNAME];
    policy_entry_t *pol_entry;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (pol_frag == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    while (!relevant) {

        /*
         * free up previous iteration policy 
         */
        if (pol != NULL) {
            free_policy_entry(pol, index);
            pol = NULL;
        }

        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(buf_ptr, end_ptr, line_number, token, sizeof(token), &endst,
                       CONF_COMMENT, CONF_END_STMT)))
            return retval;
        if (*buf_ptr >= end_ptr)
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

        if (!strcmp(label, POL_GLOBAL_OPTIONS_STR)) {
            FREE(label);
            *g_opt_seen = 1;
            return VAL_NO_ERROR;
        } else if (!strcmp(label, POL_INCLUDE_STR)) {
            FREE(label);
            *include_seen = 1;
            return VAL_NO_ERROR;
        }
        
        /*
         * read the keyword 
         */
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(buf_ptr, end_ptr, line_number, token, sizeof(token), &endst,
                       CONF_COMMENT, CONF_END_STMT))) {
            FREE(label);
            return retval;
        }
        if ((*buf_ptr >= end_ptr) || endst) {
            FREE(label);
            return VAL_CONF_PARSE_ERROR;
        }
        keyword = token;

        /* find the policy according to the keyword */
        for (index = 0; index < MAX_POL_TOKEN; index++) {
            if (!strcmp(keyword, conf_elem_array[index].keyword)) {
                break;
            }
        }
        if (index == MAX_POL_TOKEN) {
            FREE(label);
            return VAL_CONF_PARSE_ERROR;
        }

        while (!endst) {
            /*
             * read the zone name 
             */
            if (VAL_NO_ERROR != (retval = 
                val_get_token(buf_ptr, end_ptr, line_number, token, sizeof(token), &endst,
                       CONF_COMMENT, CONF_END_STMT))) {

                free_policy_entry(pol, index);
                pol = NULL;
                FREE(label);
                return retval;
            }
            if (endst && (strlen(token) == 0)) {
                break;
            }
            if ((*buf_ptr >= end_ptr) ||
                ns_name_pton(token, zone_n, sizeof(zone_n)) == -1) {

                free_policy_entry(pol, index);
                pol = NULL;
                FREE(label);
                return VAL_CONF_PARSE_ERROR;
            }
        
            pol_entry = (policy_entry_t *) MALLOC (sizeof(policy_entry_t));
            if (pol_entry == NULL) {
                free_policy_entry(pol, index);
                pol = NULL;
                FREE(label);
                return VAL_OUT_OF_MEMORY;
            }

            memcpy(pol_entry->zone_n, zone_n, wire_name_length(zone_n));
            pol_entry->exp_ttl = 0;
            pol_entry->next = NULL;

            /*
             * parse the remaining contents according to the keyword 
             */
            if (conf_elem_array[index].parse(buf_ptr, end_ptr, pol_entry, 
                        line_number, &endst) != VAL_NO_ERROR) {
                free_policy_entry(pol, index);
                FREE(pol_entry);
                pol = NULL;
                FREE(label);
                return VAL_CONF_PARSE_ERROR;
            }

            STORE_POLICY_ENTRY_IN_LIST(pol_entry, pol);
        }

        if (VAL_NO_ERROR !=
            (retval =
             (check_relevance(label, scope, &label_count, &relevant)))) {
            free_policy_entry(pol, index);
            pol = NULL;
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
        val_log(ctx, LOG_DEBUG, "store_policy_overrides(): Adding policy [%s:%s]", 
                    newp->label, 
                    conf_elem_array[e->index].keyword);
        if (e->index == (*pfrag)->index) {
            val_log(ctx, LOG_WARNING,
                    "store_policy_overrides(): Duplicate policy definition for [%s:%s]; using latest",
                    newp->label, conf_elem_array[e->index].keyword);
            free_policy_entry(e->pol, e->index);
            e->pol = NULL;
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
            if ((plist->pol != NULL) && (plist->index < MAX_POL_TOKEN)) {
                free_policy_entry(plist->pol, plist->index);
                plist->pol = NULL;
            }
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
    struct dnsval_list *dnsval_c;
    
    if (ctx == NULL)
        return;

    /* free the list of dnsval_conf files */
    dnsval_c = ctx->dnsval_l;
    while (dnsval_c) {
        struct dnsval_list *dnsval_n;
        dnsval_n = dnsval_c->next;
        if (dnsval_c->dnsval_conf)
            FREE(dnsval_c->dnsval_conf);
        FREE(dnsval_c);
        dnsval_c = dnsval_n;
    }
    
    for (i = 0; i < MAX_POL_TOKEN; i++) {
        /* Free this list */
        if (ctx->e_pol[i]) {
            free_policy_entry(ctx->e_pol[i], i);
        }
        ctx->e_pol[i] = NULL;
    }

    if (ctx->g_opt) {
        FREE(ctx->g_opt);
        ctx->g_opt = NULL;
    }
}

/*
 * Make sense of the validator configuration file
 */
int
read_val_config_file(val_context_t * ctx, char *scope)
{
    int             fd = -1;
    struct flock    fl;
    struct policy_fragment *pol_frag = NULL;
    int             retval;
    int             line_number = 1;
    struct policy_overrides *overrides = NULL, *t;
    struct stat sb;
    char *buf_ptr, *end_ptr;
    char *buf = NULL;
    int g_opt_seen = 0;
    int include_seen = 0;
    global_opt_t *g_opt = NULL;
    char *base_dnsval_conf = NULL;
    struct dnsval_list *dnsval_list = NULL;
    struct dnsval_list *dnsval_l, *dnsval_c;
    char token[TOKEN_MAX];
    int endst = 0;
   
    if (ctx == NULL)
        return VAL_BAD_ARGUMENT;
    
    CTX_LOCK_VALPOL_SH(ctx);
    if (ctx->dnsval_l && ctx->dnsval_l->dnsval_conf)
        base_dnsval_conf = strdup(ctx->dnsval_l->dnsval_conf);
    CTX_UNLOCK_VALPOL(ctx);
    
    if (base_dnsval_conf == NULL) 
        return VAL_OUT_OF_MEMORY;
   
    dnsval_list = (struct dnsval_list *) MALLOC (sizeof(struct dnsval_list));
    if (dnsval_list == NULL) {
        FREE(base_dnsval_conf);
        return VAL_OUT_OF_MEMORY;
    }
    dnsval_list->dnsval_conf = base_dnsval_conf;
    dnsval_list->next = NULL; 
    
    dnsval_c = dnsval_list;
    
    while(dnsval_c) {

        dnsval_l = dnsval_c;
        line_number = 1;
        fd = open(dnsval_c->dnsval_conf, O_RDONLY);
        if (fd == -1) {
            val_log(ctx, LOG_ERR, "read_val_config_file(): Could not open validator conf file for reading: %s",
                    dnsval_c->dnsval_conf);
            /* check if we have at least one file */
            if (dnsval_c == dnsval_list) {
                retval = VAL_CONF_NOT_FOUND;
                goto err;
            } else {
                dnsval_c = dnsval_c->next;
                continue;
            }
        }
        memset(&fl, 0, sizeof(fl));
        fl.l_type = F_RDLCK;
        fcntl(fd, F_SETLKW, &fl);

        if (0 != fstat(fd, &sb)) {
            val_log(ctx, LOG_ERR, "read_val_config_file(): Could not stat validator conf file: %s",
                    dnsval_c->dnsval_conf);
            retval = VAL_CONF_NOT_FOUND;
            goto err;
        } 
        dnsval_c->v_timestamp = sb.st_mtime;

        buf = (char *) MALLOC (sb.st_size * sizeof(char));
        if (buf == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        buf_ptr = buf;
        end_ptr = buf+sb.st_size;

        if (-1 == read(fd, buf, sb.st_size)) {
            val_log(ctx, LOG_ERR, "read_val_config_file(): Could not read validator conf file: %s",
                    dnsval_c->dnsval_conf);
            retval = VAL_CONF_NOT_FOUND;
            goto err;
        }

        val_log(ctx, LOG_INFO, "read_val_config_file(): Reading validator policy from %s",
                dnsval_c->dnsval_conf);
        val_log(ctx, LOG_DEBUG, "read_val_config_file(): Reading next policy fragment");

        while (VAL_NO_ERROR ==
               (retval =
                get_next_policy_fragment(&buf_ptr, end_ptr, 
                                         scope, &pol_frag, 
                                         &line_number, 
                                         &g_opt_seen,
                                         &include_seen))) {
            if (buf_ptr >= end_ptr) {
                retval = VAL_NO_ERROR;
                break;
            }
        
            if (g_opt_seen) {
                /* next policy fragment contains global options */ 
                if (g_opt) {
                    /* re-definition of global options */
                    val_log(ctx, LOG_ERR, 
                            "read_val_config_file(): Redefinition of global options in line %d of %s",
                            line_number, dnsval_c->dnsval_conf);
                    FREE(g_opt);
                    g_opt = NULL;
                    retval = VAL_CONF_PARSE_ERROR;
                    goto err;
                }
                g_opt_seen = 0;
                if (VAL_NO_ERROR != (retval =
                    get_global_options(&buf_ptr, end_ptr, 
                                      &line_number, &g_opt))) {
                    val_log(ctx, LOG_ERR, 
                            "read_val_config_file(): Error in line %d of %s ",
                            line_number, dnsval_c->dnsval_conf);
                    goto err;
                }
            } else if (include_seen) { 
                /* need to include another file */
                struct dnsval_list *dnsval_temp;
                
                include_seen = 0;
                /* read the filename in the next token */
                if (VAL_NO_ERROR != (retval = 
                    val_get_token(&buf_ptr, end_ptr, &line_number, 
                                  token, sizeof(token), &endst,
                                  CONF_COMMENT, CONF_END_STMT))) {
                    val_log(ctx, LOG_ERR, 
                            "read_val_config_file(): Error in line %d of %s ",
                            line_number, dnsval_c->dnsval_conf);
                    goto err;
                }
                if ((endst && (strlen(token) == 0)) || (buf_ptr >= end_ptr)) { 
                    val_log(ctx, LOG_ERR, 
                            "read_val_config_file(): Error in line %d of %s ",
                            line_number, dnsval_c->dnsval_conf);
                    retval = VAL_CONF_PARSE_ERROR;
                    goto err;
                }

                /* check if filename already exists in the list */
                for (dnsval_temp=dnsval_list; dnsval_temp; dnsval_temp=dnsval_temp->next) {
                    if (!strcmp(dnsval_temp->dnsval_conf, token)) {
                        val_log(ctx, LOG_ERR, 
                            "read_val_config_file(): File already included, possible loop in line %d of %s ",
                            line_number, dnsval_c->dnsval_conf);
                        retval = VAL_CONF_PARSE_ERROR;
                        goto err;
                    }
                } 

                base_dnsval_conf = strdup(token);
                if (base_dnsval_conf == NULL) {
                    retval = VAL_OUT_OF_MEMORY;
                    goto err;
                }

                dnsval_temp = (struct dnsval_list *) MALLOC (sizeof(struct dnsval_list));
                if (dnsval_temp == NULL) {
                    FREE(base_dnsval_conf);
                    retval = VAL_OUT_OF_MEMORY;
                    goto err;
                }

                /* add this node after last include relative to dnsval.conf being processed */
                dnsval_temp->dnsval_conf = base_dnsval_conf; 
                dnsval_temp->next = dnsval_l->next;
                dnsval_l->next = dnsval_temp;
                dnsval_l = dnsval_temp;

            } else {
                /*
                 * Store this fragment as an override, consume pol_frag 
                 */
                store_policy_overrides(ctx, &overrides, &pol_frag);
            }
        }

        if (retval != VAL_NO_ERROR) {
            val_log(ctx, LOG_ERR, "read_val_config_file(): Error in line %d of %s", line_number,
                    dnsval_c->dnsval_conf);
            goto err;
        } 

        FREE(buf);
        buf = NULL;
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLKW, &fl);
        close(fd);
        fd = -1;
    
        dnsval_c = dnsval_c->next;
    }

    if (scope == NULL) {
        /*
         * Use the first policy as the default (only) policy 
         */
        if (overrides)
            destroy_valpolovr(&overrides->next);
    }

    
    CTX_LOCK_VALPOL_EX(ctx);

    destroy_valpol(ctx);

    /* Replace policies */
    for (t = overrides; t != NULL; t = t->next) {
        struct policy_list *c;
        for (c = t->plist; c; c = c->next){
            /* Override elements in e_pol[c->index] with what's in c->pol */
            STORE_POLICY_ENTRY_IN_LIST(c->pol, ctx->e_pol[c->index]);
        }
    }
    destroy_valpolovr(&overrides);

    ctx->g_opt = g_opt;

    /* 
     * Re-initialize caches 
     */
    free_query_chain(ctx->q_list);
    free_authentication_chain(ctx->a_list);

    ctx->q_list = NULL;
    ctx->a_list = NULL;
    ctx->dnsval_l = dnsval_list;

    CTX_UNLOCK_VALPOL(ctx);

    val_log(ctx, LOG_DEBUG, "read_val_config_file(): Done reading validator configuration");

    return VAL_NO_ERROR;

err:
    if (overrides) {
        destroy_valpolovr(&overrides);
    }
    if (g_opt) {
        FREE(g_opt);
    }
    if (buf) { 
        FREE(buf);
    }

    dnsval_c = dnsval_list;
    while (dnsval_c) {
        struct dnsval_list *dnsval_n;
        dnsval_n = dnsval_c->next;
        if (dnsval_c->dnsval_conf)
            FREE(dnsval_c->dnsval_conf);
        FREE(dnsval_c);
        dnsval_c = dnsval_n;
    }

    if (fd != -1) {
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLKW, &fl);
        close(fd);
    }
    return retval;
}

void
destroy_respol(val_context_t * ctx)
{
    if ((ctx != NULL) && (ctx->nslist != NULL)) {
        free_name_servers(&ctx->nslist);
        ctx->nslist = NULL;
    }
}

static int
parse_name_server(char *cp, struct name_server **ns)
{ 
    struct sockaddr_storage serv_addr;
    struct sockaddr_in *sin = (struct sockaddr_in *)&serv_addr;
#ifdef VAL_IPV6
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&serv_addr;
#endif
    union {
        struct in_addr   v4;
#ifdef VAL_IPV6
        struct in6_addr  v6;
#endif
    } address;

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

    bzero(&serv_addr, sizeof(serv_addr));
    if (inet_pton(AF_INET, cp, &address.v4) > 0) {
        sin->sin_family = AF_INET;     // host byte order
        sin->sin_addr = address.v4;
        sin->sin_port = htons(DNS_PORT);       // short, network byte order
    }
    else {
#ifdef VAL_IPV6
        if (inet_pton(AF_INET6, cp, &address.v6) != 1)
            goto parse_err;

        sin6->sin6_family = AF_INET6;     // host byte order
        memcpy(&sin6->sin6_addr, &address.v6, sizeof(address.v6));
        sin6->sin6_port = htons(DNS_PORT);       // short, network byte order
#else
        goto parse_err;
#endif
    }

    (*ns)->ns_address = NULL;
    CREATE_NSADDR_ARRAY((*ns)->ns_address, 1);
    if ((*ns)->ns_address == NULL) {
        FREE(*ns);
        *ns = NULL;
        return VAL_OUT_OF_MEMORY;
    }
    (*ns)->ns_number_of_addresses = 1;

    memcpy((*ns)->ns_address[0], &serv_addr,
           sizeof(serv_addr));
    (*ns)->ns_number_of_addresses = 1;
    return VAL_NO_ERROR;

  parse_err:
    FREE(*ns);
    *ns = NULL;
    return VAL_CONF_PARSE_ERROR;
}

int
read_res_config_file(val_context_t * ctx)
{
    char           *resolv_config;
    int             fd;
    struct flock    fl;
    char            token[TOKEN_MAX];
    int             line_number = 0;
    int             endst = 0;
    struct name_server *ns_head = NULL;
    struct name_server *ns_tail = NULL;
    struct name_server *ns = NULL;
    u_int8_t zone_n[NS_MAXCDNAME];
    struct stat sb;
    char *buf_ptr, *end_ptr;
    char *buf = NULL;
    int retval;

    if (ctx == NULL)
        return VAL_BAD_ARGUMENT;

    resolv_config = ctx->resolv_conf;
    if (NULL == resolv_config) {
        if (!ctx->root_ns) {
            val_log(ctx, LOG_WARNING, 
                    "read_res_config_file(): Resolver configuration is NULL and root-hints was not found");
            return VAL_CONF_NOT_FOUND;
        }
        val_log(ctx, LOG_DEBUG, "read_res_config_file(): No resolv.conf file configured, but root-hints available"); 
        return VAL_NO_ERROR;
    }

    fd = open(resolv_config, O_RDONLY);
    if (fd == -1) {
        val_log(ctx, LOG_ERR, "read_res_config_file(): Could not open resolver conf file for reading: %s",
                resolv_conf);
    
        /* Use default resolv.conf file */
        FREE(ctx->resolv_conf);
        ctx->resolv_conf = strdup(VAL_DEFAULT_RESOLV_CONF);
        if (ctx->resolv_conf == NULL) {
            return VAL_OUT_OF_MEMORY;
        }
        resolv_config = ctx->resolv_conf;
        fd = open(resolv_config, O_RDONLY);
        if (fd == -1) {
            val_log(ctx, LOG_ERR, "read_res_config_file(): Could not open default resolver conf file for reading: %s",
                    resolv_conf);
        }
        return VAL_CONF_NOT_FOUND;
    }
    fl.l_type = F_RDLCK;
    fcntl(fd, F_SETLKW, &fl);

    if (0 != fstat(fd, &sb)) {
        retval = VAL_CONF_NOT_FOUND;
        goto err;
    } 

    buf = (char *) MALLOC (sb.st_size * sizeof(char));
    if (buf == NULL) {
        retval = VAL_OUT_OF_MEMORY;
        goto err;
    }
    buf_ptr = buf;
    end_ptr = buf+sb.st_size;

    if (-1 == read(fd, buf, sb.st_size)) {
        val_log(ctx, LOG_ERR, "read_res_config_file(): Could not read resolver conf file: %s",
                resolv_conf);
        retval = VAL_CONF_NOT_FOUND;
        goto err;
    }
    val_log(ctx, LOG_INFO, "read_res_config_file(): Reading resolver policy from %s", resolv_config);

    while(buf_ptr < end_ptr) {

        /* Read the keyword */
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
                       ALL_COMMENTS, ZONE_END_STMT))) {
            goto err;
        }

        if (buf_ptr >= end_ptr) {
            if (strlen(token) > 0) {
                retval = VAL_CONF_PARSE_ERROR;
                goto err;
            }
            break;
        }
        
        if (strncmp(token, "nameserver", strlen("nameserver")) == 0) {

            /* Read the value */
            if (VAL_NO_ERROR !=
                (retval =
                val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
                           ALL_COMMENTS, ZONE_END_STMT))) {
                goto err;
            }
            ns = NULL;
            if (VAL_NO_ERROR != parse_name_server(token, &ns))
                goto err;
            if (ns != NULL) {
                if (ns_tail == NULL) {
                    ns_head = ns;
                    ns_tail = ns;
                } else {
                    ns_tail->ns_next = ns;
                    ns_tail = ns;
                }
            } else {
                val_log(ctx, LOG_WARNING,
                        "read_res_config_file(): Invalid nameserver addresses '%s', skipping.",
                        token);
            }
        } else if (strncmp(token, "forward", strlen("forward")) == 0) {

            /* Read the value */
            /* nameserver first */
            if (VAL_NO_ERROR !=
                (retval =
                val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
                           ALL_COMMENTS, ZONE_END_STMT))) {
                goto err;
            }
            ns = NULL;
            if (VAL_NO_ERROR != parse_name_server(token, &ns))
                goto err;
            /* zone next */
            if (VAL_NO_ERROR !=
                (retval =
                val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
                           ALL_COMMENTS, ZONE_END_STMT))) {
                goto err;
            }
            if (ns != NULL) {
                if (ns_name_pton(token, zone_n, sizeof(zone_n)) == -1)
                    goto err;
                store_ns_for_zone(zone_n, ns);
            } else {
                val_log(ctx, LOG_WARNING,
                        "read_res_config_file(): Invalid nameserver addresses '%s', skipping.",
                        token);
            }
        } else if (strncmp(token, "search", strlen("search")) == 0) {

            /* Read the value */
            if (VAL_NO_ERROR !=
                (retval =
                val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
                           ALL_COMMENTS, ZONE_END_STMT))) {
                goto err;
            }
            if (ctx->search)
                free(ctx->search);
            ctx->search = strdup(token);
        }
    }

    FREE(buf);
    fl.l_type = F_UNLCK;
    fcntl(fd, F_SETLKW, &fl);
    close(fd);

    /*
     * Check if we have root hints 
     */
    if (ns_head == NULL) {
        if (!ctx->root_ns) {
            val_log(ctx, LOG_WARNING, 
                    "read_res_config_file(): Resolver configuration is empty, but root-hints was not found");
            return VAL_CONF_NOT_FOUND;
        }
    } 

    CTX_LOCK_RESPOL_EX(ctx);
    destroy_respol(ctx);
    ctx->nslist = ns_head;
    ctx->r_timestamp = sb.st_mtime;
    CTX_UNLOCK_RESPOL(ctx);

    val_log(ctx, LOG_DEBUG, 
            "read_res_config_file(): Done reading resolver configuration");
    return VAL_NO_ERROR;

  err:
    val_log(ctx, LOG_ERR, 
            "read_res_config_file(): Error encountered while reading file %s", resolv_config);
    free_name_servers(&ns_head);

    if (buf)
        FREE(buf);

    if (fd != -1) {
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLKW, &fl);
        close(fd);
    }

    return VAL_CONF_PARSE_ERROR;
}

/*
 * parse the contents of the root.hints file into resource records 
 */
int
read_root_hints_file(val_context_t * ctx)
{
    struct rrset_rec *root_info = NULL;
    int             fd;
    struct flock    fl;
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
    char *buf_ptr, *end_ptr;
    char *buf = NULL;

    class_h = 0;
    have_type = 0;

    if (ctx == NULL)
        return VAL_BAD_ARGUMENT;
    
    root_hints = ctx->root_conf;
    /* 
     *  Root hints are not necessary. Only needed if our resolv.conf is empty. 
     * Flag the error at that time
     */
    if (NULL == root_hints) {
        val_log(ctx, LOG_INFO, "read_root_hints_file(): No root.hints file configured"); 
        return VAL_NO_ERROR;
    }

    fd = open(root_hints, O_RDONLY);
    if (fd == -1) {
        val_log(ctx, LOG_INFO, "read_root_hints_file(): Could not open root hints file for reading: %s",
                root_hints);
        return VAL_NO_ERROR;
    }
    fl.l_type = F_RDLCK;
    fcntl(fd, F_SETLKW, &fl);

    if (0 != fstat(fd, &sb)) { 
        retval = VAL_CONF_NOT_FOUND;
        goto err;
    }

    buf = (char *) MALLOC (sb.st_size * sizeof(char));
    if (buf == NULL) {
        retval = VAL_OUT_OF_MEMORY;
        goto err;
    }
    buf_ptr = buf;
    end_ptr = buf+sb.st_size;

    if (-1 == read(fd, buf, sb.st_size)) {
        val_log(ctx, LOG_ERR, "read_root_hints_file(): Could not read root hints file: %s",
                root_hints);
        retval = VAL_CONF_NOT_FOUND;
        goto err;
    }

    val_log(ctx, LOG_INFO, "read_root_hints_file(): Reading root hints from %s",
            root_hints);

    while (buf_ptr < end_ptr) {

        /*
         * name 
         */
        if (VAL_NO_ERROR !=
            (retval =
            val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
                   ZONE_COMMENT, ZONE_END_STMT))) {
            goto err;
        }
        if (buf_ptr >= end_ptr) {
            if (strlen(token) > 0) {
                retval = VAL_CONF_PARSE_ERROR;
                goto err;
            }
            break;
        }

        if (ns_name_pton(token, zone_n, sizeof(zone_n)) == -1) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }


        /*
         * ttl 
         */
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
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
        if (buf_ptr >= end_ptr) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
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
        
        /*
         * type 
         */
        if (!have_type) {
            if (buf_ptr >= end_ptr) {
                retval = VAL_CONF_PARSE_ERROR;
                goto err;
            }
            if (VAL_NO_ERROR !=
                (retval =
                val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
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

        /*
         * rdata 
         */
        if (buf_ptr >= end_ptr) {
            retval = VAL_CONF_PARSE_ERROR;
            goto err;
        }
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
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
        } else {
            continue;
        }

        //        SAVE_RR_TO_LIST(NULL, &root_info, zone_n, type_h, type_h, ns_c_in,
        //                        ttl_h, NULL, rdata_n, rdata_len_h, VAL_FROM_UNSET, 0,
        //                        zone_n);
        rr_set = find_rr_set(NULL, &root_info, zone_n, type_h, type_h,
                             ns_c_in, (u_int32_t)ttl_h, NULL, rdata_n, VAL_FROM_UNSET,
                             0, zone_n);
        if (rr_set == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        if (type_h != ns_t_rrsig) {
            /** Add this record to its chain of val_rr_rec's. */
            retval = add_to_set(rr_set, rdata_len_h, rdata_n);
        } else {
            /** Add this record to the sig of rrset_rec. */
            retval = add_as_sig(rr_set, rdata_len_h, rdata_n);
        }
        if (retval != VAL_NO_ERROR) {
            goto err;
        }
        // end save_rr_to_list
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
    ctx->h_timestamp = sb.st_mtime;
    CTX_UNLOCK_RESPOL(ctx);

    res_sq_free_rrset_recs(&root_info);

    val_log(ctx, LOG_DEBUG, "read_root_hints_file(): Done reading root hints");
    FREE(buf);
    fl.l_type = F_UNLCK;
    fcntl(fd, F_SETLKW, &fl);
    close(fd);

    return VAL_NO_ERROR;

  err:

    if (buf)
        FREE(buf);
    fl.l_type = F_UNLCK;
    fcntl(fd, F_SETLKW, &fl);
    close(fd);
    res_sq_free_rrset_recs(&root_info);
    val_log(ctx, LOG_ERR, "read_root_hints_file(): Error encountered while reading file %s - %s", 
            root_hints, p_val_err(retval));
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


int 
val_add_valpolicy(val_context_t *context, const char *keyword, 
                  char *zone, char *value, long ttl, 
                  val_policy_entry_t **pol)
{
    int index;
    u_char zone_n[NS_MAXCDNAME];
    int line_number;
    int endst = 0;
    struct timeval  tv;
    long ttl_x;
    char *buf_ptr, *end_ptr;
    struct val_query_chain *q;
    policy_entry_t *pol_entry;
    val_context_t *ctx = NULL;
    int retval;

    if (keyword == NULL || zone == NULL || value == NULL || pol == NULL)
        return VAL_BAD_ARGUMENT;

    if (context == NULL) {
        /* Set the policy for the default context */
        if (VAL_NO_ERROR != (retval = val_create_context(NULL, &ctx)))
            return retval;
    } else
        ctx = (val_context_t *) context;
   
    *pol = NULL;
    
    /* find the policy according to the keyword */
    for (index = 0; index < MAX_POL_TOKEN; index++) {
        if (!strcmp(keyword, conf_elem_array[index].keyword)) {
            break;
        }
    }
    if (index == MAX_POL_TOKEN) {
        return VAL_BAD_ARGUMENT;
    }

    if (ns_name_pton(zone, zone_n, NS_MAXCDNAME) == -1) {
        return VAL_BAD_ARGUMENT;
    } 

    if (ttl > 0) {
        gettimeofday(&tv, NULL);
        ttl_x = ttl + tv.tv_sec;
    } else
        ttl_x = -1;
        
    buf_ptr = value;
    end_ptr = value+strlen(value);

    pol_entry = (policy_entry_t *) MALLOC (sizeof(policy_entry_t));
    if (pol_entry == NULL) {
        return VAL_OUT_OF_MEMORY;
    }

    memcpy(pol_entry->zone_n, zone_n, wire_name_length(zone_n));
    pol_entry->exp_ttl = ttl_x;
    pol_entry->next = NULL;
    
    /*
     * parse the remaining contents according to the keyword 
     */
    if (conf_elem_array[index].parse(&buf_ptr, end_ptr, pol_entry, 
            &line_number, &endst) != VAL_NO_ERROR) {
        FREE(pol_entry);
        return VAL_BAD_ARGUMENT;
    }

    /* Lock appropriately */
    CTX_LOCK_VALPOL_EX(ctx);
    CTX_LOCK_ACACHE(ctx);

    /* Flush queries that match this name */
    for(q=ctx->q_list; q; q=q->qc_next) {
        LOCK_QC_EX(q);
        /* Should never fail when holding above locks */
        if (NULL != namename(q->qc_name_n, zone_n)) {
            zap_query(ctx, q);
            if (pol_entry->exp_ttl > 0)
                q->qc_ttl_x = pol_entry->exp_ttl;
        }
        UNLOCK_QC(q);    
    }
    *pol = (val_policy_entry_t *) MALLOC (sizeof(val_policy_entry_t));
    if (*pol == NULL) {
        retval = VAL_OUT_OF_MEMORY;
        goto err;
    }
    (*pol)->pe = pol_entry;
    (*pol)->index = index;

    /* Merge this policy into the context */
    STORE_POLICY_ENTRY_IN_LIST(pol_entry, ctx->e_pol[index]);
    retval = VAL_NO_ERROR;
    
err:
    CTX_UNLOCK_ACACHE(ctx);
    CTX_UNLOCK_VALPOL(ctx);
    
    return retval;
}  

int 
val_remove_valpolicy(val_context_t *context, val_policy_entry_t *pol)
{
    val_context_t *ctx = NULL;
    policy_entry_t *p, *prev;
    struct val_query_chain *q;
    int retval;

    if (pol == NULL || pol->pe == NULL|| pol->index >= MAX_POL_TOKEN)
       return VAL_BAD_ARGUMENT; 

    if (context == NULL) {
        /* Get the policy for the default context */
        if (VAL_NO_ERROR != (retval = val_create_context(NULL, &ctx)))
            return retval;
    } else
        ctx = (val_context_t *) context;
    
    /* Lock appropriately */
    CTX_LOCK_VALPOL_EX(ctx);
    CTX_LOCK_ACACHE(ctx);

    /* find this policy in the context */
    prev = NULL;
    for (p=ctx->e_pol[pol->index]; p; p=p->next) {
        if (p == pol->pe)
            break;
        prev = p;
    }
    if (!p) {
        /* did not find any policy to remove */ 
        retval = VAL_NO_POLICY; 
        goto err; 
    }

    /* unlink the policy */
    if (prev) {
        prev->next = p->next;
    } else {
        ctx->e_pol[pol->index] = p->next;
    }
    p->next = NULL;

    /* Flush queries that match this name */
    for(q=ctx->q_list; q; q=q->qc_next) {
        LOCK_QC_EX(q);
        /* Should never fail when holding above locks */
        if (NULL != namename(q->qc_name_n, p->zone_n)) {
            zap_query(ctx, q);
        }
        UNLOCK_QC(q);    
    }
    
    /* free the policy */
    conf_elem_array[pol->index].free(p);
    FREE(p);
    FREE(pol);
    
    retval = VAL_NO_ERROR;

err:
    CTX_UNLOCK_ACACHE(ctx);
    CTX_UNLOCK_VALPOL(ctx);
    
    return retval;
}

int
val_is_local_trusted(val_context_t *context, int *trusted)
{
    val_context_t *ctx = NULL;
    int retval;

    if (trusted == NULL)
        return VAL_BAD_ARGUMENT;

    if (context == NULL) {
        /* Get the policy for the default context */
        if (VAL_NO_ERROR != (retval = val_create_context(NULL, &ctx)))
            return retval;
    } else
        ctx = (val_context_t *) context;

    CTX_LOCK_VALPOL_SH(ctx);
    if (ctx && ctx->g_opt && ctx->g_opt->local_is_trusted)
        *trusted = 1;
    else
        *trusted = 0;
    CTX_UNLOCK_VALPOL(ctx);

    return VAL_NO_ERROR;    
}
    

