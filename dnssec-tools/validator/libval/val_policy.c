/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
/*
 * DESCRIPTION
 * Read the contents of the resolver, validator and root.hints configuration 
 * files and update the validator context.
 */

#include "validator-internal.h"

#include "val_policy.h"
#include "val_support.h"
#include "val_cache.h"
#include "val_resquery.h"
#include "val_context.h"
#include "val_assertion.h"
#include "val_parse.h"

#if !defined(WIN32) || defined(LIBVAL_CONFIGURED)
#include "val_inline_conf.h"
#else
const char val_conf_inline_buf[] = "";
const char root_hints_inline_buf[] = "";
const char resolv_conf_inline_buf[] = "";
#endif

#ifdef ANDROID
#include <sys/system_properties.h>
#endif /* ANDROID */

#define READ_POL_FOR_ZONE(buf_ptr, end_ptr, line_number, endst, retval, err, token)  do {\
    /*\
     * Read the corresponding value \
     */\
    if (VAL_NO_ERROR != (retval =\
         val_get_token(buf_ptr, end_ptr, line_number, token, sizeof(token), endst,\
                       CONF_COMMENT, CONF_END_STMT, 1)))\
        return retval;\
} while (0)

#define STORE_POLICY_ENTRY_IN_LIST(pol, head) do {\
    policy_entry_t *prev, *cur, *next;\
    while (pol) {\
        int name_len = wire_name_length(pol->zone_n);\
        /*\
         * Store according to decreasing zone name length \
         */\
        next = pol->next;\
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

#define FREE_DNSVAL_FILE_LIST(dnsval_l) do {\
    struct dnsval_list *dnsval_t, *dnsval_n;\
    dnsval_t = dnsval_l;\
    while (dnsval_t) {\
        dnsval_n = dnsval_t->next;\
        if (dnsval_t->dnsval_conf)\
            FREE(dnsval_t->dnsval_conf);\
        FREE(dnsval_t);\
        dnsval_t = dnsval_n;\
    }\
    dnsval_l = NULL;\
} while (0)


/*
 ***************************************************************
 * These are functions to read/set the location of the resolver
 * configuration and root.hints files.
 ***************************************************************
 */
static char    *g_resolv_conf = NULL;
static char    *g_root_hints = NULL;
static char    *g_dnsval_conf = NULL;

static int      atexit_reg = 0;

static void
policy_cleanup(void)
{
    if (NULL != g_resolv_conf)
        free(g_resolv_conf);

    if (NULL != g_root_hints)
        free(g_root_hints);

    if (NULL != g_dnsval_conf)
        free(g_dnsval_conf);
}


char           *
resolv_conf_get(void)
{
    if (NULL == g_resolv_conf) {
        if (0 == atexit_reg) {
            atexit_reg = 1;
            atexit(policy_cleanup);
        }
        g_resolv_conf = strdup(VAL_RESOLV_CONF);
    }

    return strdup(g_resolv_conf);
}

int
resolv_conf_set(const char *name)
{
    char           *new_name = strdup(name);

    if (NULL == new_name)
        return 1;

    if (NULL != g_resolv_conf)
        free(g_resolv_conf);
    else if (0 == atexit_reg) {
        atexit_reg = 1;
        atexit(policy_cleanup);
    }
    g_resolv_conf = new_name;

    return 0;
}

char           *
root_hints_get(void)
{
    if (NULL == g_root_hints) {
        if (0 == atexit_reg) {
            atexit_reg = 1;
            atexit(policy_cleanup);
        }

        g_root_hints = strdup(VAL_ROOT_HINTS);
    }

    return strdup(g_root_hints);
}

int
root_hints_set(const char *name)
{
    char           *new_name = strdup(name);

    if (NULL == new_name)
        return 1;

    if (NULL != g_root_hints)
        free(g_root_hints);
    else if (0 == atexit_reg) {
        atexit_reg = 1;
        atexit(policy_cleanup);
    }

    g_root_hints = new_name;

    return 0;
}

char           *
dnsval_conf_get(void)
{
    if (NULL == g_dnsval_conf)
        g_dnsval_conf = strdup(VAL_CONFIGURATION_FILE);

    return strdup(g_dnsval_conf);
}

int
dnsval_conf_set(const char *name)
{
    char           *new_name = strdup(name);

    if (NULL == new_name)
        return 1;

    if (NULL != g_dnsval_conf)
        free(g_dnsval_conf);
    g_dnsval_conf = new_name;

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

static void
set_global_opt_defaults(val_global_opt_t *gopt)
{
    if (gopt == NULL)
        return;

    gopt->local_is_trusted = 0;
    gopt->edns0_size = RES_EDNS0_DEFAULT;
    gopt->env_policy = VAL_POL_GOPT_DISABLE;
    gopt->app_policy = VAL_POL_GOPT_DISABLE;
    gopt->log_target = NULL;
    gopt->closest_ta_only = 0;
    gopt->rec_fallback = 1;
    gopt->max_refresh = VAL_POL_GOPT_MAXREFRESH;
}

int 
update_dynamic_gopt(val_global_opt_t **g_new, val_global_opt_t *g)
{
    if (g_new == NULL || g == NULL)
        return VAL_BAD_ARGUMENT;

    if (*g_new == NULL) {
        *g_new = (val_global_opt_t *) MALLOC (sizeof (val_global_opt_t));
        if (*g_new == NULL) {
            return VAL_OUT_OF_MEMORY;
        }
        set_global_opt_defaults(*g_new);
    }

    /* NOTE: We must not update log_target */

    if (g->local_is_trusted != -1)
        (*g_new)->local_is_trusted = g->local_is_trusted;        
    if (g->edns0_size != -1)
        (*g_new)->edns0_size = g->edns0_size;        
    if (g->env_policy != -1)
        (*g_new)->env_policy = g->env_policy;        
    if (g->app_policy != -1)
        (*g_new)->app_policy = g->app_policy;        
    if (g->closest_ta_only != -1)
        (*g_new)->closest_ta_only = g->closest_ta_only;        
    if (g->rec_fallback != -1)
        (*g_new)->rec_fallback = g->rec_fallback;        
    if (g->max_refresh != -1)
        (*g_new)->max_refresh = g->max_refresh;        

    return VAL_NO_ERROR;
}

void
free_global_options(val_global_opt_t *g)
{
    if (g) {
        if (g->log_target)
            FREE(g->log_target);
    }
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
    {POL_PROV_INSEC_STR, parse_prov_insecure_status, 
     free_prov_insecure_status},
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
        *  DNSKEY nor DS is specified (backwards compatibility)
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
            if (ta_pol->ds->d_hash)
                FREE(ta_pol->ds->d_hash);
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
parse_prov_insecure_status(char **buf_ptr, char *end_ptr, policy_entry_t * pol_entry, 
                           int *line_number, int *endst)
{
    char            pu_token[TOKEN_MAX];
    struct prov_insecure_policy *pu_pol;
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

    pu_pol = (struct prov_insecure_policy *)
            MALLOC(sizeof(struct prov_insecure_policy));
    if (pu_pol == NULL) {
        return VAL_OUT_OF_MEMORY;
    }
    pu_pol->trusted = zone_status;
    pol_entry->pol = pu_pol;

    return VAL_NO_ERROR;
}

int
free_prov_insecure_status(policy_entry_t * pol_entry)
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
    size_t        len;
    u_char        zone_n[NS_MAXCDNAME];

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
    dlv_pol->trust_point = (u_char *) MALLOC (len * sizeof(u_char));
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
        u_char *tp = ((struct dlv_policy *)(pol_entry->pol))->trust_point;
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
              int conf_limit, 
              int *endst, 
              const char *comment_c, 
              char endstmt_c,
              int ignore_space)
{
    int             i = 0;
    int             quoted = 0;
    int             escaped = 0;
    int             comment = 0;
    char            c;
    int             j = 0;
    int            trail_space = -1;

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

    while (*buf_ptr < end_ptr) {
        c = **buf_ptr;
        /* if spaces are meant to be delimiters, break */
        if (!ignore_space && isspace(c) && !quoted && !escaped) {
            break;
        }
           
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
                if (!escaped && !quoted) {
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
                if (!isspace(c)) {
                    escaped = 0;
                    trail_space = -1;
                } else {
                    trail_space = i;
                }
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
    /* remove all trailing white spaces */
    if (trail_space != -1) {
        conf_token[trail_space] = '\0';
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
check_relevance(const char *label, const char *scope, int *label_count, int *relevant)
{
    const char           *c, *p, *e;

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
                        int *endst, val_global_opt_t *g_opt) 
{
    char            token[TOKEN_MAX];
    int retval;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (g_opt == NULL) || (endst == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    if (VAL_NO_ERROR != (retval = 
        val_get_token(buf_ptr, end_ptr, line_number, 
                      token, sizeof(token), endst,
                      CONF_COMMENT, CONF_END_STMT, 0))) {
        return retval;
    }
    if ((endst && (strlen(token) == 0)) ||
        (*buf_ptr >= end_ptr)) { 
        return VAL_CONF_PARSE_ERROR;
    }

    if (!strcmp(token, GOPT_YES_STR))
        g_opt->local_is_trusted = 1;
    else if (!strcmp(token, GOPT_NO_STR))
        g_opt->local_is_trusted = 0;
    else
        return VAL_CONF_PARSE_ERROR;
    
    return VAL_NO_ERROR;
}

static int
parse_edns0_size_gopt(char **buf_ptr, char *end_ptr, int *line_number, 
                      int *endst, val_global_opt_t *g_opt) 
{
    char            token[TOKEN_MAX];
    int retval;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (g_opt == NULL) || (endst == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    if (VAL_NO_ERROR != (retval = 
        val_get_token(buf_ptr, end_ptr, line_number, 
                      token, sizeof(token), endst,
                      CONF_COMMENT, CONF_END_STMT, 0))) {
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
parse_enable_disable_gopt(int *type, char **buf_ptr, char *end_ptr, int *line_number,
                          int *endst, val_global_opt_t *g_opt)
{
    char            token[TOKEN_MAX];
    int retval;

    if ((type == NULL) || (buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (g_opt == NULL) || (endst == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    /* read the next token */
    if (VAL_NO_ERROR != (retval = 
        val_get_token(buf_ptr, end_ptr, line_number, 
                      token, sizeof(token), endst,
                      CONF_COMMENT, CONF_END_STMT, 0))) {
        return retval;
    }
    if ((endst && (strlen(token) == 0)) ||
        (*buf_ptr >= end_ptr)) { 
        return VAL_CONF_PARSE_ERROR;
    }

    if (!strcmp(token, GOPT_ENABLE_STR)) {
        *type = VAL_POL_GOPT_ENABLE;
    } else if (!strcmp(token, GOPT_OVERRIDE_STR)) {
        *type = VAL_POL_GOPT_OVERRIDE;
    } else {
        /* default is disable */
        *type = VAL_POL_GOPT_DISABLE;
    } 

    return VAL_NO_ERROR;
}

static int
parse_log_target_gopt(char **buf_ptr, char *end_ptr, int *line_number,
                      int *endst, val_global_opt_t *g_opt)
{
    char            token[TOKEN_MAX];
    int retval;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (g_opt == NULL) || (endst == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    /* read the next token */
    if (VAL_NO_ERROR != (retval = 
        val_get_token(buf_ptr, end_ptr, line_number, 
                      token, sizeof(token), endst,
                      CONF_COMMENT, CONF_END_STMT, 0))) {
        return retval;
    }
    if ((endst && (strlen(token) == 0)) ||
        (*buf_ptr >= end_ptr)) { 
        return VAL_CONF_PARSE_ERROR;
    }

    g_opt->log_target = (char *) MALLOC (strlen(token) + 1);
    if (g_opt->log_target == NULL)
        return VAL_OUT_OF_MEMORY;
    strcpy(g_opt->log_target, token);
    return VAL_NO_ERROR;
}

static int
parse_closest_ta_target_gopt(char **buf_ptr, char *end_ptr, int *line_number,
                      int *endst, val_global_opt_t *g_opt)
{
    char            token[TOKEN_MAX];
    int retval;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (g_opt == NULL) || (endst == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    /* read the next token */
    if (VAL_NO_ERROR != (retval = 
        val_get_token(buf_ptr, end_ptr, line_number, 
                      token, sizeof(token), endst,
                      CONF_COMMENT, CONF_END_STMT, 0))) {
        return retval;
    }
    if ((endst && (strlen(token) == 0)) ||
        (*buf_ptr >= end_ptr)) { 
        return VAL_CONF_PARSE_ERROR;
    }

    if (!strncmp(token, GOPT_YES_STR, strlen(GOPT_YES_STR))) {
        g_opt->closest_ta_only = 1;
    } else if (!strncmp(token, GOPT_NO_STR, strlen(GOPT_NO_STR))) {
        g_opt->closest_ta_only = 0;
    } else {
        return VAL_CONF_PARSE_ERROR;
    }
    return VAL_NO_ERROR;
}

static int
parse_rec_fallback(char **buf_ptr, char *end_ptr, int *line_number,
                   int *endst, val_global_opt_t *g_opt)
{
    char            token[TOKEN_MAX];
    int retval;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (g_opt == NULL) || (endst == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    /* read the next token */
    if (VAL_NO_ERROR != (retval = 
        val_get_token(buf_ptr, end_ptr, line_number, 
                      token, sizeof(token), endst,
                      CONF_COMMENT, CONF_END_STMT, 0))) {
        return retval;
    }
    if ((endst && (strlen(token) == 0)) ||
        (*buf_ptr >= end_ptr)) { 
        return VAL_CONF_PARSE_ERROR;
    }

    if (!strncmp(token, GOPT_YES_STR, strlen(GOPT_YES_STR))) {
        g_opt->rec_fallback = 1;
    } else if (!strncmp(token, GOPT_NO_STR, strlen(GOPT_NO_STR))) {
        g_opt->rec_fallback = 0;
    } else {
        return VAL_CONF_PARSE_ERROR;
    }
    return VAL_NO_ERROR;
}

static int
parse_max_refresh_gopt(char **buf_ptr, char *end_ptr, int *line_number, 
                      int *endst, val_global_opt_t *g_opt) 
{
    char            token[TOKEN_MAX];
    int retval;

    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (g_opt == NULL) || (endst == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    if (VAL_NO_ERROR != (retval = 
        val_get_token(buf_ptr, end_ptr, line_number, 
                      token, sizeof(token), endst,
                      CONF_COMMENT, CONF_END_STMT, 0))) {
        return retval;
    }
    if ((endst && (strlen(token) == 0)) ||
        (*buf_ptr >= end_ptr)) { 
        return VAL_CONF_PARSE_ERROR;
    }

    g_opt->max_refresh = strtol(token, (char **)NULL, 10);
    
    return VAL_NO_ERROR;
}

static int
get_global_options(char **buf_ptr, char *end_ptr, 
                   int *line_number, val_global_opt_t **g_opt) 
{
    int endst = 0;
    char            token[TOKEN_MAX];
    int retval;
   
    if ((buf_ptr == NULL) || (*buf_ptr == NULL) || (end_ptr == NULL) || 
        (g_opt == NULL) || (line_number == NULL))
        return VAL_BAD_ARGUMENT;

    *g_opt = (val_global_opt_t *) MALLOC (sizeof (val_global_opt_t));
    if (*g_opt == NULL)
        return VAL_OUT_OF_MEMORY;
    set_global_opt_defaults(*g_opt);
    while (!endst) {
        /*
         * read the option type 
         */
        if (VAL_NO_ERROR != (retval = 
            val_get_token(buf_ptr, end_ptr, line_number, 
                          token, sizeof(token), &endst,
                          CONF_COMMENT, CONF_END_STMT, 0))) {
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
        if (!strcmp(token, GOPT_TRUST_OOB_STR) ||
            !strcmp(token, GOPT_TRUST_LOCAL_STR)) {
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
        } else if (!strcmp(token, GOPT_ENV_POL_STR)) {
            if (VAL_NO_ERROR != 
                    (retval = parse_enable_disable_gopt(&((*g_opt)->env_policy), buf_ptr, end_ptr, 
                                                        line_number, &endst, *g_opt))) {
                goto err;
            }
        } else if (!strcmp(token, GOPT_APP_POL_STR)) {
            if (VAL_NO_ERROR != 
                    (retval = parse_enable_disable_gopt(&((*g_opt)->app_policy), buf_ptr, end_ptr, 
                                                        line_number, &endst, *g_opt))) {
                goto err;
            }
        } else if (!strcmp(token, GOPT_LOGTARGET_STR)) {
            if (VAL_NO_ERROR != 
                    (retval = parse_log_target_gopt(buf_ptr, end_ptr, 
                                                    line_number, &endst, *g_opt))) {
                goto err;
            }
        } else if (!strcmp(token, GOPT_CLOSEST_TA_ONLY_STR)) {
            if (VAL_NO_ERROR != 
                    (retval = parse_closest_ta_target_gopt(buf_ptr, end_ptr, 
                                                    line_number, &endst, *g_opt))) {
                goto err;
            }

        } else if (!strcmp(token, GOPT_REC_FALLBACK)) {
            if (VAL_NO_ERROR != 
                    (retval = parse_rec_fallback(buf_ptr, end_ptr, 
                                                 line_number, &endst, *g_opt))) {
                goto err;
            }

        } else if (!strcmp(token, GOPT_MAX_REFRESH_STR)) {
            if (VAL_NO_ERROR != 
                    (retval = parse_max_refresh_gopt(buf_ptr, end_ptr,
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
int
get_next_policy_fragment(char **buf_ptr, char *end_ptr, const char *scope,
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
        if (label != NULL) {
            FREE(label);
            label = NULL;
        }

        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(buf_ptr, end_ptr, line_number, token, sizeof(token), &endst,
                       CONF_COMMENT, CONF_END_STMT, 0)))
            return retval;
        if (*buf_ptr >= end_ptr)
            return VAL_NO_ERROR;
        if (endst)
            return VAL_CONF_PARSE_ERROR;
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
                       CONF_COMMENT, CONF_END_STMT, 0))) {
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
                       CONF_COMMENT, CONF_END_STMT, 0))) {

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
int
store_policy_overrides(struct policy_overrides **overrides, 
                       struct policy_fragment **pfrag)
{
    struct policy_overrides *cur, *prev, *newp;
    struct policy_list *e;

    if ((overrides == NULL) || (pfrag == NULL) || (*pfrag == NULL))
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
     * Check if we have an existing entry for this label/policy-type combination 
     */
    for (e = newp->plist; e; e = e->next) {
        if (e->index == (*pfrag)->index) {
            /* 
             * Duplicate policy definition conf_elem_array[e->index].keyword
             * Use the first one found
             */
            free_policy_entry((*pfrag)->pol, (*pfrag)->index);
            (*pfrag)->pol = NULL;
            FREE(*pfrag);
            
            return VAL_NO_ERROR;
        }
    }

    /*
     * Add policy-type to list 
     */
    e = (struct policy_list *) MALLOC(sizeof(struct policy_list));
    if (e == NULL)
        return VAL_OUT_OF_MEMORY;

    e->index = (*pfrag)->index;
    e->next = newp->plist;
    newp->plist = e;
    e->pol = (*pfrag)->pol;
    (*pfrag)->pol = NULL;
    FREE(*pfrag);

    return VAL_NO_ERROR;
}

void
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
        /*XXX should stop logging to current channel */
        free_global_options(ctx->g_opt);
        FREE(ctx->g_opt);
        ctx->g_opt = NULL;
    }
}


#ifdef __linux__
#define getprogname() program_invocation_short_name 
#endif
#ifdef solaris2
#define getprogname() getexecname()
#endif
#ifdef WIN32
#define getprogname() NULL
#endif
#ifdef __OpenBSD__
#define getprogname() NULL
#endif
#ifdef eabi
#define getprogname() NULL
#endif

static int
read_next_val_config_file(val_context_t *ctx, 
                          const char **label, 
                          struct dnsval_list *dnsval_c, 
                          struct dnsval_list *dlist, 
                          struct dnsval_list **added_files,
                          struct policy_overrides **overrides,
                          val_global_opt_t **g_opt)
{
    int    fd = -1;
#ifdef HAVE_FLOCK
    struct flock    fl;
#endif
    struct stat sb;
    char token[TOKEN_MAX];
    int endst = 0;
    char *buf = NULL;
    size_t bufsize = 0;
    char *buf_ptr, *end_ptr;
    int  line_number = 1;
    struct policy_fragment *pol_frag = NULL;
    int g_opt_seen = 0;
    int include_seen = 0;
    char *dnsval_filename = NULL;
    struct dnsval_list *dnsval_l;
    int retval = VAL_NO_ERROR;
    const char *next_label;
    int done;
    char *env = NULL;

    if (ctx == NULL || label == NULL || 
        added_files == NULL || 
        overrides == NULL || g_opt == NULL)
        return VAL_BAD_ARGUMENT;

    done = 0;
    pol_frag = NULL;
    *added_files = NULL;

    next_label = *label;
   
    fd = -1;
    if (dnsval_c != NULL && dlist != NULL) {
        fd = open(dnsval_c->dnsval_conf, O_RDONLY);
    }

    if (fd < 0) {
        val_log(ctx, LOG_ERR, 
                "read_next_val_config_file(): Could not open validator conf file for reading: %s",
                dnsval_c->dnsval_conf);

        /* check if we have read at least one file in the past */
        if (dnsval_c && dlist && (dnsval_c != dlist)) {
            return VAL_NO_ERROR;
        }
        /* check if we have the validator policy available inline */
        bufsize = sizeof(val_conf_inline_buf);
        if (!strncmp(val_conf_inline_buf, "", sizeof(""))) {
            retval = VAL_CONF_NOT_FOUND;
            goto err;
        }
        val_log(ctx, LOG_INFO, 
                "read_next_val_config_file(): Using inline validator configuration data");
        buf = (char *) MALLOC (bufsize * sizeof(char));
        if (buf == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        memcpy(buf, val_conf_inline_buf, bufsize);
    } else {
#ifdef HAVE_FLOCK
        memset(&fl, 0, sizeof(fl));
        fl.l_type = F_RDLCK;
        if (-1 == fcntl(fd, F_SETLK, &fl)) {
            val_log(ctx, LOG_WARNING, 
                "read_next_val_config_file(): Could not acquire shared lock on conf file: %s", 
                dnsval_c->dnsval_conf);
            goto err; 
        }
#endif
        if (0 != fstat(fd, &sb)) {
            val_log(ctx, LOG_ERR, 
                "read_next_val_config_file(): Could not stat validator conf file: %s",
                dnsval_c->dnsval_conf);
            retval = VAL_CONF_NOT_FOUND;
            goto err;
        } 
        dnsval_c->v_timestamp = sb.st_mtime;
        bufsize = sb.st_size;

        buf = (char *) MALLOC (bufsize * sizeof(char));
        if (buf == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }

        if (-1 == read(fd, buf, bufsize)) {
            val_log(ctx, LOG_ERR, "read_next_val_config_file(): Could not read validator conf file: %s",
                    dnsval_c->dnsval_conf);
            retval = VAL_CONF_NOT_FOUND;
            goto err;
        }
#ifdef HAVE_FLOCK
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
#endif
        close(fd);
        fd = -1;
    }

    val_log(ctx, LOG_NOTICE, "read_next_val_config_file(): Reading validator policy from %s",
            dnsval_c->dnsval_conf);
    val_log(ctx, LOG_DEBUG, "read_next_val_config_file(): Reading next policy fragment");

    while (!done) {

        if (*added_files) {
            FREE_DNSVAL_FILE_LIST(*added_files);
            *added_files = NULL;
        }

        /* if we're looping again for the first file, trash our temporary overrides */
        if (*overrides && dnsval_c == dlist) {
            destroy_valpolovr(overrides);
            *overrides = NULL;
        }

        /* don't free global options g_opt since we're going to reuse this */

        buf_ptr = buf;
        end_ptr = buf+bufsize;
        dnsval_l = NULL;
        done = 1;
    
        while (VAL_NO_ERROR == (retval =
                    get_next_policy_fragment(&buf_ptr, end_ptr, 
                                             next_label, 
                                             &pol_frag, 
                                             &line_number, 
                                             &g_opt_seen,
                                             &include_seen))) {
            if (g_opt_seen) {
                /* next policy fragment contains global options */ 
                val_global_opt_t *gt_opt = NULL;
                g_opt_seen = 0;
                if (VAL_NO_ERROR != (retval =
                        get_global_options(&buf_ptr, end_ptr, 
                                          &line_number, &gt_opt))) {
                    val_log(ctx, LOG_ERR, 
                            "read_next_val_config_file(): Error in line %d of %s ",
                            line_number, dnsval_c->dnsval_conf);
                    goto err;
                }
    
                if (*g_opt || (dnsval_c != dlist)) {
                    /* 
                     * re-definition of global options 
                     * or global options was not in the first file
                     */
                    val_log(ctx, LOG_WARNING, 
                            "read_next_val_config_file(): Ignoring global options from line %d of %s",
                            line_number, dnsval_c->dnsval_conf);
                    free_global_options(gt_opt);
                    FREE(gt_opt);
                    gt_opt = NULL;
                } else {
                    *g_opt = gt_opt;
                    val_log(ctx, LOG_DEBUG, 
                            "read_next_val_config_file(): Using global options from line %d of %s",
                            line_number, dnsval_c->dnsval_conf);
                    
                    if (gt_opt->env_policy == VAL_POL_GOPT_OVERRIDE ||
                            (*label == NULL && gt_opt->env_policy == VAL_POL_GOPT_ENABLE)) {
                        next_label = getenv(VAL_CONTEXT_LABEL);
                        if (next_label != NULL) {
                            val_log(ctx, LOG_NOTICE, 
                                    "read_next_val_config_file(): Using policy label from environment: %s",
                                    next_label);
                            done = 0;
                            break;
                        }
                        /* policy does not exist, dont create the impression that we have one */
                        gt_opt->env_policy = VAL_POL_GOPT_DISABLE;
                        next_label = *label;
                    } 
                    if (gt_opt->app_policy == VAL_POL_GOPT_OVERRIDE ||
                            (*label == NULL && gt_opt->app_policy == VAL_POL_GOPT_ENABLE)) {
                        const char *c_next_label = getprogname();
                        if (c_next_label != NULL) {
                            val_log(ctx, LOG_NOTICE, 
                                    "read_next_val_config_file(): Using policy label from app name: %s",
                                    c_next_label);
                            done = 0;
                            next_label = (const char *)c_next_label;
                            break;
                        }
                        /* policy does not exist, dont create the impression that we have one */
                        gt_opt->app_policy = VAL_POL_GOPT_DISABLE;
                        next_label = *label;
                    }
                } 
            } else if (include_seen) { 
                /* need to include another file */
                struct dnsval_list *dnsval_temp;
                include_seen = 0;
                /* read the filename in the next token */
                if (VAL_NO_ERROR != (retval = 
                        val_get_token(&buf_ptr, end_ptr, &line_number, 
                                      token, sizeof(token), &endst,
                                      CONF_COMMENT, CONF_END_STMT, 0))) {
                    val_log(ctx, LOG_ERR, 
                            "read_next_val_config_file(): Error in line %d of %s ",
                            line_number, dnsval_c->dnsval_conf);
                    goto err;
                }
                if ((endst && (strlen(token) == 0)) || (buf_ptr >= end_ptr)) { 
                    val_log(ctx, LOG_ERR, 
                            "read_next_val_config_file(): Error in line %d of %s ",
                            line_number, dnsval_c->dnsval_conf);
                    retval = VAL_CONF_PARSE_ERROR;
                    goto err;
                }

                /* expand any environment variables */
                if (NULL != (env = strchr(token, '$'))) {
                    char env_token[TOKEN_MAX];
                    char *cp1, *cp2, *cp3;
                    int len;

                    strcpy(env_token, "");
                    cp1 = env_token;

                    cp2 = env;
                    cp2++; /* next character after $ */

                    /* get the variable name in cp1 */
                    while ((*cp2 != '\0') && isalnum(*cp2)) {
                        *cp1 = *cp2;
                        cp1++; cp2++;
                    }
                    *cp1 = '\0';
                    
                    /* get the value in cp1 */
                    if ((NULL == (cp1 = getenv(env_token))) ||
                        (strlen(token) + strlen(cp1) - strlen(env_token) 
                            >= TOKEN_MAX)) {

                        val_log(ctx, LOG_ERR, 
                            "read_next_val_config_file(): Unknown environment"
                            "variable in line %d of %s ", 
                            line_number, dnsval_c->dnsval_conf);
                        retval = VAL_CONF_PARSE_ERROR;
                        goto err;
                    } 

                    /* save the length of the reference */
                    /* Add 1 for the $ character */
                    len = strlen(env_token) + 1; 
                    
                    /* cp3 will contain the complete expanded file name */
                    strcpy(env_token, "");
                    cp3 = env_token;

                    /* 
                     *  the value of the env variable is in cp1, 
                     *  env points to the string of length len where it is 
                     *  referenced.
                     *  Replace reference with value and store in env_token. 
                     */
                    cp2 = token;
                    while (*cp2 != '\0' && cp2 < env) { 
                        *cp3 = *cp2;
                        cp3++; cp2++;
                    }
                    while (*cp1 != '\0') {
                        *cp3 = *cp1;
                        cp3++; cp1++; 
                    }
                    cp2 = env + len;
                    while (*cp2 != '\0') { 
                        *cp3 = *cp2;
                        cp3++; cp2++; 
                    }
                    *cp3 = '\0';

                    strcpy(token, env_token);
                } 
    
                /* check if filename already exists in the list */
                for (dnsval_temp=dlist; dnsval_temp; dnsval_temp=dnsval_temp->next) {
                    if (!strcmp(dnsval_temp->dnsval_conf, token)) {
                        val_log(ctx, LOG_ERR, 
                                "read_next_val_config_file(): File already included, possible loop in line %d of %s ",
                                line_number, dnsval_c->dnsval_conf);
                        retval = VAL_CONF_PARSE_ERROR;
                        goto err;
                    }
                } 
    
                dnsval_filename = strdup(token);
                if (dnsval_filename == NULL) {
                    retval = VAL_OUT_OF_MEMORY;
                    goto err;
                }
                dnsval_temp = (struct dnsval_list *) MALLOC (sizeof(struct dnsval_list));
                if (dnsval_temp == NULL) {
                    FREE(dnsval_filename);
                    retval = VAL_OUT_OF_MEMORY;
                    goto err;
                }
                dnsval_temp->dnsval_conf = dnsval_filename; 
                dnsval_temp->next = NULL;
    
                if (dnsval_l) {
                    dnsval_l->next = dnsval_temp;
                } else {
                    *added_files = dnsval_temp;
                }
                dnsval_l = dnsval_temp;
            } else {
                /*
                 * Store this fragment as an override, consume pol_frag 
                 */
                store_policy_overrides(overrides, &pol_frag);
                pol_frag = NULL;
            }
            if (buf_ptr >= end_ptr) {
                /* done reading file */
                retval = VAL_NO_ERROR;
                break;
            }
        }
    }

    if (retval != VAL_NO_ERROR) {
        val_log(ctx, LOG_ERR, "read_next_val_config_file(): Error in line %d of %s", line_number,
                dnsval_c->dnsval_conf);
        goto err;
    } 

    *label = next_label;
    FREE(buf);
    buf = NULL;

    return VAL_NO_ERROR;

err:
    FREE_DNSVAL_FILE_LIST(*added_files);
    if (pol_frag) {
        FREE(pol_frag->label);
        free_policy_entry(pol_frag->pol, pol_frag->index);
        FREE(pol_frag);
    }
    if (buf) { 
        FREE(buf);
    }
    if (fd != -1) {
#ifdef HAVE_FLOCK
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
#endif
        close(fd);
    }
    return retval;
}

/*
 * Make sense of the validator configuration file
 * Precedence is environment, app and user
 */
int
read_val_config_file(val_context_t * ctx, const char *scope)
{
    struct policy_overrides *t;
    struct dnsval_list *dnsval_c;
    int             retval;
    const char *label;
    char *newctxlab;
    struct val_query_chain *q;
    char *logtarget = NULL;
    val_global_opt_t *g_opt = NULL;
    struct dnsval_list *dlist = NULL;
    struct policy_overrides *overrides = NULL;
   
    if (ctx == NULL)
        return VAL_BAD_ARGUMENT;

    label = scope;

    /*
     * If our dynamic policies override existing policies
     * we don't need to read any of the config files 
     */
    if ((ctx->dyn_polflags & CTX_DYN_POL_VAL_OVR) &&
        (ctx->dyn_polflags & CTX_DYN_POL_GLO_OVR))
        goto skipfileread;
    
    if (ctx->base_dnsval_conf == NULL) {
        goto skipfileread;
    }
   
    /* create a new head element for the dnsval.conf file list */
    dlist = (struct dnsval_list *) MALLOC (sizeof(struct dnsval_list));
    if (dlist == NULL) {
        return VAL_OUT_OF_MEMORY;
    }
    dlist->dnsval_conf = strdup(ctx->base_dnsval_conf);
    dlist->v_timestamp = 0;
    dlist->next = NULL; 
    dnsval_c = dlist;

    while(dnsval_c) {
        struct dnsval_list *added_list = NULL;
        /* read the head element first */
        if (VAL_NO_ERROR != (retval = 
                read_next_val_config_file(ctx,
                                          &label,
                                          dnsval_c,
                                          dlist,
                                          &added_list,
                                          &overrides, 
                                          &g_opt))) {

             /* 
              * Ignore files that could not be read at all, 
              * flag error in other cases 
              */
            if (retval != VAL_CONF_NOT_FOUND) {
                goto err;
            }
        }

        /* Add new file names to the list */
        if (added_list) {
            struct dnsval_list *dnsval_l = added_list;
            while (dnsval_l->next)
                dnsval_l = dnsval_l->next;

            /* add added_list between dnsval_c and its successor */
            dnsval_l->next = dnsval_c->next;
            dnsval_c->next = added_list;
            added_list = NULL;
        }
        dnsval_c = dnsval_c->next;
    }

skipfileread:
    newctxlab = NULL;
    if (label == NULL) {
        /*
         * Use the first policy as the default (only) policy 
         */
        if (overrides)
            destroy_valpolovr(&overrides->next);
    } else { 
        /* clone the label */
        newctxlab = strdup(label); 
        if (newctxlab == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
    }

    if (ctx->label)
        FREE(ctx->label);
    ctx->label = newctxlab;

    destroy_valpol(ctx);

    /* process overrides unless we want to override them */
    if (!(ctx->dyn_polflags & CTX_DYN_POL_VAL_OVR)) {
        /* Replace policies */
        for (t = overrides; t != NULL; t = t->next) {
            struct policy_list *c;
            for (c = t->plist; c; c = c->next){
                /* Override elements in e_pol[c->index] with what's in c->pol */
                STORE_POLICY_ENTRY_IN_LIST(c->pol, ctx->e_pol[c->index]);
            }
        }
    }

    destroy_valpolovr(&overrides);

    /* Apply any dynamic policies */
    for (t = ctx->dyn_valpol; t != NULL; t = t->next) {
        struct policy_list *c;
        for (c = t->plist; c; c = c->next){
            /* Override elements in e_pol[c->index] with what's in c->pol */
            STORE_POLICY_ENTRY_IN_LIST(c->pol, ctx->e_pol[c->index]);
        }
    }

    /* Process Global options */
    ctx->g_opt = g_opt;

    /* free up older log targets */
    while (ctx->val_log_targets) {
        val_log_t *temp = ctx->val_log_targets->next;
        FREE (ctx->val_log_targets);
        ctx->val_log_targets = temp;
    }
    ctx->val_log_targets = NULL;
    
    /* enable logging as specified by global options */
    if (ctx->g_opt && ctx->g_opt->log_target) {
        val_log_add_optarg_to_list(&ctx->val_log_targets, ctx->g_opt->log_target, 1);
    }
    /* enable logging as specified by dynamic policy */
    if (ctx->dyn_valpolopt && ctx->dyn_valpolopt->log_target) {
        val_log_add_optarg_to_list(&ctx->val_log_targets,
                ctx->dyn_valpolopt->log_target, 1);
    }
    /* set the log target from environment */
    logtarget = getenv(VAL_LOG_TARGET);
    if (logtarget) {
        val_log_add_optarg_to_list(&ctx->val_log_targets, logtarget, 1);
    }

    /* 
     * Merge other dynamic global options into the context 
     */
    if (ctx->dyn_valpolopt) {
        if (VAL_NO_ERROR != 
                (retval = update_dynamic_gopt(&ctx->g_opt, ctx->dyn_valpolopt)))
            goto err;
    }

    /* 
     * Free the query cache 
     */
    while (NULL != (q = ctx->q_list)) {
        ctx->q_list = q->qc_next;
        free_query_chain_structure(q);
        q = NULL;
    }

    ctx->dnsval_l = dlist;

    val_log(ctx, LOG_DEBUG, "read_val_config_file(): Done reading validator configuration");

    return VAL_NO_ERROR;

err:
    if (overrides) {
        destroy_valpolovr(&overrides);
        overrides = NULL;
    }
    if (g_opt) {
        free_global_options(g_opt);
        FREE(g_opt);
        g_opt = NULL;
    }
    FREE_DNSVAL_FILE_LIST(dlist);
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

struct name_server *
val_get_nameservers(val_context_t *context)
{
    val_context_t *ctx = NULL;
    struct name_server *ns_list = NULL;

    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL) {
        return NULL;
    }
    clone_ns_list(&ns_list, ctx->nslist);

    CTX_UNLOCK_POL(ctx);

    return ns_list;
}

#ifdef ANDROID
int
read_res_config_file(val_context_t * ctx)
{
    /* android stores its resolvers in its property system */
    char property_buffer[PROP_VALUE_MAX + 1];
    char property_name[PROP_NAME_MAX+1];
    int  property_buffer_len;
    int  counter = 0;
    struct name_server *ns_head = NULL;
    struct name_server *ns_tail = NULL;
    struct name_server *ns = NULL;

    while(counter < 255) { /* arbitary way-too-high upper limit */
        /* shouldn't be necessary, but still wise */
        property_name[PROP_NAME_MAX] = '\0';
        property_buffer[PROP_VALUE_MAX] = '\0';

        snprintf(property_name, PROP_NAME_MAX, "net.dns%d", ++counter);
        if (! __system_property_get(property_name, property_buffer)) {
            /* end of the list: 0 length return */
            break;
        }

        ns = parse_name_server(property_buffer, NULL);
        if (ns == NULL) {
            val_log(ctx, LOG_WARNING,
                    "read_res_config_file(): error parsing android resource!");
            return VAL_CONF_PARSE_ERROR;
        }

        ns->ns_options |= RES_RECURSE;
        if (ns_tail == NULL) {
            ns_head = ns;
            ns_tail = ns;
        } else {
            ns_tail->ns_next = ns;
            ns_tail = ns;
        }
    }

    /*
     * Check if we have root hints 
     */
    if (ns_head == NULL) {
        if (!ctx->root_ns) {
            val_log(ctx, LOG_WARNING, 
                    "read_res_config_file(): Resolver configuration empty or missing, but root-hints was not found");
            return VAL_CONF_NOT_FOUND;
        }
    } 

    destroy_respol(ctx);
    ctx->nslist = ns_head;
    ctx->r_timestamp = 0; /* XXX: set to what?  there is no file stat */

    val_log(ctx, LOG_DEBUG, 
            "read_res_config_file(): Done reading resolver configuration");
    return VAL_NO_ERROR;
}

#else /* ! ANDROID */

int
read_res_config_file(val_context_t * ctx)
{
    char           *resolv_config;
#ifdef HAVE_FLOCK
    struct flock    fl;
#endif
    char            token[TOKEN_MAX];
    int             fd = -1;
    int             line_number = 0;
    int             endst = 0;
    struct name_server *ns_head = NULL;
    struct name_server *ns_tail = NULL;
    struct name_server *ns = NULL;
    u_char zone_n[NS_MAXCDNAME];
    struct stat sb;
    char *buf_ptr, *end_ptr;
    char *buf = NULL;
    size_t bufsize = 0;
    int retval;
    time_t mtime = 0;
    
    if (ctx == NULL)
        return VAL_BAD_ARGUMENT;

    /*
     * Use any dynamic resolver policy that we may have
     */
    if (ctx->dyn_nslist) {
        clone_ns_list(&ns_head, ctx->dyn_nslist);
        ns = ns_head;
        while (ns) {
            ns_tail = ns;
            ns = ns->ns_next;
        }
    }
    if (ctx->dyn_polflags & CTX_DYN_POL_RES_OVR) {
        goto done;
    }

    resolv_config = ctx->resolv_conf;
    if (resolv_config) {
        fd = open(resolv_config, O_RDONLY);
        if (fd == -1) {
            val_log(ctx, LOG_ERR, "read_res_config_file(): Could not open resolver conf file for reading: %s",
                resolv_config);
    
            /* Use default resolv.conf file */
            FREE(ctx->resolv_conf);
            ctx->resolv_conf = strdup(VAL_DEFAULT_RESOLV_CONF);
            if (ctx->resolv_conf == NULL) {
                return VAL_OUT_OF_MEMORY;
            }
            resolv_config = ctx->resolv_conf;
            fd = open(resolv_config, O_RDONLY);
        }
    }

    if (fd > 0) {
#ifdef HAVE_FLOCK
        memset(&fl, 0, sizeof(fl));
        fl.l_type = F_RDLCK;
        if (-1 == fcntl(fd, F_SETLK, &fl)) {
            val_log(ctx, LOG_WARNING, 
                "read_next_val_config_file(): Could not acquire shared lock on conf file: %s", 
                resolv_config);
            goto err;
        }
#endif

        if (0 != fstat(fd, &sb)) {
            retval = VAL_CONF_NOT_FOUND;
            goto err;
        } 
        if (0 == sb.st_size)
            goto done;

        mtime = sb.st_mtime;
        bufsize = sb.st_size;
        buf = (char *) MALLOC (bufsize * sizeof(char));
        if (buf == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        if (-1 == read(fd, buf, bufsize)) {
            val_log(ctx, LOG_ERR, "read_res_config_file(): Could not read resolver conf file: %s",
                    resolv_config);
            retval = VAL_CONF_NOT_FOUND;
            goto err;
        }
#ifdef HAVE_FLOCK
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
#endif
        close(fd);
        fd = -1;

        val_log(ctx, LOG_NOTICE, "read_res_config_file(): Reading resolver policy from %s", resolv_config);

    } else {
        if (resolv_config)
            val_log(ctx, LOG_ERR, "read_res_config_file(): Could not open resolver conf file for reading: %s",
                    resolv_config);

        /* Try to read any inline resolv.conf information */
        mtime = 0;
        bufsize = sizeof(resolv_conf_inline_buf);
        if (!strncmp(resolv_conf_inline_buf, "", sizeof(""))) {
            goto done;
        }
        val_log(ctx, LOG_INFO, 
                "read_res_config_file(): Using inline resolv.conf data");
        buf = (char *) MALLOC (bufsize * sizeof(char));
        if (buf == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        memcpy(buf, resolv_conf_inline_buf, bufsize);
    }

    buf_ptr = buf;
    end_ptr = buf+bufsize;

    while(buf_ptr < end_ptr) {

        /* Read the keyword */
        if (VAL_NO_ERROR !=
            (retval =
             val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
                       ALL_COMMENTS, ZONE_END_STMT, 0))) {
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
                           ALL_COMMENTS, ZONE_END_STMT, 0))) {
                val_log(ctx, LOG_WARNING,
			"read_res_config_file(): error getting nameserver token!");
                goto err;
            }
            if ((ns = parse_name_server(token, DEFAULT_ZONE)) == NULL) {
                val_log(ctx, LOG_WARNING,
			"read_res_config_file(): error parsing nameserver token!");
                goto err;
	        }
            if (ns != NULL) {
                ns->ns_options |= SR_QUERY_RECURSE;
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
                           ALL_COMMENTS, ZONE_END_STMT, 0))) {
                goto err;
            }
            if ((ns = parse_name_server(token, DEFAULT_ZONE)) == NULL)
                goto err;
            /* zone next */
            if (VAL_NO_ERROR !=
                (retval =
                val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
                           ALL_COMMENTS, ZONE_END_STMT, 0))) {
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
                           ALL_COMMENTS, ZONE_END_STMT, 0))) {
                goto err;
            }
            if (ctx->search)
                free(ctx->search);
            ctx->search = strdup(token);
        }
    }

    FREE(buf);

  done:

    /*
     * Check if we have root hints 
     */
    if (ns_head == NULL) {
        if (!ctx->root_ns) {
            val_log(ctx, LOG_WARNING, 
                    "read_res_config_file(): Resolver configuration empty or missing, but root-hints was not found");
            return VAL_CONF_NOT_FOUND;
        }
    } 

    destroy_respol(ctx);
    ctx->nslist = ns_head;
    ctx->r_timestamp = mtime;

    val_log(ctx, LOG_DEBUG, 
            "read_res_config_file(): Done reading resolver configuration");

    if (fd != -1) {
#ifdef HAVE_FLOCK
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
#endif
        close(fd);
    }
    return VAL_NO_ERROR;

  err:
    val_log(ctx, LOG_ERR, 
            "read_res_config_file(): Error encountered while reading file %s", resolv_config);
    free_name_servers(&ns_head);

    if (buf)
        FREE(buf);

    if (fd != -1) {
#ifdef HAVE_FLOCK
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
#endif
        close(fd);
    }

    return VAL_CONF_PARSE_ERROR;
}

#endif /* ! ANDROID */

/*
 * parse the contents of the root.hints file into resource records 
 */
int
read_root_hints_file(val_context_t * ctx)
{
    struct rrset_rec *root_info = NULL;
    int             fd;
#ifdef HAVE_FLOCK
    struct flock    fl;
#endif
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
    int             retval = VAL_NO_ERROR;
    u_int16_t       rdata_len_h;
    struct rrset_rec *rr_set;
    struct name_server *ns_list = NULL;
    struct name_server *pending_glue = NULL;    
    struct stat sb;
    int have_type;
    char *buf_ptr, *end_ptr;
    char *buf = NULL;
    size_t bufsize = 0;
    time_t mtime;

    class_h = 0;
    have_type = 0;

    if (ctx == NULL)
        return VAL_BAD_ARGUMENT;
    
    root_hints = ctx->root_conf;

    fd = -1;

    if (NULL != root_hints && 
            (fd = open(root_hints, O_RDONLY)) > 0) {
#ifdef HAVE_FLOCK
        memset(&fl, 0, sizeof(fl));
        fl.l_type = F_RDLCK;
        if (-1 == fcntl(fd, F_SETLK, &fl)) {
            val_log(ctx, LOG_WARNING, 
                    "read_next_val_config_file(): Could not acquire shared lock on conf file: %s", 
                    root_hints);
            goto err;
        }
#endif
        if (0 != fstat(fd, &sb)) { 
            retval = VAL_CONF_NOT_FOUND;
            goto err;
        }
        mtime = sb.st_mtime;
        bufsize = sb.st_size;
        buf = (char *) MALLOC (bufsize * sizeof(char));
        if (buf == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        if (-1 == read(fd, buf, bufsize)) {
            val_log(ctx, LOG_ERR, "read_root_hints_file(): Could not read root hints file: %s",
                    root_hints);
            retval = VAL_CONF_NOT_FOUND;
            goto err;
        }
#ifdef HAVE_FLOCK
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
#endif
        close(fd);
        fd = -1;

        val_log(ctx, LOG_NOTICE, "read_root_hints_file(): Reading root hints from %s",
                root_hints);

    } else {
        /* Try to read any inline root.hints information */
        mtime = 0;
        bufsize = sizeof(root_hints_inline_buf);
        if (!strncmp(root_hints_inline_buf, "", sizeof(""))) {
            if (root_hints)
                val_log(ctx, LOG_INFO, "read_root_hints_file(): Could not open root hints file for reading: %s",
                    root_hints);
            else
                val_log(ctx, LOG_INFO, "read_root_hints_file(): No root.hints file configured"); 
            /* 
             * Root hints are not necessary. Only needed if our resolv.conf is empty. 
             * Flag the error at that time
             */
            return VAL_NO_ERROR;
        }
        val_log(ctx, LOG_INFO, 
                "read_root_hints_file(): Using inline root.hints data");
        buf = (char *) MALLOC (bufsize * sizeof(char));
        if (buf == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        memcpy(buf, root_hints_inline_buf, bufsize);
    }

    buf_ptr = buf;
    end_ptr = buf+bufsize;

    while (buf_ptr < end_ptr) {

        /*
         * name 
         */
        if (VAL_NO_ERROR !=
            (retval =
            val_get_token(&buf_ptr, end_ptr, &line_number, token, sizeof(token), &endst,
                   ZONE_COMMENT, ZONE_END_STMT, 0))) {
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
                       ZONE_COMMENT, ZONE_END_STMT, 0))) {
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
                       ZONE_COMMENT, ZONE_END_STMT, 0))) {
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
                       ZONE_COMMENT, ZONE_END_STMT, 0))) {
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
                       ZONE_COMMENT, ZONE_END_STMT, 0))) {
            goto err;
        }
        if (type_h == ns_t_a) {
            struct sockaddr_in sa;
            size_t addrlen4 = sizeof(struct sockaddr_in);
            memset(&sa, 0, sizeof(sa));
            if ((addrlen4 == addrlen4) && /* this is to remove unused variable warning */
                (INET_PTON(AF_INET, token, ((struct sockaddr *)&sa), &addrlen4) != 1)) {
                retval = VAL_CONF_PARSE_ERROR;
                goto err;
            }
            rdata_len_h = sizeof(struct in_addr);
            memcpy(rdata_n, &sa.sin_addr, rdata_len_h);
#ifdef VAL_IPV6
        } else if (type_h == ns_t_aaaa) {
            struct sockaddr_in6 sa6;
            size_t addrlen6 = sizeof(struct sockaddr_in6);
            memset(&sa6, 0, sizeof(sa6));
            if ((addrlen6 == addrlen6) && /* this is to remove unused variable warning */
                (INET_PTON(AF_INET6, token, ((struct sockaddr *)&sa6), &addrlen6) != 1)) {
                val_log(ctx, LOG_INFO, 
                        "read_root_hints_file(): Cannot parse IPv6 address, skipping.");
                continue;
            }
            rdata_len_h = sizeof(struct in6_addr);
            memcpy(rdata_n, &sa6.sin6_addr, rdata_len_h);
#endif
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
                             0, 0, zone_n);
        if (rr_set == NULL) {
            retval = VAL_OUT_OF_MEMORY;
            goto err;
        }
        if (type_h != ns_t_rrsig) {
            /* Add this record to its chain. */
            retval = add_to_set(rr_set, rdata_len_h, rdata_n);
        } else {
            /* Add this record's sig to its chain. */
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
         res_zi_unverified_ns_list(ctx, &ns_list, root_zone_n, root_info,
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

    if (ctx->root_ns)
        free_name_servers(&ctx->root_ns);
    ctx->root_ns = ns_list;
    ctx->h_timestamp = mtime;

    res_sq_free_rrset_recs(&root_info);

    val_log(ctx, LOG_DEBUG, "read_root_hints_file(): Done reading root hints");
    FREE(buf);


    return VAL_NO_ERROR;

  err:

    if (buf)
        FREE(buf);
    if (fd > 0) {
#ifdef HAVE_FLOCK
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
#endif
        close(fd);
    }
    res_sq_free_rrset_recs(&root_info);
    val_log(ctx, LOG_ERR, "read_root_hints_file(): Error encountered around line %d while reading file %s - %s",
            line_number, root_hints, p_val_err(retval));
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
#ifdef HAVE_STRTOK_R
        char           *buf = NULL;
#endif
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
#ifdef HAVE_STRTOK_R
        cp = (char *) strtok_r(line, "#", &buf);
#else
	    cp = (char *) strtok(line, "#");
#endif

        if (!cp)
            continue;

        memset(fileentry, 0, MAXLINE);
        strncpy(fileentry, cp, sizeof(fileentry));

        /*
         * read the ip address 
         */
#ifdef HAVE_STRTOK_R
        cp = (char *) strtok_r(fileentry, white, &buf);
#else
        cp = (char *) strtok(fileentry, white);
#endif
        if (!cp)
            continue;

        memset(addr_buf, 0, INET6_ADDRSTRLEN);
        strncpy(addr_buf, cp, sizeof(addr_buf));

        /*
         * read the full domain name 
         */
#ifdef HAVE_STRTOK_R
        cp = (char *) strtok_r(NULL, white, &buf);
#else
        cp = (char *) strtok(NULL, white);
#endif
        if (!cp)
            continue;

        domain_name = cp;

        if (strncasecmp(name, cp, strlen(cp)) == 0) {
            matchfound = 1;
        }

        /*
         * read the aliases 
         */
        memset(alias_list, 0, MAX_ALIAS_COUNT);
        alias_index = 0;
#ifdef HAVE_STRTOK_R
        while ((cp = (char *) strtok_r(NULL, white, &buf)) != NULL) {
#else
        while ((cp = (char *) strtok(NULL, white)) != NULL) {
#endif
            alias_list[alias_index++] = cp;
            if ((!matchfound) && (strncasecmp(name, cp, strlen(cp)) == 0)) {
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

        memset(hentry, 0, sizeof(struct hosts));
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
val_add_valpolicy(val_context_t *context, 
                  void *policy_definition,
                  val_policy_handle_t **pol)
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

    libval_policy_definition_t *libval_pol;

    if (policy_definition == NULL || pol == NULL)
        return VAL_BAD_ARGUMENT;

    libval_pol = (libval_policy_definition_t *) policy_definition;

    if (libval_pol->keyword == NULL || 
        libval_pol->zone == NULL || 
        libval_pol->value == NULL)
        return VAL_BAD_ARGUMENT;

    *pol = NULL;

    /* find the policy according to the keyword */
    for (index = 0; index < MAX_POL_TOKEN; index++) {
        if (!strcmp(libval_pol->keyword, conf_elem_array[index].keyword)) {
            break;
        }
    }
    if (index == MAX_POL_TOKEN) {
        return VAL_BAD_ARGUMENT;
    }

    if (ns_name_pton(libval_pol->zone, zone_n, NS_MAXCDNAME) == -1) {
        return VAL_BAD_ARGUMENT;
    } 

    if (libval_pol->ttl > 0) {
        gettimeofday(&tv, NULL);
        ttl_x = libval_pol->ttl + tv.tv_sec;
    } else
        ttl_x = 0;
        
    buf_ptr = libval_pol->value;
    end_ptr = libval_pol->value+strlen(libval_pol->value);

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

    *pol = (val_policy_handle_t *) MALLOC (sizeof(val_policy_handle_t));
    if (*pol == NULL) {
        FREE(pol_entry);
        return VAL_OUT_OF_MEMORY;
    }

    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL) { 
        FREE(pol_entry);
        FREE(*pol);
        *pol = NULL;
        return VAL_OUT_OF_MEMORY;
    }
   
    /* Lock exclusively */
    CTX_LOCK_ACACHE(ctx);

    (*pol)->pe = pol_entry;
    (*pol)->index = index;

    /* Merge this policy into the context */
    STORE_POLICY_ENTRY_IN_LIST(pol_entry, ctx->e_pol[index]);

    /* Flush queries that match this name */
    for(q=ctx->q_list; q; q=q->qc_next) {
        if (NULL != namename(q->qc_name_n, zone_n)) {
            q->qc_flags |= VAL_QUERY_MARK_FOR_DELETION;
        }
    }
    
    CTX_UNLOCK_ACACHE(ctx);
    CTX_UNLOCK_POL(ctx);

    return VAL_NO_ERROR;
}  

int 
val_remove_valpolicy(val_context_t *context, val_policy_handle_t *pol)
{
    val_context_t *ctx = NULL;
    policy_entry_t *p, *prev;
    struct val_query_chain *q;
    int retval;

    if (pol == NULL || pol->pe == NULL|| pol->index >= MAX_POL_TOKEN)
       return VAL_BAD_ARGUMENT; 

    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL)
        return VAL_INTERNAL_ERROR;
    
    /* Lock exclusively */
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

    /* free the policy */
    conf_elem_array[pol->index].free(p);
    FREE(p);
    FREE(pol);
    
    /* Flush queries that match this name */
    for(q=ctx->q_list; q; q=q->qc_next) {
        if (NULL != namename(q->qc_name_n, p->zone_n)) {
            q->qc_flags |= VAL_QUERY_MARK_FOR_DELETION;
        }
    }
    
    retval = VAL_NO_ERROR;

err:
    CTX_UNLOCK_ACACHE(ctx);
    CTX_UNLOCK_POL(ctx);
    
    return retval;
}

int
val_is_local_trusted(val_context_t *context, int *trusted)
{
    val_context_t *ctx = NULL;

    if (trusted == NULL)
        return VAL_BAD_ARGUMENT;

    ctx = val_create_or_refresh_context(context); /* does CTX_LOCK_POL_SH */
    if (ctx == NULL)
        return VAL_INTERNAL_ERROR;

    if (ctx && ctx->g_opt && ctx->g_opt->local_is_trusted)
        *trusted = 1;
    else
        *trusted = 0;

    CTX_UNLOCK_POL(ctx);

    return VAL_NO_ERROR;    
}
    

