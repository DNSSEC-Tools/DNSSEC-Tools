#ifndef VAL_POLICY_H
#define VAL_POLICY_H

#include "val_parse.h"

#define CONF_COMMENT '#'
#define CONF_END_STMT ';'
#define ZONE_COMMENT ';'
#define ZONE_END_STMT '\0'
#define LVL_DELIM ":"
#define MAX_LEVEL_IN_POLICY	5
#define TOKEN_MAX 2048
#define MAX_LINE_SIZE 2048
#define DEFAULT_ZONE	"."

#define OVERRIDE_POLICY(ctx, override)   do {\
    struct policy_list *c;\
    if ((ctx) && override) {\
        (ctx)->cur_override = override;\
        for (c = override->plist; c; c = c->next){\
            if ((ctx)->e_pol[c->index])\
                val_log(ctx, LOG_WARNING,\
                        "Duplicate policy definition for [%s%s] ; using latest", \
                        override->label, conf_elem_array[c->index].keyword);\
            (ctx)->e_pol[c->index] = c->pol;\
        }\
    }\
} while (0)

#define POL_TRUST_ANCHOR_STR "trust-anchor"
#define POL_PREFERRED_SEP_STR "preferred-sep"
#define POL_MUST_VERIFY_COUNT_STR "must-verify-count"
#define POL_PREFERRED_ALGORITHM_DATA_STR "preferred-algo-data"
#define POL_PREFERRED_ALGORITHM_KEYS_STR "preferred-algo-keys"
#define POL_PREFERRED_ALGORITHM_DS_STR "preferred-algo-ds"
#define POL_CLOCK_SKEW_STR "clock-skew"
#define POL_EXPIRED_SIGS_STR "expired-sigs"
#define POL_USE_TCP_STR "use-tcp"
#define POL_ZONE_SE_STR "zone-security-expectation"
#ifdef DLV
#define POL_DLV_TRUST_POINTS_STR  "dlv-trust-points"
#define POL_DLV_MAX_LINKS_STR "dlv-max-links"
#endif
#ifdef LIBVAL_NSEC3
#define POL_NSEC3_MAX_ITER_STR "nsec3-max-iter"
#endif

#define P_TRUST_ANCHOR              0
#define P_PREFERRED_SEP             1
#define P_MUST_VERIFY_COUNT         2
#define P_PREFERRED_ALGORITHM_DATA  3
#define P_PREFERRED_ALGORITHM_KEYS  4
#define P_PREFERRED_ALGORITHM_DS    5
#define P_CLOCK_SKEW                6
#define P_EXPIRED_SIGS              7
#define P_USE_TCP                   8
#define P_ZONE_SECURITY_EXPECTATION 9
#define MAX_POL_TOKEN               10
#ifdef LIBVAL_NSEC3
#define P_NSEC3_MAX_ITER            MAX_POL_TOKEN 
#undef  MAX_POL_TOKEN
#define MAX_POL_TOKEN               P_NSEC3_MAX_ITER+1 
#endif
#ifdef DLV
#define P_DLV_TRUST_POINTS          MAX_POL_TOKEN 
#define P_DLV_MAX_VALIDATION_LINKS  MAX_POL_TOKEN+1 
#undef  MAX_POL_TOKEN
#define MAX_POL_TOKEN               P_DLV_MAX_VALIDATION_LINKS+1 
#endif

#define ZONE_SE_IGNORE_MSG     "ignore"
#define ZONE_SE_TRUSTED_MSG    "trusted"
#define ZONE_SE_DO_VAL_MSG     "validate"
#define ZONE_SE_UNTRUSTED_MSG  "untrusted"
#define ZONE_SE_IGNORE 1
#define ZONE_SE_TRUSTED 2
#define ZONE_SE_DO_VAL 3
#define ZONE_SE_UNTRUSTED 4

#define RETRIEVE_POLICY(ctx, index, type)      \
    (ctx == NULL) ? NULL :                                              \
    (!ctx->e_pol[index])? NULL:(type)(ctx->e_pol[index])

char           *resolver_config_get(void);
int             resolver_config_set(const char *name);

char           *root_hints_get(void);
int             root_hints_set(const char *name);

char           *dnsval_conf_get(void);
int             dnsval_conf_set(const char *name);


int             read_root_hints_file(val_context_t * ctx);
int             read_res_config_file(val_context_t * ctx);
int             read_val_config_file(val_context_t * ctx, char *scope);
void            destroy_valpol(val_context_t * ctx);
void            destroy_respol(val_context_t * ctx);
struct hosts   *parse_etc_hosts(const char *name);

int             parse_trust_anchor(FILE *, policy_entry_t *, int *);
int             free_trust_anchor(policy_entry_t *);
int             parse_preferred_sep(FILE *, policy_entry_t *, int *);
int             free_preferred_sep(policy_entry_t *);
int             parse_must_verify_count(FILE *, policy_entry_t *, int *);
int             free_must_verify_count(policy_entry_t *);
int             parse_preferred_algo_data(FILE *, policy_entry_t *, int *);
int             free_preferred_algo_data(policy_entry_t *);
int             parse_preferred_algo_keys(FILE *, policy_entry_t *, int *);
int             free_preferred_algo_keys(policy_entry_t *);
int             parse_preferred_algo_ds(FILE *, policy_entry_t *, int *);
int             free_preferred_algo_ds(policy_entry_t *);
int             parse_clock_skew(FILE *, policy_entry_t *, int *);
int             free_clock_skew(policy_entry_t *);
int             parse_expired_sigs(FILE *, policy_entry_t *, int *);
int             free_expired_sigs(policy_entry_t *);
int             parse_use_tcp(FILE *, policy_entry_t *, int *);
int             free_use_tcp(policy_entry_t *);
int             parse_zone_security_expectation(FILE *, policy_entry_t *,
                                                int *);
int             free_zone_security_expectation(policy_entry_t *);
#ifdef LIBVAL_NSEC3
int             parse_nsec3_max_iter(FILE * fp, policy_entry_t * pol_entry,
                                     int *line_number);
int             free_nsec3_max_iter(policy_entry_t * pol_entry);
#endif
#ifdef DLV
int             parse_dlv_trust_points(FILE *, policy_entry_t *, int *);
int             free_dlv_trust_points(policy_entry_t *);
int             parse_dlv_max_links(FILE *, policy_entry_t *, int *);
int             free_dlv_max_links(policy_entry_t *);
#endif
int             check_relevance(char *label, char *scope, int *label_count,
                                int *relevant);

/*
 * fragment of the configuration file containing 
 * one policy chunk
 */
struct policy_fragment {
    char           *label;
    int             label_count;
    int             index;
    policy_entry_t  pol;
};

struct policy_conf_element {
    const char     *keyword;
    int             (*parse) (FILE *, policy_entry_t *, int *);
    int             (*free) (policy_entry_t *);
};

extern const struct policy_conf_element conf_elem_array[];

struct trust_anchor_policy {
    u_int8_t        zone_n[NS_MAXCDNAME];
    val_dnskey_rdata_t *publickey;
    struct trust_anchor_policy *next;
};

struct zone_se_policy {
    u_int8_t        zone_n[NS_MAXCDNAME];
    int             trusted;
    struct zone_se_policy *next;
};


#ifdef LIBVAL_NSEC3
struct nsec3_max_iter_policy {
    u_int8_t        zone_n[NS_MAXCDNAME];
    int             iter;
    struct nsec3_max_iter_policy *next;
};
#endif

#endif                          /* VAL_POLICY_H */
