#ifndef VAL_POLICY_H
#define VAL_POLICY_H

#define CONF_COMMENT "#"
#define ZONE_COMMENT ";"
#define ALL_COMMENTS ";#"
#define CONF_END_STMT ';'
#define ZONE_END_STMT '\0'
#define LVL_DELIM ":"
#define MAX_LEVEL_IN_POLICY	5
#define TOKEN_MAX 2048
#define MAX_LINE_SIZE 2048
#define DEFAULT_ZONE	"."
#define IPADDR_STRING_MAX 128

#define DNSKEY_STR "DNSKEY"
#define DS_STR "DS"

#define POL_GLOBAL_OPTIONS_STR "global-options"
#define POL_INCLUDE_STR "include"

#define P_TRUST_ANCHOR              0
#define P_CLOCK_SKEW                1
#define P_PROV_INSECURE             2
#define P_ZONE_SECURITY_EXPECTATION 3 
#define P_BASE_LAST                 P_ZONE_SECURITY_EXPECTATION

#ifdef LIBVAL_NSEC3
#define P_NSEC3_MAX_ITER            (P_BASE_LAST+1)
#define NSEC3_POL_COUNT             1
#else
#define NSEC3_POL_COUNT             0
#endif

#ifdef LIBVAL_DLV
#define P_DLV_TRUST_POINTS          (P_BASE_LAST+NSEC3_POL_COUNT+1) 
#define DLV_POL_COUNT               1
#else
#define DLV_POL_COUNT               0
#endif

#define MAX_POL_TOKEN               (P_BASE_LAST+NSEC3_POL_COUNT+DLV_POL_COUNT+1) 


#define ZONE_PU_TRUSTED 1
#define ZONE_PU_UNTRUSTED 2

#define ZONE_SE_IGNORE 1
#define ZONE_SE_DO_VAL 2
#define ZONE_SE_UNTRUSTED 3

#define RETRIEVE_POLICY(ctx, index, pol) do {\
    pol = (ctx == NULL) ? NULL :\
          (!ctx->e_pol[index])? NULL:(ctx->e_pol[index]);\
    /* check if policies are still the same */\
    if (pol) {\
        policy_entry_t *cur, *next, *prev;\
        struct timeval  tv;\
        /* Get current time */\
        gettimeofday(&tv, NULL);\
        /* Remove expired policies */\
        prev = NULL;\
        cur = pol;\
        while (cur) {\
            next = cur->next;\
            if (cur->exp_ttl > 0 &&\
                cur->exp_ttl <= tv.tv_sec) {\
                if (prev) {\
                    prev->next = next;\
                } else {\
                    pol = next;\
                }\
                cur->next = NULL;\
                free_policy_entry(cur, index);\
                cur = next;\
            } else {\
                prev = cur;\
                cur = cur->next;\
            }\
        }\
    }\
} while(0)
    
int             free_policy_entry(policy_entry_t *pol_entry, int index);
int             read_root_hints_file(val_context_t * ctx);
int             read_res_config_file(val_context_t * ctx);
int             read_val_config_file(val_context_t * ctx, const char *scope);
void            destroy_valpol(val_context_t * ctx);
void            destroy_respol(val_context_t * ctx);
struct hosts   *parse_etc_hosts(const char *name);

int             parse_trust_anchor(char **, char *, policy_entry_t *, int *, int *);
int             free_trust_anchor(policy_entry_t *);
int             parse_clock_skew(char **, char *, policy_entry_t *, int *, int *);
int             free_clock_skew(policy_entry_t *);
int             parse_prov_insecure_status(char **, char *, policy_entry_t *, int *, int *);
int             free_prov_insecure_status(policy_entry_t *);
int             parse_zone_security_expectation(char **, char *, policy_entry_t *, int *, int *);
int             free_zone_security_expectation(policy_entry_t *);
#ifdef LIBVAL_NSEC3
int             parse_nsec3_max_iter(char **, char *, policy_entry_t * pol_entry, int *line_number, int *);
int             free_nsec3_max_iter(policy_entry_t * pol_entry);
#endif
#ifdef LIBVAL_DLV
int             parse_dlv_trust_points(char **, char *, policy_entry_t *, int *, int *);
int             free_dlv_trust_points(policy_entry_t *);
#endif
int             check_relevance(const char *label, const char *scope,
                                int *label_count, int *relevant);
int             val_get_token(char **buf_ptr,
                              char *end_ptr,
                              int *line_number,
                              char *conf_token,
                              int conf_limit, int *endst, 
                              const char *comment_c, char endstmt_c,
                              int ignore_space);

/*
 * fragment of the configuration file containing 
 * one policy chunk
 */
struct policy_fragment {
    char           *label;
    int             label_count;
    int             index;
    policy_entry_t  *pol;
};

int
get_next_policy_fragment(char **buf_ptr, char *end_ptr, const char *scope,
                         struct policy_fragment **pol_frag,
                         int *line_number, int *g_opt_seen, 
                         int *include_seen);
int store_policy_overrides(struct policy_overrides **overrides,
                               struct policy_fragment **pfrag);
void destroy_valpolovr(struct policy_overrides **po);

int update_dynamic_gopt(val_global_opt_t **g_new, val_global_opt_t *g);

struct policy_conf_element {
    const char     *keyword;
    int             (*parse) (char **, char *, policy_entry_t *, int *, int *);
    int             (*free) (policy_entry_t *);
};

extern const struct policy_conf_element conf_elem_array[];

struct trust_anchor_policy {
    val_dnskey_rdata_t *publickey;
    val_ds_rdata_t *ds;
};

struct clock_skew_policy {
    int  clock_skew;
};

struct prov_insecure_policy {
    int             trusted;
};

struct zone_se_policy {
    int             trusted;
};


#ifdef LIBVAL_NSEC3
struct nsec3_max_iter_policy {
    int             iter;
};
#endif

#ifdef LIBVAL_DLV
struct dlv_policy {
    u_char *trust_point;
};
#endif

#endif                          /* VAL_POLICY_H */
