#ifndef VAL_POLICY_H
#define VAL_POLICY_H

#include "val_parse.h"

#define COMMENT '#'
#define LVL_DELIM ":"
#define END_STMT ';'
#define MAX_LEVEL_IN_POLICY	5
#define TOKEN_MAX 2048
#define DEFAULT_ZONE	"."
#define NS_PORT	53

#define OVERRIDE_POLICY(ctx, override)   do {		\
	struct policy_list *c;							\
	if (ctx && override) {							\
		ctx->cur_override = override;				\
		for (c = override->plist; c; c = c->next)	\
			ctx->e_pol[c->index] = c->pol;			\
	}												\
} while (0)

int read_res_config_file(val_context_t *ctx);
int read_val_config_file(val_context_t *ctx, const char *scope);
void destroy_valpol(val_context_t *ctx);
void destroy_respol(val_context_t *ctx);
int switch_effective_policy(val_context_t *ctx, const char *label);

int parse_trust_anchor(FILE*, policy_entry_t*, int*);
int free_trust_anchor(policy_entry_t*);
int parse_preferred_sep(FILE*, policy_entry_t*, int*);
int free_preferred_sep(policy_entry_t*);
int parse_not_preferred_sep(FILE*, policy_entry_t*, int*);
int free_not_preferred_sep(policy_entry_t*);
int parse_must_verify_count(FILE*, policy_entry_t*, int*);
int free_must_verify_count(policy_entry_t*);
int parse_preferred_algo_data(FILE*, policy_entry_t*, int*);
int free_preferred_algo_data(policy_entry_t*);
int parse_not_preferred_algo_data(FILE*, policy_entry_t*, int*);
int free_not_preferred_algo_data(policy_entry_t*);
int parse_preferred_algo_keys(FILE*, policy_entry_t*, int*);
int free_preferred_algo_keys(policy_entry_t*);
int parse_not_preferred_algo_keys(FILE*, policy_entry_t*, int*);
int free_not_preferred_algo_keys(policy_entry_t*);
int parse_preferred_algo_ds(FILE*, policy_entry_t*, int*);
int free_preferred_algo_ds(policy_entry_t*);
int parse_not_preferred_algo_ds(FILE*, policy_entry_t*, int*);
int free_not_preferred_algo_ds(policy_entry_t*);
int parse_clock_skew(FILE*, policy_entry_t*, int*);
int free_clock_skew(policy_entry_t*);
int parse_expired_sigs(FILE*, policy_entry_t*, int*);
int free_expired_sigs(policy_entry_t*);
int parse_use_tcp(FILE*, policy_entry_t*, int*);
int free_use_tcp(policy_entry_t*);
#ifdef DLV
int parse_dlv_trust_points(FILE*, policy_entry_t*, int*);
int free_dlv_trust_points(policy_entry_t*);
int parse_dlv_max_links(FILE*, policy_entry_t*, int*);
int free_dlv_max_links(policy_entry_t*);
#endif

/*
 * fragment of the configuration file containing 
 * one policy chunk
 */
struct policy_fragment {
	char *label;
	int label_count;
	int index;
	policy_entry_t pol;
};

struct policy_conf_element {
	char *keyword;
	int (*parse)(FILE*, policy_entry_t*, int*);
	int (*free)(policy_entry_t*);
};

struct trust_anchor_policy {
	u_int8_t zone_n[MAXCDNAME];
	val_dnskey_rdata_t *publickey;
	struct trust_anchor_policy *next;
}; 

#endif /* VAL_POLICY_H */ 
