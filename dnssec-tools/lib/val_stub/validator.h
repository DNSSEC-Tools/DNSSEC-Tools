#ifndef VALIDATOR_H
#define VALIDATOR_H

typedef struct val_context {
	struct rrset_rec    *learned_zones;
	struct rrset_rec    *learned_keys;
	struct rrset_rec    *learned_ds	;
} val_context_t;

#endif /* VALIDATOR_H */
