#ifndef RES_ZONE_H
#define RES_ZONE_H

#define SR_ZI_STATUS_UNSET      0
#define SR_ZI_STATUS_PERMANENT      1
#define SR_ZI_STATUS_LEARNED        2

#include "validator.h"

int res_zi_unverified_ns_list(val_context_t *context, struct name_server **ns_list,
			u_int8_t *zone_name, struct res_policy *respol, 
			struct rrset_rec *unchecked_zone_info);

#endif /* RES_ZONE_H */
