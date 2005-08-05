/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_RESQUERY_H
#define VAL_RESQUERY_H

#include "validator.h"

int val_resquery ( 	val_context_t			*context,
					const char              *domain_name,
                    const u_int16_t         type,
                    const u_int16_t         class,
					struct res_policy 		*respol, 
					struct domain_info      *response);

#endif /* VAL_RESQUERY_H */
