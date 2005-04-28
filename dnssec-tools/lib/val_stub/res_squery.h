/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef RES_SQUERY_H
#define RES_SQUERY_H

#include "validator.h"

int res_squery ( 	val_context_t			*context,
					const char              *domain_name,
                    const u_int16_t         type,
                    const u_int16_t         class,
					struct res_policy 		*respol, 
					struct domain_info      *response);

#endif /* RES_SQUERY_H */
