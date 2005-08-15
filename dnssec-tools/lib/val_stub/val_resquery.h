/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_RESQUERY_H
#define VAL_RESQUERY_H

#include "validator.h"

int val_resquery_send (	val_context_t           *context,
                        struct query_chain      *matched_q);
int val_resquery_rcv ( 	
					val_context_t *context,
					struct query_chain *matched_q,
					struct domain_info **response);

#endif /* VAL_RESQUERY_H */
