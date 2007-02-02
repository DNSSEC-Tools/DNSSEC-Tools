/*
 * Copyright 2006 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_CONTEXT_H
#define VAL_CONTEXT_H

int             val_create_context_with_conf(char *label,
                                             char *dnsval_conf,
                                             char *resolv_conf,
                                             char *root_conf,
                                             val_context_t ** newcontext);
int             val_create_context(char *label,
                                   val_context_t ** newcontext);
void            val_free_context(val_context_t * context);
void            val_refresh_resolver_policy(val_context_t * context);
void            val_refresh_validator_policy(val_context_t * context);
void            val_refresh_root_hints(val_context_t * context);

#endif
