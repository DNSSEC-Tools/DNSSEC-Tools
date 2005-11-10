/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_CONTEXT_H
#define VAL_CONTEXT_H

int get_context(char *label, val_context_t **newcontext);
void destroy_context(val_context_t *context);
int switch_effective_policy(val_context_t *ctx, char *label);

#endif
