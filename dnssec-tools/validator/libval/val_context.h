/*
 * Copyright 2006 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_CONTEXT_H
#define VAL_CONTEXT_H

int val_create_context(char *label, val_context_t **newcontext);
void val_free_context(val_context_t *context);
int val_switch_policy_scope(val_context_t *ctx, char *label);

#endif
