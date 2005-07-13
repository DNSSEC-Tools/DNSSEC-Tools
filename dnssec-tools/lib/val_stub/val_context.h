/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef VAL_CONTEXT_H
#define VAL_CONTEXT_H

val_context_t *get_context(const char *label);
void destroy_context(val_context_t *context);

#endif
