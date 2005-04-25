/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * This is a header file for the validator logger.
 */

#ifndef VAL_LOG_H
#define VAL_LOG_H
#include <stdio.h>
#include <stdarg.h>

/* void val_log (FILE *fp, int level, const char *template, ...) */
void val_log (const char *template, ...);
#endif
