/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * This is the implementation file for the validator logger.
 */

#include "val_log.h"

int log_level = 0;

/* void val_log (FILE *fp, int level, const char *template, ...) */
void val_log (const char *template, ...)
{
       va_list ap;
     
       va_start (ap, template);
       if (log_level) {
	       vfprintf (stderr, template, ap);
       }
       va_end (ap);
}
