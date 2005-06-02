/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * This is the header file for a validating gethostbyname function.
 * Applications should be able to use this with minimal change.
 */

#ifndef VAL_GETHOSTBYNAME_H
#define VAL_GETHOSTBYNAME_H

#include <netdb.h>
#include "val_api.h"

struct hostent *val_gethostbyname ( const char *name, int *dnssec_status );
struct hostent *val_x_gethostbyname ( const char *name, int *dnssec_status );

#endif
