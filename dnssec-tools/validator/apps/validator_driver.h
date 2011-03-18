/*
 * Copyright 2007-2011 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VALIDATOR_DRIVER_H
#define VALIDATOR_DRIVER_H

void print_val_response(struct val_response *resp);
int sendquery(val_context_t * context, const char *desc, char * name,
              int class, int type, u_int32_t flags,
              const int *result_ar, int trusted_only,
              struct val_response *resp);

int self_test(val_context_t *context, int tcs, int tce, u_int32_t flags,
              const char *tests, const char *suites, int doprint,
              int max_in_flight);



#endif /* VALIDATOR_DRIVER_H */
