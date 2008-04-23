/*
 * Copyright 2007 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VALIDATOR_DRIVER_H
#define VALIDATOR_DRIVER_H

void print_val_response(struct val_response *resp);
int sendquery(val_context_t * context, const char *desc, u_char * name_n,
              const u_int16_t class, const u_int16_t type, u_int32_t flags,
              const int *result_ar, int trusted_only,
              struct val_response **resp);

int self_test(val_context_t *context, int tcs, int tce, u_int32_t flags,
              const char *tests, const char *suites, int doprint);



#endif /* VALIDATOR_DRIVER_H */
