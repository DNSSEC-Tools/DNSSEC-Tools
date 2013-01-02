/*
 * Copyright 2007-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VALIDATOR_DRIVER_H
#define VALIDATOR_DRIVER_H

#define MAX_TEST_RESULTS 10

void print_val_response(struct val_response *resp);
int sendquery(val_context_t * context, const char *desc, char * name,
              int class_h, int type_h, u_int32_t flags,
              const int *result_ar, int trusted_only,
              struct val_response *resp);

int self_test(val_context_t *context, int tcs, int tce, u_int32_t flags,
              const char *tests, const char *suites, int doprint,
              int max_in_flight);

int check_results(val_context_t * context, const char *desc, char * name,
                  const u_int16_t class_h, const u_int16_t type_h,
                  const int *result_ar, struct val_result_chain *results,
                  int trusted_only, struct timeval *start);


#endif /* VALIDATOR_DRIVER_H */
