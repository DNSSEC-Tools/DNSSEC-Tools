/*
 * Copyright 2004 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

#include <stdio.h>

#include "validator.h"

int main(int argc, char**argv) {

  if (argc < 2) {
    printf("Usage: %s <domain-name>", argv[0]);
    exit(1);
  }
  else {
    printf("DNSSEC Validating for domain %s\n", argv[1]);
    if (dnssec_validate (argv[1])) {
      printf("DNSSEC Validation successful\n");
    }
    else {
      printf("DNSSEC Validation failed\n");
    }
  }
}
