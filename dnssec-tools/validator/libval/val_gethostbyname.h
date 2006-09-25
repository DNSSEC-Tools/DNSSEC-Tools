/*
 * Copyright 2006 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */
#ifndef VAL_GETHOSTBYNAME_H
#define VAL_GETHOSTBYNAME_H

extern int      h_errno;
struct hostent *val_gethostbyname(const val_context_t * ctx,
                                  const char *name,
                                  val_status_t * val_status);

int             val_gethostbyname_r(const val_context_t * ctx,
                                    const char *name,
                                    struct hostent *ret,
                                    char *buf,
                                    size_t buflen,
                                    struct hostent **result,
                                    int *h_errnop,
                                    val_status_t * val_status);

struct hostent *val_gethostbyname2(const val_context_t * ctx,
                                   const char *name,
                                   int af, val_status_t * val_status);

int             val_gethostbyname2_r(const val_context_t * ctx,
                                     const char *name,
                                     int af,
                                     struct hostent *ret,
                                     char *buf,
                                     size_t buflen,
                                     struct hostent **result,
                                     int *h_errnop,
                                     val_status_t * val_status);

#endif
