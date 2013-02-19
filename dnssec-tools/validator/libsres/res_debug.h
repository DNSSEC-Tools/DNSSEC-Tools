#ifndef _RES_DEBUG_H_
#define _RES_DEBUG_H_

/*
 * some system prototypes don't match up
 */
#ifdef sun
#define P_OPTION_ARG_TYPE uint_t
#define P_SECSTODATE_ARG_TYPE  uint_t
#else
#define P_OPTION_ARG_TYPE u_long
#define P_SECSTODATE_ARG_TYPE  u_long
#endif

#if defined(__OpenBSD__)
int
dn_count_labels(char *name);
#else
int
dn_count_labels(const char *name);
#endif

const char     *
loc_ntoa(const u_char *binary, char *ascii);

char           *
p_secstodate(P_SECSTODATE_ARG_TYPE secs);

#endif
