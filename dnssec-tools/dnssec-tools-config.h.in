/* dnssec-tools-config.h.in.  Generated from configure.in by autoheader.  */

/* Define to 1 if you have the <arpa/nameser_compat.h> header file. */
#undef HAVE_ARPA_NAMESER_COMPAT_H

/* Define to 1 if you have the <arpa/nameser.h> header file. */
#undef HAVE_ARPA_NAMESER_H

/* Define to 1 if you have the declaration of `getopt_long', and to 0 if you
   don't. */
#undef HAVE_DECL_GETOPT_LONG

/* Define to 1 if you have the declaration of `getopt_long_only', and to 0 if
   you don't. */
#undef HAVE_DECL_GETOPT_LONG_ONLY

/* Define to 1 if you have the declaration of `ns_r_badsig', and to 0 if you
   don't. */
#undef HAVE_DECL_NS_R_BADSIG

/* Define to 1 if you have the declaration of `ns_t_kx', and to 0 if you
   don't. */
#undef HAVE_DECL_NS_T_KX

/* Define to 1 if you have the declaration of `p_rcode', and to 0 if you
   don't. */
#undef HAVE_DECL_P_RCODE

/* Define to 1 if you have the <dlfcn.h> header file. */
#undef HAVE_DLFCN_H

/* Define to 1 if you have the <getopt.h> header file. */
#undef HAVE_GETOPT_H

/* Define to 1 if the system has the type `int16_t'. */
#undef HAVE_INT16_T

/* Define to 1 if the system has the type `int32_t'. */
#undef HAVE_INT32_T

/* Define to 1 if the system has the type `int8_t'. */
#undef HAVE_INT8_T

/* Define to 1 if you have the <inttypes.h> header file. */
#undef HAVE_INTTYPES_H

/* Define to 1 if you have the `crypto' library (-lcrypto). */
#undef HAVE_LIBCRYPTO

/* Define to 1 if you have the <memory.h> header file. */
#undef HAVE_MEMORY_H

/* Define to 1 if you have the <netinet/in.h> header file. */
#undef HAVE_NETINET_IN_H

/* Define to 1 if the system has the type `ns_cert_types'. */
#undef HAVE_NS_CERT_TYPES

/* Define to 1 if you have the <openssl/bio.h> header file. */
#undef HAVE_OPENSSL_BIO_H

/* Define to 1 if you have the <openssl/evp.h> header file. */
#undef HAVE_OPENSSL_EVP_H

/* Define to 1 if you have the <stdint.h> header file. */
#undef HAVE_STDINT_H

/* Define to 1 if you have the <stdlib.h> header file. */
#undef HAVE_STDLIB_H

/* Define to 1 if you have the <strings.h> header file. */
#undef HAVE_STRINGS_H

/* Define to 1 if you have the <string.h> header file. */
#undef HAVE_STRING_H

/* Define to 1 if you have the <sys/filio.h> header file. */
#undef HAVE_SYS_FILIO_H

/* Define to 1 if you have the <sys/stat.h> header file. */
#undef HAVE_SYS_STAT_H

/* Define to 1 if you have the <sys/types.h> header file. */
#undef HAVE_SYS_TYPES_H

/* Define to 1 if the system has the type `uint16_t'. */
#undef HAVE_UINT16_T

/* Define to 1 if the system has the type `uint32_t'. */
#undef HAVE_UINT32_T

/* Define to 1 if the system has the type `uint8_t'. */
#undef HAVE_UINT8_T

/* Define to 1 if you have the <unistd.h> header file. */
#undef HAVE_UNISTD_H

/* Define to 1 if the system has the type `u_int16_t'. */
#undef HAVE_U_INT16_T

/* Define to 1 if the system has the type `u_int32_t'. */
#undef HAVE_U_INT32_T

/* Define to 1 if the system has the type `u_int8_t'. */
#undef HAVE_U_INT8_T

/* Define to the address where bug reports for this package should be sent. */
#undef PACKAGE_BUGREPORT

/* Define to the full name of this package. */
#undef PACKAGE_NAME

/* Define to the full name and version of this package. */
#undef PACKAGE_STRING

/* Define to the one symbol short name of this package. */
#undef PACKAGE_TARNAME

/* Define to the version of this package. */
#undef PACKAGE_VERSION

/* The size of a `int', as computed by sizeof. */
#undef SIZEOF_INT

/* The size of a `long', as computed by sizeof. */
#undef SIZEOF_LONG

/* The size of a `short', as computed by sizeof. */
#undef SIZEOF_SHORT

/* *s*printf() functions are char* */
#undef SPRINTF_CHAR

/* Define to 1 if you have the ANSI C header files. */
#undef STDC_HEADERS

/* Define if struct __ns_msg had _msg_ptr. */
#undef STRUCT___NS_MSG_HAS__MSG_PTR

/* Define if struct __ns_msg had _ptr. */
#undef STRUCT___NS_MSG_HAS__PTR


/*
 * FreeBSD is missing ns_t_kx, ns_t_cert, ns_t_a6, ns_t_dname, ns_t_sink, ns_t_tsig, ns_t_zxfr
 * for now, assume if the first is missing, the rest are too. If we hit system that has some
 * but not others, tweak accordingly.
 */
#if defined HAVE_DECL_NS_T_KX && !HAVE_DECL_NS_T_KX
#define ns_t_kx      36  /* Key Exchange */
#define ns_t_cert    37  /* Certification record */
#define ns_t_a6      38  /* IPv6 address (deprecates AAAA) */
#define ns_t_dname   39  /* Non-terminal DNAME (for IPv6) */
#define ns_t_sink    40  /* Kitchen sink (experimentatl) */
#define ns_t_tsig    250 /* Transaction signature. */
#define ns_t_zxfr    256 /* BIND-specific, nonstandard. */
#endif /* HAVE_NS_T_KX */

/*
 * FreeBSD is missing ns_r_badsig, ns_r_badkey, ns_r_badtime
 * for now, assume if the first is missing, the rest are too. If we hit system that has some
 * but not others, tweak accordingly.
 */
#if defined HAVE_DECL_NS_R_BADSIG && !HAVE_DECL_NS_R_BADSIG
#define ns_r_badsig      16
#define ns_r_badkey      17
#define ns_r_badtime     18
#endif /* HAVE_NS_R_BADSIG */



#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
/* define u_int32_t if not available */
#ifndef HAVE_U_INT32_T
#ifdef HAVE_UINT32_T
typedef uint32_t        u_int32_t;
#else
#ifdef INT32_T
typedef unsigned INT32_T u_int32_t;
#else
typedef unsigned int     u_int32_t;
#endif
#endif
#endif /* !HAVE_U_INT32_T */

/* define u_int16_t if not available */
#ifndef HAVE_U_INT16_T
#ifdef HAVE_UINT16_T
typedef uint16_t        u_int16_t;
#else
#ifdef INT16_T
typedef unsigned INT16_T u_int16_t;
#else
typedef unsigned short     u_int16_t;
#endif
#endif
#endif /* !HAVE_U_INT16_T */

/* define u_int8_t if not available */
#ifndef HAVE_U_INT8_T
#ifdef HAVE_UINT8_T
typedef uint8_t        u_int8_t;
#else
#ifdef INT8_T
typedef unsigned INT8_T u_int8_t;
#else
typedef unsigned short     u_int8_t;
#endif
#endif
#endif /* !HAVE_U_INT8_T */
