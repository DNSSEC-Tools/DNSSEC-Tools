#include "validator-config.h"
#include <validator/validator.h>
#include <validator/resolver.h>

#include <dlfcn.h>

#ifdef __linux__
#define getprogname() program_invocation_short_name 
#endif

typedef struct val_context ValContext;

static ValContext *libval_shim_ctx = NULL;

static int
libval_shim_context(void)
{
  if (libval_shim_ctx == NULL) {
      if (val_create_context(NULL, &libval_shim_ctx) != VAL_NO_ERROR)
	return -1;
  }
  return 0;
}

static int 
libval_shim_init(void)
{

  return (libval_shim_context());
}


struct hostent *
gethostbyname(const char *name)
{
  val_status_t          val_status;
  struct hostent *      res;

  if (libval_shim_init())
    return NULL;

  val_log(NULL, LOG_DEBUG, "libval_shim: gethostbyname(%s) called: wrapper\n", name);
  
  res = val_gethostbyname(libval_shim_ctx, name, &val_status);

  if (val_istrusted(val_status) && !val_does_not_exist(val_status)) {
      return res;
  }

  return (NULL); 
}


#ifdef R_FUNCS_RETURN_STRUCT
struct hostent *
gethostbyname_r(const char * name,struct hostent * result_buf, char * buf, 
		int buflen, int * h_errnop)
{
  val_status_t          val_status;
  int                   ret;
  struct hostent *result = NULL;
  
  if (libval_shim_init())
      return NULL;

  val_log(NULL, LOG_DEBUG, "libval_shim: gethostbyname_r(%s) called: wrapper\n", name);

  ret = 
    val_gethostbyname_r(libval_shim_ctx, name, result_buf, buf, buflen, 
			&result, h_errnop,
			&val_status);

  if (val_istrusted(val_status) && !val_does_not_exist(val_status)) {
      return result;
  }

  return (NULL); 
}
#endif
#ifndef R_FUNCS_RETURN_STRUCT
int
gethostbyname_r(__const char * name,struct hostent * result_buf, char * buf, 
                size_t buflen, struct hostent ** result, int * h_errnop)
{
  val_status_t          val_status;
  int                   ret;

  if (libval_shim_init())
    return NO_RECOVERY;

  val_log(NULL, LOG_DEBUG, "libval_shim: gethostbyname_r(%s) called: wrapper\n", name);

  ret = 
    val_gethostbyname_r(libval_shim_ctx, name, result_buf, buf, buflen, 
			result, h_errnop,
			&val_status);

  if (val_istrusted(val_status) && !val_does_not_exist(val_status)) {
      return ret;
  }

  return (HOST_NOT_FOUND); 
}
#endif

struct hostent *
#if    defined(GETHOSTBYADDR_USES_CHAR_INT)
gethostbyaddr(const char *addr, int len, int type)
#elif  defined(GETHOSTBYADDR_USES_VOID_SOCKLEN)
gethostbyaddr(const void *addr, socklen_t len, int type)
#elif  defined(GETHOSTBYADDR_USES_VOID_INT)
gethostbyaddr(const void *addr, int len, int type)
#else
/* GUESSSSSS */
gethostbyaddr(const char *addr, socklen_t len, int type)
#endif
{
  if (libval_shim_init())
    return NULL;

  val_log(NULL, LOG_DEBUG, "libval_shim: gethostbyaddr called: not-available\n");

  return NULL;
}


struct hostent *
gethostbyname2(__const char *__name, int __af)
{
  if (libval_shim_init())
    return NULL;

  val_log(NULL, LOG_DEBUG, "libval_shim: gethostbyname2 called: not-available\n");

  return NULL;
}



int
gethostbyname2_r(__const char * name, int af, struct hostent * result_buf,
		 char * buf, size_t buflen, struct hostent ** result, 
		 int * h_errnop)
{
  if (libval_shim_init())
    return EAI_FAIL;

  val_log(NULL, LOG_DEBUG, "libval_shim: gethostbyname2_r called: not-available\n");

  return EAI_FAIL;
}



int
getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
	    struct addrinfo **res)
{
  val_status_t          val_status;
  int                   ret;

  if (libval_shim_init())
    return EAI_FAIL;

  val_log(NULL, LOG_DEBUG, "libval_shim: getaddrinfo(%s, %s) called: wrapper\n",
	  node, service);

  ret = val_getaddrinfo(libval_shim_ctx, node, service, hints, res, &val_status);

  if (val_istrusted(val_status) && !val_does_not_exist(val_status)) {
      return ret;
  }

  return (EAI_NONAME); 
}

#if    defined(GETNAMEINFO_USES_SOCKLEN_AND_UINT)
int
getnameinfo(const struct sockaddr * sa, socklen_t salen, char * host, 
	    socklen_t hostlen, char *serv, socklen_t servlen, 
	    unsigned int flags)
#elif  defined(GETNAMEINFO_USES_SOCKLEN_AND_INT)
int
getnameinfo(const struct sockaddr * sa, socklen_t salen, char * host, 
	    socklen_t hostlen, char *serv, socklen_t servlen, int flags)
#elif  defined(GETNAMEINFO_USES_SIZET_AND_INT)
int
getnameinfo(const struct sockaddr * sa, socklen_t salen, char * host, 
	    size_t hostlen, char *serv, size_t servlen, int flags)
#else
/* GUESSSSSS */
int
getnameinfo(const struct sockaddr * sa, socklen_t salen, char * host, 
	    socklen_t hostlen, char *serv, socklen_t servlen, 
	    unsigned int flags)
#endif
{
  val_status_t          val_status;
  char addrbuf[INET6_ADDRSTRLEN + 1];
  const char *addr;
  int ret;

  if (libval_shim_init())
    return EAI_FAIL;

  if (sa->sa_family == AF_INET) {
    addr = inet_ntop(AF_INET, &((const struct sockaddr_in*)sa)->sin_addr, 
                                addrbuf, sizeof(addrbuf)); 
  } else if (sa->sa_family == AF_INET6) {
    addr = inet_ntop(AF_INET6, &((const struct sockaddr_in6*)sa)->sin6_addr, 
                                addrbuf, sizeof(addrbuf)); 
  } else {
    return EAI_FAMILY;
  } 
  val_log(NULL, LOG_DEBUG, "libval_shim: getnameinfo(%s) called: wrapper\n", 
          addr);

  ret = val_getnameinfo(libval_shim_ctx, sa, salen, host, hostlen, 
			            serv, servlen, flags,
			            &val_status);

  val_log(NULL,LOG_DEBUG,"libval_shim: getnameinfo(%s) = (%s:%s) ret = %d\n",
	      addr, host, serv, ret);

  if (val_istrusted(val_status) && !val_does_not_exist(val_status)) {
      return ret;
  }

  return (EAI_NONAME); 
}



int
res_init(void)
{
  val_log(NULL, LOG_DEBUG, "libval_shim: res_init called: wrapper\n");

  return (libval_shim_init());
}



int
res_query(const char *dname, int class_h, int type_h, 
	  unsigned char *answer, int anslen)
{
  val_status_t          val_status;
  int ret;

  if (libval_shim_init())
    return -1;

  val_log(NULL, LOG_DEBUG, "libval_shim: res_query(%s,%d,%d) called: wrapper\n",
	  dname, class_h, type_h);

  ret = val_res_query(libval_shim_ctx, dname, class_h, type_h, answer, anslen,
			&val_status);

  if (val_istrusted(val_status) && !val_does_not_exist(val_status)) {
    return ret;
  }

  return (-1); 
}


int
res_querydomain(const char *name, const char *domain, int class_h, int type_h, 
		u_char * answer, int anslen)
{
  val_log(NULL, LOG_DEBUG, "libval_shim: res_querydomain called: not-available\n");

  return -1;
}


int
res_search(const char *dname, int class_h, int type_h, 
	   unsigned char *answer, int anslen)
{
  val_log(NULL, LOG_DEBUG, "libval_shim: res_search called: not-available\n");

  return -1;
}


int
res_send(const u_char * msg, int msglin, u_char *answer, int anslen)
{
  val_log(NULL, LOG_DEBUG, "libval_shim: res_send called: not-available\n");

  return -1;
}


struct hostent *
getipnodebyname(const char *name, int af, int flags, int *error_num)
{
  val_log(NULL,LOG_DEBUG,"libval_shim: getipnodebyname: called: not-available\n");

  return (struct hostent *)NULL;
}


struct hostent *
getipnodebyaddr(const void *addr, size_t len, int af, int *error_num)
{
  val_log(NULL,LOG_DEBUG,"libval_shim: getipnodebyaddr: called: not-available\n");

  return (struct hostent *)NULL;
}


/* int
getrrsetbyname(const char *hostname, unsigned int rdclass, unsigned int rdtype, unsigned int flags, struct rrsetinfo **res)
{
  // int (*lib_getrrsetbyname)(const char *hostname, unsigned int rdclass, unsigned int rdtype, unsigned int flags, struct rrsetinfo **res);
  // char *error;

  // lib_getrrsetbyname = dlsym(RTLD_NEXT, "getrrsetbyname");
  //
  // if ((error = dlerror()) != NULL) {
  //   val_log(NULL, LOG_DEBUG, "unable to load getrrsetbyname: %s\n", error);
  //   exit(1);
  // }

  val_log(NULL, LOG_DEBUG, "libval_shim: getrrsetbyname: called: not-avail\n");

  return (int)NULL;
}
*/

