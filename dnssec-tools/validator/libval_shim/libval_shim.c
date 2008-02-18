#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>


#include <arpa/nameser.h>
#include <validator/resolver.h>
#include <validator/validator.h>

#ifdef __linux__
#define getprogname() program_invocation_short_name 
#endif

typedef struct val_context ValContext;

static ValContext *libval_shim_ctx = NULL;

static int libval_shim_log_set = 0;

static int 
libval_shim_log(void)
{
  char *shim_log = getenv("LIBVAL_SHIM_LOG");

  if (shim_log && strlen(shim_log) && !libval_shim_log_set) {
    libval_shim_log_set = 1;
    if (val_log_add_optarg(shim_log, 1) == NULL)
      return -1;
  }
  return 0;
}

static int
libval_shim_context(void)
{
  if (libval_shim_ctx == NULL) {
    char *shim_ctx_name = getenv("LIBVAL_SHIM_CONTEXT");
    
    if (shim_ctx_name == NULL || strlen(shim_ctx_name) == 0)
      shim_ctx_name = getprogname();

    if (val_create_context(shim_ctx_name, &libval_shim_ctx) != VAL_NO_ERROR)
      if (val_create_context(":", &libval_shim_ctx) != VAL_NO_ERROR)
	return -1;
  }
  return 0;
}

static int 
libval_shim_init(void)
{
  libval_shim_log();

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

  if (val_istrusted(val_status)) {
      return res;
  }

  return (NULL); 
}


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

  if (val_istrusted(val_status)) {
      return ret;
  }

  return (HOST_NOT_FOUND); 
}


struct hostent *
gethostbyaddr(__const void *addr, __socklen_t len, int type)
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
  struct val_addrinfo *	vainfo_ptr = NULL;
  val_status_t          val_status;
  int                   ret;

  if (libval_shim_init())
    return EAI_FAIL;

  val_log(NULL, LOG_DEBUG, "libval_shim: getaddrinfo(%s, %s) called: wrapper\n",
	  node, service);

  ret = val_getaddrinfo(libval_shim_ctx, node, service, hints, &vainfo_ptr, 
			&val_status);

  if (res) {
    *res = (struct addrinfo *)vainfo_ptr;
  }

  if (val_istrusted(val_status)) {
      return ret;
  }

  return (EAI_NONAME); 
}



void
freeaddrinfo(struct addrinfo *ai)
{
  val_log(NULL, LOG_DEBUG, "libval_shim: freeaddrinfo called: wrapper\n");

  val_freeaddrinfo((struct val_addrinfo *)ai);
}



int
getnameinfo(__const struct sockaddr * sa, socklen_t salen,char * host, 
	    socklen_t hostlen, char *serv, socklen_t servlen, 
	    unsigned int flags)
{
  val_status_t          val_status;
  char *addr;
  int ret;

  if (libval_shim_init())
    return EAI_FAIL;

  addr = inet_ntoa(((const struct sockaddr_in*)sa)->sin_addr);
  val_log(NULL, LOG_DEBUG, "libval_shim: getnameinfo(%s,%d) called: wrapper\n", 
	  addr, ntohs(((const struct sockaddr_in*)sa)->sin_port));

  ret = val_getnameinfo(libval_shim_ctx, sa, salen, host, hostlen, 
			serv, servlen, flags,
			&val_status);

  val_log(NULL,LOG_DEBUG,"libval_shim: getnameinfo(%s,%d) = (%s:%s) ret = %d\n",
	  addr, ntohs(((const struct sockaddr_in*)sa)->sin_port), host, serv, ret);

  if (val_istrusted(val_status)) {
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
res_query(const char *dname, int class, int type, 
	  unsigned char *answer, int anslen)
{
  val_status_t          val_status;
  int ret;

  if (libval_shim_init())
    return -1;

  val_log(NULL, LOG_DEBUG, "libval_shim: res_query(%s,%d,%d) called: wrapper\n",
	  dname, class, type);

  ret = val_res_query(libval_shim_ctx, dname, class, type, answer, anslen,
			&val_status);

  if (val_istrusted(val_status)) {
    return ret;
  }

  return (-1); 
}


int
res_querydomain(const char *name, const char *domain, int class, int type, 
		u_char * answer, int anslen)
{
  val_log(NULL, LOG_DEBUG, "libval_shim: res_querydomain called: not-available\n");

  return -1;
}


int
res_search(const char *dname, int class, int type, 
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

