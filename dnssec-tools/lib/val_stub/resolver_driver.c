#include <stdio.h>
#include <arpa/nameser.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <resolver.h>
#include <res_errors.h>
#include <support.h>

#include "val_support.h"
#include "res_squery.h"
#include "validator.h"
#include "val_x_query.h"
#include "val_log.h"


#define QUERY_NAME "dns.wesh.fruits.netsec.tislabs.com."
#define QUERY_TYPE ns_t_a
#define QUERY_CLASS ns_c_in

/*
#define QUERY_NAME "dns.wesh.fruits.netsec.tislabs.com."
#define QUERY_TYPE ns_t_a
#define QUERY_CLASS ns_c_in
*/

int main()
{

	char *name = QUERY_NAME;
	const u_int16_t type = QUERY_TYPE;
	const u_int16_t class = QUERY_CLASS;

	int ret_val;
	ret_val = val_x_query( NULL, name, type, class, 0, NULL, 0);

	return ret_val;
}
