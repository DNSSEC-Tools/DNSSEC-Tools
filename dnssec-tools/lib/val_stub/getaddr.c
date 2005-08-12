/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * Author: Abhijit Hayatnagarkar
 *
 * A command-line tool for testing the val_getaddrinfo() function.
 */

#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "val_api.h"
#include "val_getaddrinfo.h"
#include "val_log.h"

static int validate = 0;

static void print_addrinfo(struct addrinfo* ainfo)
{
	struct sockaddr_in  *s_inaddr = NULL;
	struct sockaddr_in6 *s_in6addr = NULL;
	struct addrinfo *a = ainfo;
	char buf[INET6_ADDRSTRLEN];

	while (a != NULL) {
		printf("{\n");
		printf("\tFlags:     %d [", a->ai_flags);
		if (a->ai_flags & AI_PASSIVE) printf("AI_PASSIVE ");
		if (a->ai_flags & AI_CANONNAME) printf("AI_CANONNAME ");
		if (a->ai_flags & AI_NUMERICHOST) printf("AI_NUMERICHOST ");
		if (a->ai_flags & AI_V4MAPPED) printf("AI_V4MAPPED ");
		if (a->ai_flags & AI_ALL) printf("AI_ALL ");
		if (a->ai_flags & AI_ADDRCONFIG) printf("AI_ADDRCONFIG ");
		if (a->ai_flags & AI_NUMERICSERV) printf("AI_NUMERICSERV ");
		printf("]\n");
		printf("\tFamily:    %d [%s]\n", a->ai_family,
		       (a->ai_family == AF_UNSPEC)? "AF_UNSPEC":
		       (a->ai_family == AF_INET)? "AF_INET":
		       (a->ai_family == AF_INET6)? "AF_INET6":
		       "Unknown");
		printf("\tSockType:  %d [%s]\n", a->ai_socktype,
		       (a->ai_socktype == SOCK_STREAM)? "SOCK_STREAM":
		       (a->ai_socktype == SOCK_DGRAM)? "SOCK_DGRAM":
		       (a->ai_socktype == SOCK_RAW)? "SOCK_RAW":
		       "Unknown");
		printf("\tProtocol:  %d [%s]\n", a->ai_protocol,
		       (a->ai_protocol == IPPROTO_IP)? "IPPROTO_IP":
		       (a->ai_protocol == IPPROTO_TCP)? "IPPROTO_TCP":
		       (a->ai_protocol == IPPROTO_UDP)? "IPPROTO_UDP":
		       "Unknown");
		printf("\tAddrLen:   %d\n", a->ai_addrlen);

		if (a->ai_addr != NULL) {
			printf("\tAddrPtr:   %d\n", a->ai_addr);
			if (a->ai_family == AF_INET) {
				s_inaddr = (struct sockaddr_in *) (a->ai_addr);
				printf("\tAddr:      %s\n",
				       inet_ntop(AF_INET,
						 &(s_inaddr->sin_addr),
						 buf, INET6_ADDRSTRLEN));
			}
			else if (a->ai_family == AF_INET6) {
				s_in6addr= (struct sockaddr_in6 *)(a->ai_addr);
				printf("\tAddr:      %s\n",
				       inet_ntop(AF_INET6,
						 &(s_in6addr->sin6_addr),
						 buf, INET6_ADDRSTRLEN));
			}
			else
				printf("\tAddr:      Cannot parse address. Unknown protocol family\n");
		}
		else
			printf("\tAddr:      (null)\n");

		if (a->ai_canonname)
			printf("\tCanonName: %s\n", a->ai_canonname);
		else
			printf("\tCanonName: (null)\n");

		if (validate) {
			printf("\tDNSSEC status: %s\n", p_val_error(val_get_addrinfo_dnssec_status(a)));
		}
		printf("}\n");

		a = a->ai_next;
	}
}

int main(int argc, char *argv[])
{
	char *node = NULL;
	char *service = NULL;
	struct addrinfo hints;
	struct addrinfo *ainfo = NULL;
	int retval;
	int index = 0;
	int getcanonname = 0;

	if (argc < 2) {
		printf ("Usage: %s [-v] [-c] <hostname|IPv4 address|IPv6 address> [Port]\n", argv[0]);
		exit(1);
	}

	index = 1;
	if (strcasecmp(argv[index], "-v") == 0) {
		validate = 1;
		index++;
	}

	if (strcasecmp(argv[index], "-c") == 0) {
		getcanonname = 1;
		index++;
	}

	if (strcasecmp(argv[index], "NULL")) {
		node = argv[index];
	}

	index++;

	if (argc > index) {
		service = argv[index];
	}

	bzero(&hints, sizeof(struct addrinfo));
	if (getcanonname) {
		hints.ai_flags |= AI_CANONNAME;
	}
	if (validate) {
		retval = val_getaddrinfo(node, service, &hints, &ainfo);
		// retval = val_getaddrinfo(node, service, NULL, &ainfo);
	}
	else {
		retval = getaddrinfo(node, service, &hints, &ainfo);
	}
	
	if (retval != 0) {
		printf("Error in val_getaddrinfo(): %s\n", gai_strerror(retval));
		exit(1);
	}
	else {
		print_addrinfo(ainfo);
	}

	/* cleanup */
	freeaddrinfo(ainfo);
}
