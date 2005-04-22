/*
 * Copyright 2005 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/nameser.h>

#include "resolver.h"
#include "res_transaction.h"
#include "res_errors.h"
#include "res_mkquery.h"
#include "support.h"

#define ENVELOPE	10
#define EMSG_MAX   2048


int res_sq_set_tsig_msg (char **error_msg, char *msg,
                            struct name_server *server, int error_code)
{
    char    name_h[DNAME_MAX];
                                                                                                                          
    if (wire_to_ascii_name (name_h, server->ns_name_n, DNAME_MAX)==-1)
        strcpy (name_h, "<unprintable>");
                                                                                                                          
    *error_msg = (char *) MALLOC (strlen(msg)+ 2 + strlen(name_h));
    if (*error_msg==NULL) return SR_MEMORY_ERROR;
    sprintf (*error_msg, "%s %s", msg, name_h);
    return error_code;
}


int right_sized (   u_int8_t    *response,
                    u_int32_t   response_length)
{
    HEADER      *header = (HEADER *) response;
    int         index = skip_questions (response);
    int         records = ntohs(header->ancount) + ntohs(header->nscount)
                    + ntohs(header->arcount);
    int         i;
    u_int16_t   rdata_len_n;
                                                                                                                          
    if (index > response_length) return TRUE;
                                                                                                                          
    for (i = 0; i < records; i++)
    {
        index += wire_name_length (&response[index])+ENVELOPE;
                                                                                                                          
        if (index > response_length) return TRUE;
                                                                                                                          
        memcpy(&rdata_len_n,&response[index-2],sizeof(u_int16_t));
        index += ntohs(rdata_len_n);
                                                                                                                          
        if (index > response_length) return TRUE;
    }
                                                                                                                          
    return index == response_length;
}

int theres_something_wrong_with_header (    u_int8_t    *response,
                                            u_int32_t   response_length,
                                            char        **error_msg)
{
    HEADER  *header = (HEADER *) response;
                                                                                                                          
    /* Check to see if this is supposed to be a real response */
                                                                                                                          
    if (header->qr == 1 && header->opcode != ns_o_query)
        return res_sq_set_message (error_msg,
                "Message is not a response to a query", SR_HEADER_ERROR);
                                                                                                                          
    /* Check the length and count of the records */
                                                                                                                          
    if (right_sized (response, response_length)==FALSE)
        return res_sq_set_message (error_msg,
            "Message size not consistent with record counts", SR_HEADER_ERROR);
                                                                                                                          
    /* Check the RCODE value */
                                                                                                                          
    /* RCODE of no error is always welcome */
                                                                                                                          
    if (header->rcode == ns_r_noerror)
        return SR_UNSET;
                                                                                                                          
    /*
        RCODE of NXDOMAIN (no such domain) is welcome in some circumtances:
            With no other records present
            With an SOA or NXT in the authority (ns) section
    */

    if (header->rcode == ns_r_nxdomain)
    {
        if (header->ancount==0 && header->nscount ==0 && header->arcount ==0)
            return SR_UNSET;
                                                                                                                          
        /*if (ntohs(header->nscount) > 1)*/
        {
            int             i;
            int             auth_index = skip_questions (response);
            u_int16_t       type_h;
            u_int16_t       rdata_len_n;
                                                                                                                          
            for (i = 0; i < ntohs(header->ancount); i++)
            {
                auth_index += wire_name_length (&response[auth_index])+ENVELOPE;
                memcpy(&rdata_len_n,&response[auth_index-2],sizeof(u_int16_t));
                auth_index += ntohs(rdata_len_n);
            }
                                                                                                                          
            for (i = 0; i < ntohs(header->nscount); i++)
            {
                type_h = retrieve_type (&response[auth_index]);
                                                                                                                          
                if (type_h == ns_t_soa || type_h == ns_t_nsec)
                    return SR_UNSET;
                                                                                                                          
                auth_index += wire_name_length (&response[auth_index])+ENVELOPE;
                memcpy(&rdata_len_n,&response[auth_index-2],sizeof(u_int16_t));
                auth_index += ntohs(rdata_len_n);
            }
        }
                                                                                                                          
        return res_sq_set_message (error_msg,
            "RCODE set to NXDOMAIN w/o appropriate records", SR_HEADER_ERROR);
    }

    switch (header->rcode)
    {
        case ns_r_formerr:
            return res_sq_set_message (error_msg,
                "RCODE set to FORMERR", SR_HEADER_ERROR);
                                                                                                                          
        case ns_r_servfail:
            return res_sq_set_message (error_msg,
                "RCODE set to SERVFAIL", SR_HEADER_ERROR);
                                                                                                                          
        case ns_r_notimpl:
            return res_sq_set_message (error_msg,
                "RCODE set to NOTIMPL", SR_HEADER_ERROR);
                                                                                                                          
        case ns_r_refused:
            return res_sq_set_message (error_msg,
                "RCODE set to REFUSED", SR_HEADER_ERROR);
                                                                                                                          
        default:
        {
            char    message[EMSG_MAX];
            sprintf (message, "RCODE set to 0x%x", header->rcode);
            return res_sq_set_message (error_msg,message,SR_HEADER_ERROR);
        }
    }
                                                                                                                          
    return SR_UNSET;
}



int get (	const char*			name,
			const u_int16_t		type_h,
			const u_int16_t		class_h,
			struct res_policy	*respol,
            struct name_server  **server,
			u_int8_t			**response,
			u_int32_t			*response_length,
            char                **error_msg)
{
	u_int8_t			query[12+MAXDNAME+4];
	int					query_limit = 12+MAXDNAME+4;
	int					query_length;
	int					ret_val;

	struct name_server *ns_list = NULL; 

	if (respol == NULL) 
		return res_sq_set_message(error_msg,
					"No reolver policy specified", SR_INTERNAL_ERROR);

	ns_list = respol->ns;

	/* Form the query with res_nmkquery_n */
	
	query_length = res_nmkquery (&_res, ns_o_query, name, class_h, type_h,
									NULL, 0, NULL, query, query_limit);
	_res.options |= RES_USE_DNSSEC;
    query_length = res_nopt(&_res, query_length, query, query_limit, EDNS_UDP_SIZE);	
	if (query_length == -1)
		return res_sq_set_message(error_msg,
					"Internal error in res_nmkquery_n", SR_INTERNAL_ERROR);
	/* Set the CD flag */
	((HEADER *)query)->cd = 1;
	//((HEADER *)query)->rd = 0;


printf ("-----------------------------------------------------------------------------\n");

/*
printf ("The Query:\n");
print_response (query, query_length);
*/
    /* Grab a response from the name server */
                                                                                                                          
    if ((ret_val = res_transaction (query, query_length, ns_list, response,
                                response_length, server)) != SR_TR_RESPONSE)
        switch (ret_val)
        {
            case SR_TR_MEMORY_ERROR:
                return SR_MEMORY_ERROR;
                                                                                                                          
            case SR_TR_NO_ANSWER:
            case SR_TR_IO_ERROR:
                return res_sq_set_message(error_msg, "Nothing received",
                                                    SR_NO_ANSWER);
            case SR_TR_TSIG_FAILURE:
                /* *server points to the failed server */
                return res_sq_set_tsig_msg (error_msg, "TSIG failed for",
                                                *server, SR_TSIG_ERROR);
            case SR_TR_CALL_ERROR:
            case SR_TR_TOO_BUSY:
            case SR_TR_INTERNAL_ERROR:
            default:
                return res_sq_set_message(error_msg,
                    "Internal error in res_transaction", SR_INTERNAL_ERROR);
        }
                                                                                                                          
printf ("The Response: ");
printf (":\n");
print_response (*response, *response_length);

    /* Check the header fields */
                                                                                                                          
    if ((ret_val = theres_something_wrong_with_header (*response,
                                    *response_length, error_msg))!=SR_UNSET)
        return ret_val;

    return ret_val;
}                                                                                                                          

