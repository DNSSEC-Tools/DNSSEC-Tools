
/*
 * Portions Copyright (c) 1995, 1996, 1997 by Trusted Information Systems, Inc.
 *
 * Permission to use, copy modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND TRUSTED INFORMATION SYSTEMS
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
 * TRUSTED INFORMATION SYSTEMS BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THE SOFTWARE.
 */
/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/nameser.h>

#include "resolver.h"
#include "res_mkquery.h"
#include "res_support.h"
#include "res_tsig.h"
#include "res_io_manager.h"
                                                                                                                             
#ifndef NULL
#define NULL (void*)0
#endif

#define ENVELOPE	10
#define EMSG_MAX   2048

static int res_sq_set_message(char **error_msg, char *msg, int error_code)
{
    *error_msg = (char *) MALLOC (strlen(msg)+1);
    if (*error_msg==NULL) return SR_MEMORY_ERROR;
    sprintf (*error_msg, "%s", msg);
    return error_code;
}

static int res_sq_set_tsig_msg (char **error_msg, char *msg,
                            struct name_server *server, int error_code)
{
    char    name_h[DNAME_MAX];
                                                                                                                          
    if ((server->ns_name_n == NULL) ||
		(wire_to_ascii_name (name_h, server->ns_name_n, DNAME_MAX)==-1))
        strcpy (name_h, "<unprintable>");
                                                                                                                          
    *error_msg = (char *) MALLOC (strlen(msg)+ 2 + strlen(name_h));
    if (*error_msg==NULL) return SR_MEMORY_ERROR;
    sprintf (*error_msg, "%s %s", msg, name_h);
    return error_code;
}

static u_int16_t wire_name_length (const u_int8_t *field)
{
    /* Calculates the number of bytes in a DNS wire format name */
    u_short j;
    if (field==NULL) return 0;
                                                                                                                          
    for (j = 0; field[j]&&!(0xc0&field[j])&&j<MAXDNAME ; j += field[j]+1);
    if (field[j]) j++;
    j++;
                                                                                                                          
    if (j > MAXDNAME)
        return 0;
    else
        return j;
}


static int skip_questions(const u_int8_t *buf)
{
    return 12 + wire_name_length (&buf[12]) + 4;
}

void dump_response (const u_int8_t *ans, int resplen)
{
    /* Prints the "raw" response from DNS */
    int i,j, k;
                                                                                                                          
    printf ("Message length is %d\n", resplen);
                                                                                                                          
    for (i = 0; i < 12; i++) printf ("%02x ", (u_char) ans[i]);
    printf ("\n");
    k = 12;
    while (ans[k]) k += ans[k] + 1;
    for (i = 12; i < k+1; i++) printf ("%02x ", (u_char) ans[i]);
    printf (": ");
    for (i = k+1; i < k+5; i++) printf ("%02x ", (u_char) ans[i]);
    printf ("\n");
    k += 5;
    if (k < resplen)
    do
    {
        j = wire_name_length(&ans[k]) + 10; /* j = envelope length */
        j += ntohs(*(u_short*)(&ans[k+j-2])); /* adds rdata length to j */
        for (i = k; i < k+j; i++) printf ("%02x ", (u_char) ans[i]);
        printf ("\n");
        k += j;
    } while (k < resplen);
}

u_int16_t retrieve_type (const u_int8_t *rr)
{
    u_int16_t   type_n;
    int         name_length = wire_name_length (rr);
                                                                                                                          
    memcpy (&type_n, &rr[name_length], sizeof(u_int16_t));
    return ntohs(type_n);
}

int res_quecmp (u_int8_t *query, u_int8_t *response)
{
	int	length;

	if (query==NULL || response==NULL) return 1;

	length = wire_name_length (&query[12]);

	if (length != wire_name_length(&response[12]) ) return 1;

	return (memcmp (&query[12], &response[12], length));
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


int query_send( const char*     name,
            const u_int16_t     type_h,
            const u_int16_t     class_h,
            struct name_server  *ns,
			int                 *trans_id,
            char                **error_msg)
{
	u_int8_t			query[12+MAXDNAME+4];
	int					query_limit = 12+MAXDNAME+4;
	int					query_length;
	int					ret_val;

	u_int8_t			*signed_query;
	int					signed_length;

	struct name_server *ns_list = NULL; 

	*trans_id = -1;

	if (ns == NULL) 
		return res_sq_set_message(error_msg,
					"No name servers specified", SR_INTERNAL_ERROR);


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

	/*res_io_stall();*/

	/* XXX clone those and store to ns_list */
	ns_list = ns;

	/* Loop through the list of destinations */
	for (ns = ns_list; ns; ns = ns->ns_next)
	{
		if ((ret_val = res_tsig_sign(query,query_length,ns,
					&signed_query,&signed_length)) != SR_TS_OK)
		{
			if (ret_val == SR_TS_FAIL)
				continue;
			else /* SR_TS_CALL_ERROR */
			{
				res_io_cancel (trans_id);
	               return res_sq_set_message(error_msg,
    	               "Internal error in query_send", SR_INTERNAL_ERROR);
			}
		}

		if ((ret_val = res_io_deliver(trans_id, signed_query,
						signed_length, ns)) <= 0)
		{

			if (ret_val == 0) continue;

			res_io_cancel(trans_id);

			if (ret_val == SR_IO_MEMORY_ERROR)
				return SR_MEMORY_ERROR;

	        return res_sq_set_message(error_msg,
        	       "Internal error in query_send", SR_INTERNAL_ERROR);
		}

	}

	return SR_UNSET;
}


int response_recv(int           *trans_id,
            struct name_server  **respondent,
			u_int8_t		    **answer,
			u_int32_t			*answer_length,
            char                **error_msg)
{
	int ret_val;

	/* Prepare the default response */
	*answer=NULL;
	*answer_length=0;
	*respondent=NULL;

	if ((ret_val=res_io_accept(*trans_id,answer,answer_length,respondent))
			== SR_NO_ANSWER_YET)
		return ret_val;
		
	res_io_cancel (trans_id);

	if (ret_val == SR_IO_INTERNAL_ERROR) 
    	return res_sq_set_message(error_msg,
    		"Internal error in response_recv", SR_INTERNAL_ERROR);

	if ((ret_val == SR_IO_SOCKET_ERROR) ||
	   (ret_val == SR_IO_NO_ANSWER))
    	return res_sq_set_message(error_msg, "Nothing received", SR_NO_ANSWER);

	/* ret_val is SR_IO_GOT_ANSWER */
	if ((ret_val = res_tsig_verifies (*respondent, *answer, *answer_length))==SR_TS_OK) {
    	/* Check the header fields */
    	if ((ret_val = theres_something_wrong_with_header (*answer,
                                    *answer_length, error_msg))!=SR_UNSET)
        	return ret_val;
/*
printf ("The Response: ");
printf (":\n");
print_response (*answer, *answer_length);
*/
		return SR_UNSET;
	}
	else if (ret_val == SR_TS_FAIL)
    	/* *server points to the failed server */
    		return res_sq_set_tsig_msg (error_msg, "TSIG failed for",
    			*respondent, SR_TSIG_ERROR);
	else
            return res_sq_set_message(error_msg,
                   "Internal error in response_recv", SR_INTERNAL_ERROR);
}


int get (   const char*         name,
            const u_int16_t     type_h,
            const u_int16_t     class_h,
            struct name_server  *nslist,
            struct name_server  **server,
            u_int8_t            **response,
            u_int32_t           *response_length,
            char                **error_msg)
{
    int ret_val;
    int trans_id;
                                                                                                                             
    if (SR_UNSET == (ret_val = query_send(name, type_h, class_h, nslist, &trans_id, error_msg))) {
        do {
            ret_val = response_recv(&trans_id, server, response, response_length, error_msg);
        } while (ret_val == SR_NO_ANSWER_YET);
    }
                                                                                                                             
    return ret_val;
}

