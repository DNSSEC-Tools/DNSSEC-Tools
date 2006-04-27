
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

#include "resolver.h"
#include "res_mkquery.h"
#include "res_support.h"
#include "res_tsig.h"
#include "res_io_manager.h"

#include <arpa/nameser.h>
                                                                                                                             
#ifndef NULL
#define NULL (void*)0
#endif

#define ENVELOPE	10
#define EMSG_MAX   2048

static u_int16_t wire_name_length (const u_int8_t *field)
{
    /* Calculates the number of bytes in a DNS wire format name */
    u_short j;
    if (field==NULL) return 0;
                                                                                                                          
    for (j = 0; field[j]&&!(0xc0&field[j])&&j<NS_MAXDNAME ; j += field[j]+1);
    if (field[j]) j++;
    j++;
                                                                                                                          
    if (j > NS_MAXDNAME)
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
                                            u_int32_t   response_length)
{
    HEADER  *header = (HEADER *) response;
                                                                                                                          
    /* Check to see if this is supposed to be a real response */
                                                                                                                          
    if (header->qr == 1 && header->opcode != ns_o_query)
		return SR_WRONG_ANSWER;
                                                                                                                          
    /* Check the length and count of the records */
                                                                                                                          
    if (right_sized (response, response_length)==FALSE)
		return SR_HEADER_BADSIZE;

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
                                                                                                                          
        return SR_NXDOMAIN;
    }

    switch (header->rcode)
    {
        case ns_r_formerr:
			return SR_FORMERR;
                                                                                                                          
        case ns_r_servfail:
			return SR_SERVFAIL;
                                                                                                                          
        case ns_r_notimpl:
            return SR_NOTIMPL; 
                                                                                                                          
        case ns_r_refused:
			return SR_REFUSED;
                                                                                                                          
        default:
			return SR_GENERIC_FAILURE;
    }
                                                                                                                          
    return SR_UNSET;
}

int clone_ns(struct name_server **cloned_ns, struct name_server *ns)
{
	if (ns == NULL) {
		*cloned_ns = NULL;
		return SR_UNSET;
	}

	/* Create the structure for the name server */
    *cloned_ns = (struct name_server *)
						MALLOC(sizeof(struct name_server));
	if (*cloned_ns == NULL)
		return SR_MEMORY_ERROR;

	/* Make room for the name and insert the name */
	int name_len = wire_name_length (ns->ns_name_n);
	(*cloned_ns)->ns_name_n = 
		(u_int8_t *)MALLOC(name_len);
	if ((*cloned_ns)->ns_name_n==NULL)
		return SR_MEMORY_ERROR;
	memcpy ((*cloned_ns)->ns_name_n, ns->ns_name_n, name_len);

	/* Initialize the rest of the fields */
	(*cloned_ns)->ns_tsig_key = NULL; //XXX Still not doing anything with TSIG
	(*cloned_ns)->ns_security_options = ns->ns_security_options;
	(*cloned_ns)->ns_status = ns->ns_status;

	(*cloned_ns)->ns_options = ns->ns_options;
	(*cloned_ns)->ns_retrans = ns->ns_retrans;
	(*cloned_ns)->ns_retry = ns->ns_retry;

	(*cloned_ns)->ns_number_of_addresses = ns->ns_number_of_addresses;
	memcpy((*cloned_ns)->ns_address, ns->ns_address, sizeof(struct sockaddr));
	(*cloned_ns)->ns_next = NULL;

	return SR_UNSET;
}

int clone_ns_list(struct name_server **ns_list, struct name_server *orig_ns_list)
{
	struct name_server *ns, *tail_ns;
	int ret_val;

	*ns_list = NULL;
	for(ns = orig_ns_list; ns != NULL; ns = ns->ns_next) {

		struct name_server *temp_ns;
		if((ret_val = clone_ns(&temp_ns, ns)) != SR_UNSET)
			return ret_val;

		/* Add the name server record to the list */
		if (*ns_list == NULL)
			*ns_list = temp_ns;
		else
		{
			/* Preserving order in case of round robin */
			tail_ns = *ns_list;
			while (tail_ns->ns_next != NULL)
				tail_ns = tail_ns->ns_next;
			tail_ns->ns_next = temp_ns;
		}
	}
	return SR_UNSET;
}


int query_send( const char*     name,
            const u_int16_t     type_h,
            const u_int16_t     class_h,
            struct name_server  *pref_ns,
			int                 *trans_id)
{
	u_int8_t			query[12+NS_MAXDNAME+4];
	int					query_limit = 12+NS_MAXDNAME+4;
	int					query_length;
	int					ret_val;

	u_int8_t			*signed_query;
	int					signed_length;

	struct name_server *ns_list = NULL; 
	struct name_server *ns; 

	*trans_id = -1;

	if (pref_ns == NULL) 
		return SR_CALL_ERROR;


	/*res_io_stall();*/

	/* clone these and store to ns_list */
	if ((ret_val = clone_ns_list(&ns_list, pref_ns)) != SR_UNSET)
		return ret_val;

	/* Loop through the list of destinations */
	for (ns = ns_list; ns; ns = ns->ns_next)
	{
		/* Form the query with res_val_nmkquery_n */
		query_length = res_val_nmkquery (ns, ns_o_query, name, class_h, type_h,
										NULL, 0, NULL, query, query_limit);
   	 	query_length = res_val_nopt(ns, query_length, query, query_limit, EDNS_UDP_SIZE);	
		if (query_length == -1)
			return SR_MKQUERY_INTERNAL_ERROR;
		/* Set the CD flag */
		((HEADER *)query)->cd = 1;
		//((HEADER *)query)->rd = 0;

		if ((ret_val = res_tsig_sign(query,query_length,ns,
					&signed_query,&signed_length)) != SR_TS_OK)
		{
			if (ret_val == SR_TS_FAIL)
				continue;
			else /* SR_TS_CALL_ERROR */
			{
				res_io_cancel (trans_id);
    	        return SR_TSIG_INTERNAL_ERROR;
			}
		}

		if ((ret_val = res_io_deliver(trans_id, signed_query,
						signed_length, ns)) <= 0)
		{

			if (ret_val == 0) continue;

			res_io_cancel(trans_id);

			if (ret_val == SR_IO_MEMORY_ERROR)
				return SR_MEMORY_ERROR;

    	    return SR_SEND_INTERNAL_ERROR;
		}

	}

	return SR_UNSET;
}

int response_recv(int           *trans_id,
            struct name_server  **respondent,
			u_int8_t		    **answer,
			u_int32_t			*answer_length)
{
	int ret_val;

	/* Prepare the default response */
	*answer=NULL;
	*answer_length=0;
	*respondent=NULL;

	struct name_server *temp_ns = NULL;

	if ((ret_val=res_io_accept(*trans_id,answer,answer_length, &temp_ns))
			== SR_IO_NO_ANSWER_YET)
		return SR_NO_ANSWER_YET;

	if(temp_ns == NULL) {
		*respondent = NULL;
		return SR_NO_ANSWER;
	}

	if (clone_ns(respondent, temp_ns) != SR_UNSET)	
		return ret_val;
		
	res_io_cancel (trans_id);

	if (ret_val == SR_IO_INTERNAL_ERROR) 
        return SR_RCV_INTERNAL_ERROR;

	if ((ret_val == SR_IO_SOCKET_ERROR) ||
	   (ret_val == SR_IO_NO_ANSWER))
    	return SR_NO_ANSWER;

	/* ret_val is SR_IO_GOT_ANSWER */
	if ((ret_val = res_tsig_verifies (*respondent, *answer, *answer_length))==SR_TS_OK) {
    	/* Check the header fields */
    	if ((ret_val = theres_something_wrong_with_header (*answer,
                                    *answer_length))!=SR_UNSET)
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
    		return SR_TSIG_ERROR;
	else
            return SR_RCV_INTERNAL_ERROR;
}


int get (   const char*         name,
            const u_int16_t     type_h,
            const u_int16_t     class_h,
            struct name_server  *nslist,
            struct name_server  **server,
            u_int8_t            **response,
            u_int32_t           *response_length)
{
    int ret_val;
    int trans_id;
                                                                                                                             
    if (SR_UNSET == (ret_val = query_send(name, type_h, class_h, nslist, &trans_id))) {
        do {
            ret_val = response_recv(&trans_id, server, response, response_length);
        } while (ret_val == SR_NO_ANSWER_YET);
    }
                                                                                                                             
    return ret_val;
}

