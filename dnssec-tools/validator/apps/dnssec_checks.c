#include <stdio.h>
#include <errno.h>

#include "validator-config.h"
#include "validator/resolver.h"
#include "resolv.h"

#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#elif ! defined( HAVE_ARPA_NAMESER_H )
#include "arpa/header.h"
#endif

#define CHECK_SUCCEEDED 0
#define CHECK_FAILED    1

int check_small_edns0(char *ns_name) {
    /* will fail because the response > 512 */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_edns0_size = 512;
    ns->ns_options |= RES_USE_DNSSEC | RES_USE_EDNS0;

    rc = get("test.dnssec-tools.org", ns_t_dnskey, ns_c_in, ns,
             &server, &response, &len);

    printf("length: %d\n", len);
    print_response(response, len);

    free_name_server(&ns);
    return rc;
}

int check_do_bit(char *ns_name) {
    /* queries with the DO bit and thus should return an answer with
       the DO bit as well.  It should additionall have at least one
       RRSIG record. */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;
    int found_edns0 = 0, found_rrsig = 0;

    ns_msg          handle;
    int             qdcount, ancount, nscount, arcount;
    u_int           opcode, rcode, id;
    ns_rr           rr;
    int             n, rrnum;

    ns = parse_name_server(ns_name, NULL);
    ns->ns_options |= RES_USE_DNSSEC | RES_USE_EDNS0;

    rc = get("test.dnssec-tools.org", ns_t_dnskey, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        return CHECK_FAILED;

    if (ns_initparse(response, len, &handle) < 0)
        return CHECK_FAILED;

    opcode = libsres_msg_getflag(handle, ns_f_opcode);
    rcode = libsres_msg_getflag(handle, ns_f_rcode);
    id = ns_msg_id(handle);
    qdcount = ns_msg_count(handle, ns_s_qd);
    ancount = ns_msg_count(handle, ns_s_an);
    nscount = ns_msg_count(handle, ns_s_ns);
    arcount = ns_msg_count(handle, ns_s_ar);
    
    /* check the answer records for at least one RRSIG */
    rrnum = 0;
    for (;;) {
        if (ns_parserr(&handle, ns_s_ar, rrnum, &rr)) {
            if (errno != ENODEV) {
                /* parse error */
                return CHECK_FAILED;
            }
            break; /* out of data */
        }
        if (ns_rr_type(rr) == ns_t_rrsig) {
            u_int32_t       ttl = ns_rr_ttl(rr);
            u_int32_t     flags = ttl & 0xffff;

            found_edns0 = 1;

            if ((ttl >> 16 & 0xff) != 0) {
                return CHECK_FAILED; /* EDNS version != 0 */
            }

            if ((flags & RES_USE_DNSSEC) == 0)
                return CHECK_FAILED; /* no do bit returned */
            printf("do bit returned\n");

            /* edns0 size = int(ns_rr_class(rr)) */
            break;
        }
        rrnum++;
    }

    if (!found_edns0)
        return CHECK_FAILED;

    /* check the additional records for the expected DO bit */
    rrnum = 0;
    for (;;) {
        if (ns_parserr(&handle, ns_s_an, rrnum, &rr)) {
            if (errno != ENODEV) {
                /* parse error */
                return CHECK_FAILED;
            }
            break; /* out of data */
        }

        if (ns_rr_type(rr) == ns_t_rrsig) {
            found_rrsig = 1;
            break;
        }
    }

    if (!found_rrsig)
        return CHECK_FAILED;

    free_name_server(&ns);
    return rc;
}

int main(int argc, char *argv[]) {
    int rc;
    char *nameservertouse = "168.150.253.2";

    if (argc == 2)
        nameservertouse = argv[1];
    
    rc = check_small_edns0(nameservertouse);
    printf("small_dns0: %d\n", rc);

    rc = check_do_bit(nameservertouse);
    printf("do_bit:     %d\n", rc);
}

    
