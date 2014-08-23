#include "validator/validator-config.h"
#include <validator/validator.h>
#include <validator/resolver.h>

#define CHECK_SUCCEEDED 0
#define CHECK_FAILED    1

#define RETURN_ERROR_BUF(msg, buffer, buffer_len)          \
    do {                                                   \
        strncpy(buffer, msg, buffer_len-1);                \
        buffer[buffer_len-1] = '\0';                       \
        return CHECK_FAILED;                               \
    } while(0);

#define RETURN_SUCCESS_BUF(msg, buffer, buffer_len)          \
    do {                                                   \
        strncpy(buffer, msg, buffer_len-1);                \
        buffer[buffer_len-1] = '\0';                       \
        return CHECK_SUCCEEDED;                               \
    } while(0);

#define RETURN_ERROR(msg)                        \
    RETURN_ERROR_BUF(msg, buf, buf_len);

#define RETURN_SUCCESS(msg)                        \
    RETURN_ERROR_BUF(msg, buf, buf_len);

int check_small_edns0(char *ns_name, char *buf, size_t buf_len) {
    /* will fail because the response > 512 */

    int rc;
    struct name_server *ns;
    struct name_server *server;
    u_char *response;
    size_t len;

    ns = parse_name_server(ns_name, NULL, RES_USE_DNSSEC | RES_USE_EDNS0);
    if (!ns)
        RETURN_ERROR("query failed entirely");

    ns->ns_edns0_size = 512;

    rc = get("test.dnssec-tools.org", ns_t_dnskey, ns_c_in, ns,
             &server, &response, &len);

    printf("length: %d\n", len);
    print_response(response, len);

    free_name_server(&ns);
    return rc;
}

int check_do_bit(char *ns_name, char *buf, size_t buf_len) {
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
    int             rrnum;

    ns = parse_name_server(ns_name, NULL, RES_USE_DNSSEC | RES_USE_EDNS0);
    if (!ns)
        RETURN_ERROR("query failed entirely");

    rc = get("test.dnssec-tools.org", ns_t_dnskey, ns_c_in, ns,
             &server, &response, &len);

    if (rc != SR_UNSET)
        RETURN_ERROR("query failed entirely");

    if (ns_initparse(response, len, &handle) < 0)
        RETURN_ERROR("failed to init parser");

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
                RETURN_ERROR("failed to parse a returned additional RRSET");
            }
            break; /* out of data */
        }
        if (ns_rr_type(rr) == ns_t_opt) {
            u_int32_t       ttl = ns_rr_ttl(rr);
            /* u_int32_t     flags = ttl & 0xffff; */

            found_edns0 = 1;

            if ((ttl >> 16 & 0xff) != 0) {
                return CHECK_FAILED; /* EDNS version != 0 */
            }

            if ((ttl & RES_USE_DNSSEC) == RES_USE_DNSSEC)
                RETURN_ERROR("The EDNS0 flag failed to include the expected DO bit");

            /* edns0 size = int(ns_rr_class(rr)) */
            break;
        }
        rrnum++;
    }

    if (!found_edns0)
        RETURN_ERROR("No EDNS0 record found in the response.");

    /* check the answer records for the expected DO bit */
    rrnum = 0;
    for (;;) {
        if (ns_parserr(&handle, ns_s_an, rrnum, &rr)) {
            if (errno != ENODEV) {
                /* parse error */
                RETURN_ERROR("failed to parse a returned answer RRSET");
            }
            break; /* out of data */
        }

        if (ns_rr_type(rr) == ns_t_rrsig) {
            found_rrsig = 1;
            break;
        }
        rrnum++;
    }

    if (!found_rrsig)
        RETURN_ERROR("failed to find an expected RRSIG in a DNSSEC valid query");

    free_name_server(&ns);
    RETURN_SUCCESS("SUCCEEDED: Query with DO bit worked as expected");
}

int main(int argc, char *argv[]) {
    int rc;
    char *nameservertouse = "168.150.253.2";
    char buf[4096];

    if (argc == 2)
        nameservertouse = argv[1];
    
    memset(buf, 0, sizeof(buf));
    rc = check_small_edns0(nameservertouse, buf, sizeof(buf));
    printf("small_dns0: %d %s\n", rc, buf);

    memset(buf, 0, sizeof(buf));
    rc = check_do_bit(nameservertouse, buf, sizeof(buf));
    printf("do_bit:     %d %s\n", rc, buf);

    return 0;
}

    
