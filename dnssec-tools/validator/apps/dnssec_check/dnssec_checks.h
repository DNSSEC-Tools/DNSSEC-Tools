#ifndef DNSSEC_CHECKS_H
#define DNSSEC_CHECKS_H

int check_basic_dns(char *ns_name, char *buf, size_t buf_len);
int check_do_bit(char *ns_name, char *buf, size_t buf_len);
int check_do_has_rrsigs(char *ns_name, char *buf, size_t buf_len);
int check_small_edns0(char *ns_name, char *buf, size_t buf_len);
int check_can_get_nsec(char *ns_name, char *buf, size_t buf_len);
int check_can_get_nsec3(char *ns_name, char *buf, size_t buf_len);
int check_can_get_dnskey(char *ns_name, char *buf, size_t buf_len);
int check_can_get_ds(char *ns_name, char *buf, size_t buf_len);

#endif // DNSSEC_CHECKS_H
