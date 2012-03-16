#ifndef DNSSEC_CHECKS_H
#define DNSSEC_CHECKS_H

int check_outstanding_async();
void collect_async_query_select_info(fd_set *fds, int *numfds);

int check_basic_dns(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_basic_tcp(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_do_bit(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_ad_bit(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_do_has_rrsigs(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_small_edns0(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_can_get_nsec(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_can_get_nsec3(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_can_get_dnskey(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_can_get_ds(char *ns_name, char *buf, size_t buf_len, int *return_status);

/* async versions of the tests */
int check_basic_dns_async(char *ns_name, char *buf, size_t buf_len, int *return_status);

/* libval async test */
int check_basic_async(char *ns_name, char *buf, size_t buf_len, int *return_status);

#endif // DNSSEC_CHECKS_H
