#ifndef DNSSEC_CHECKS_H
#define DNSSEC_CHECKS_H

#ifdef __MINGW32__
#include <winsock2.h>
#endif

#define CHECK_QUEUED    -2
#define CHECK_CRITICAL  -1
#define CHECK_SUCCEEDED 0
#define CHECK_FAILED    1
#define CHECK_WARNING   2

int async_requests_remaining();
void async_cancel_outstanding();
void check_outstanding_async();
void check_queued_sends();
void collect_async_query_select_info(fd_set *fds, int *numfds, fd_set *tcp_fds, int *numUdpFds);

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
int check_basic_tcp_async(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_can_get_nsec_async(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_can_get_nsec3_async(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_do_bit_async(char *ns_name, char *buf, size_t buf_len, int *testStatus);
int check_ad_bit_async(char *ns_name, char *buf, size_t buf_len, int *testStatus);
int check_do_has_rrsigs_async(char *ns_name, char *buf, size_t buf_len, int *return_status);
int check_small_edns0_async(char *ns_name, char *buf, size_t buf_len, int *testStatus);
int check_can_get_dnskey_async(char *ns_name, char *buf, size_t buf_len, int *testStatus);
int check_can_get_ds_async(char *ns_name, char *buf, size_t buf_len, int *testStatus);
int check_can_get_signed_dname_async(char *ns_name, char *buf, size_t buf_len, int *testStatus);

/* libval async test */
void check_basic_async(char *ns_name, char *buf, size_t buf_len, int *return_status);

#endif // DNSSEC_CHECKS_H
