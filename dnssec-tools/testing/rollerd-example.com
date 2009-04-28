$ORIGIN com.
$TTL 1m
example     IN SOA dns.example.com. admin.example.com. (
                2009030100 ;SERIALNUM
                3h  ; Refresh
                30m  ; Retry
                1m  ; Expire
                1m) ; Minimum TTL

                IN   NS      dns.example.com.
		IN   A       192.0.2.1
		IN   AAAA    2001:DB8::1
		IN   NS	     dns2.example.com.

                IN   MX      10 mail.example.com.
		IN   MX	     20 mail2.example.com.
;
; name          class  ttl  rrtype  rdata
;
$ORIGIN example.com.
dns             IN   A       192.0.2.1
dns2            IN   A       192.0.2.2
mail            IN   A       192.0.2.3

dns      	IN   AAAA    2001:DB8::1
dns2      	IN   AAAA    2001:DB8::2

www             IN   CNAME   dns.example.com.
ns              IN   CNAME   dns.example.com.
mail2		IN   CNAME   dns.example.com.
