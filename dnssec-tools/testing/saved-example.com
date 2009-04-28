$ORIGIN com.
$TTL 3h
example     IN SOA dns.example.com. admin.example.com. (
                2009030144  ;SERIALNUM
                3H  ; Refresh
                1H  ; Retry
                1W  ; Expire
                1D) ; Minimum TTL
$TTL 3h
                1D IN   NS      dns.example.com.
		1D IN   A       192.0.2.1
		1D IN	AAAA	2001:DB8::1
		1D IN	NS	dns2.example.com.

                1D IN   MX      10 dns.example.com.
		1D IN   MX	20 dns2.example.com.
;
; name          class  ttl  rrtype  rdata
;
$ORIGIN example.com.
dns             1D IN   A       192.0.2.1
dns2            1D IN   A       192.0.2.2

dns      	1D IN	AAAA   	2001:DB8::1
dns2      	1D IN	AAAA   	2001:DB8::2

www             1D IN   CNAME   dns.example.com.
ns              1D IN   CNAME   dns.example.com.
mail		1D IN   CNAME	dns.example.com.
