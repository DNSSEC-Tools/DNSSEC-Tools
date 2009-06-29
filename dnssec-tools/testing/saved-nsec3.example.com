$ORIGIN example.com.
$TTL 3h
nsec3     IN SOA dns.nsec3.example.com. admin.nsec3.example.com. (
                2009030144  ;SERIALNUM
                3H  ; Refresh
                1H  ; Retry
                1W  ; Expire
                1D) ; Minimum TTL
$TTL 3h
                1D IN   NS      dns.nsec3.example.com.
		1D IN   A       192.0.2.1
		1D IN	AAAA	2001:DB8::1
		1D IN	NS	dns2.nsec3.example.com.

                1D IN   MX      10 dns.nsec3.example.com.
		1D IN   MX	20 dns2.nsec3.example.com.
;
; name          class  ttl  rrtype  rdata
;
$ORIGIN nsec3.example.com.
dns             1D IN   A       192.0.2.1
dns2            1D IN   A       192.0.2.2

dns      	1D IN	AAAA   	2001:DB8::1
dns2      	1D IN	AAAA   	2001:DB8::2

www             1D IN   CNAME   dns.nsec3.example.com.
ns              1D IN   CNAME   dns.nsec3.example.com.
mail		1D IN   CNAME	dns.nsec3.example.com.
