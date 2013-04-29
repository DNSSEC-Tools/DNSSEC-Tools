$TTL 1D
example.com.   IN SOA host.example.com. admin.example.com. (
               2009010101
               3H                           ; refresh, seconds
               1H                           ; retry, seconds
               1W                           ; expire, seconds
               3H)                          ; negative ttl minimum, seconds

               NS      ns1.example.com.
               NS      ns2.example.com.
         1D IN MX      10 mail.example.com.

ns1.example.com.       1D IN A         192.0.2.81
ns2.example.com.       1D IN A         192.0.2.82

www.example.com.       1D IN A         192.1.2.1
                       1D IN MX        10 mail.example.com.

; missing MX
ssh.example.com.       1D IN A         192.0.2.2

; deliberately low ttl
lowttl.example.com     50 IN A         192.0.2.3
                       1D IN MX        10 mail.example.com.
