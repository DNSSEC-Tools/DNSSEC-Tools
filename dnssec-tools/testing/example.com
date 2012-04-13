$TTL 30

@ IN SOA dns.example.com. admin.example.com. (1 30 30 30 30)

                NS      dns.example.com.

www IN A 127.0.0.1
dns IN A 127.0.0.1
