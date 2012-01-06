$TTL	30s

@	IN	SOA	example003.com.	tewok.leodhas.example003.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example003.com.

		IN	MX 10	leodhas.example003.com.


mull			IN	A	100.0.3.21
iona			IN	A	100.0.3.22
leodhas			IN	A	100.0.3.23
harris			IN	A	100.0.3.24
barra			IN	A	100.0.3.25
skye			IN	A	100.0.3.26
uist			IN	A	100.0.3.27
staffa			IN	A	100.0.3.28
arran			IN	A	100.0.3.29
soarplane		IN	A	100.0.3.99


