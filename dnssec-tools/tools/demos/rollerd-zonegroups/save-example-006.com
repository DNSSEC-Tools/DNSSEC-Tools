$TTL	30s

@	IN	SOA	example006.com.	tewok.leodhas.example006.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example006.com.

		IN	MX 10	leodhas.example006.com.


mull			IN	A	100.0.6.21
iona			IN	A	100.0.6.22
leodhas			IN	A	100.0.6.23
harris			IN	A	100.0.6.24
barra			IN	A	100.0.6.25
skye			IN	A	100.0.6.26
uist			IN	A	100.0.6.27
staffa			IN	A	100.0.6.28
arran			IN	A	100.0.6.29
soarplane		IN	A	100.0.6.99


