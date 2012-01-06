$TTL	30s

@	IN	SOA	example008.com.	tewok.leodhas.example008.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example008.com.

		IN	MX 10	leodhas.example008.com.


mull			IN	A	100.0.8.21
iona			IN	A	100.0.8.22
leodhas			IN	A	100.0.8.23
harris			IN	A	100.0.8.24
barra			IN	A	100.0.8.25
skye			IN	A	100.0.8.26
uist			IN	A	100.0.8.27
staffa			IN	A	100.0.8.28
arran			IN	A	100.0.8.29
soarplane		IN	A	100.0.8.99


