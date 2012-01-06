$TTL	30s

@	IN	SOA	example004.com.	tewok.leodhas.example004.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example004.com.

		IN	MX 10	leodhas.example004.com.


mull			IN	A	100.0.4.21
iona			IN	A	100.0.4.22
leodhas			IN	A	100.0.4.23
harris			IN	A	100.0.4.24
barra			IN	A	100.0.4.25
skye			IN	A	100.0.4.26
uist			IN	A	100.0.4.27
staffa			IN	A	100.0.4.28
arran			IN	A	100.0.4.29
soarplane		IN	A	100.0.4.99


