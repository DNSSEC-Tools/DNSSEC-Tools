$TTL	45s

@	IN	SOA	dev.com.	tewok.leodhas.dev.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					1m		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.dev.com.

		IN	MX 10	leodhas.dev.com.


mull			IN	A	100.100.82.21
iona			IN	A	100.100.82.22
leodhas			IN	A	100.100.82.23
harris			IN	A	100.100.82.24
barra			IN	A	100.100.82.25
skye			IN	A	100.100.82.26
uist			IN	A	100.100.82.27
staffa			IN	A	100.100.82.28
arran			IN	A	100.100.82.29
soarplane		IN	A	100.100.82.99


