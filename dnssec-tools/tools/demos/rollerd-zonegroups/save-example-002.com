$TTL	30s

@	IN	SOA	example002.com.	tewok.leodhas.example002.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example002.com.

		IN	MX 10	leodhas.example002.com.


mull			IN	A	100.0.2.21
iona			IN	A	100.0.2.22
leodhas			IN	A	100.0.2.23
harris			IN	A	100.0.2.24
barra			IN	A	100.0.2.25
skye			IN	A	100.0.2.26
uist			IN	A	100.0.2.27
staffa			IN	A	100.0.2.28
arran			IN	A	100.0.2.29
soarplane		IN	A	100.0.2.99


