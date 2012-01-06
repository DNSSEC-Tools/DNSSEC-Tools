$TTL	30s

@	IN	SOA	example000.com.	tewok.leodhas.example000.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example000.com.

		IN	MX 10	leodhas.example000.com.


mull			IN	A	100.0.0.21
iona			IN	A	100.0.0.22
leodhas			IN	A	100.0.0.23
harris			IN	A	100.0.0.24
barra			IN	A	100.0.0.25
skye			IN	A	100.0.0.26
uist			IN	A	100.0.0.27
staffa			IN	A	100.0.0.28
arran			IN	A	100.0.0.29
soarplane		IN	A	100.0.0.99


