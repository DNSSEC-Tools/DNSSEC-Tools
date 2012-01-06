$TTL	30s

@	IN	SOA	example009.com.	tewok.leodhas.example009.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example009.com.

		IN	MX 10	leodhas.example009.com.


mull			IN	A	100.0.9.21
iona			IN	A	100.0.9.22
leodhas			IN	A	100.0.9.23
harris			IN	A	100.0.9.24
barra			IN	A	100.0.9.25
skye			IN	A	100.0.9.26
uist			IN	A	100.0.9.27
staffa			IN	A	100.0.9.28
arran			IN	A	100.0.9.29
soarplane		IN	A	100.0.9.99


