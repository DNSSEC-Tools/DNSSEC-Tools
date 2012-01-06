$TTL	30s

@	IN	SOA	example005.com.	tewok.leodhas.example005.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example005.com.

		IN	MX 10	leodhas.example005.com.


mull			IN	A	100.0.5.21
iona			IN	A	100.0.5.22
leodhas			IN	A	100.0.5.23
harris			IN	A	100.0.5.24
barra			IN	A	100.0.5.25
skye			IN	A	100.0.5.26
uist			IN	A	100.0.5.27
staffa			IN	A	100.0.5.28
arran			IN	A	100.0.5.29
soarplane		IN	A	100.0.5.99


