$TTL	30s

@	IN	SOA	example007.com.	tewok.leodhas.example007.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example007.com.

		IN	MX 10	leodhas.example007.com.


mull			IN	A	100.0.7.21
iona			IN	A	100.0.7.22
leodhas			IN	A	100.0.7.23
harris			IN	A	100.0.7.24
barra			IN	A	100.0.7.25
skye			IN	A	100.0.7.26
uist			IN	A	100.0.7.27
staffa			IN	A	100.0.7.28
arran			IN	A	100.0.7.29
soarplane		IN	A	100.0.7.99


