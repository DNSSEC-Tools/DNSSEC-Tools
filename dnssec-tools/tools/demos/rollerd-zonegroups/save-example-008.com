$TTL	30s

@	IN	SOA	example008.com.	tewok.leodhas.example008.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example008.com.

		IN	MX 10	leodhas.example008.com.


mull			IN	A	1.8.81.21
iona			IN	A	1.8.81.22
leodhas			IN	A	1.8.81.23
harris			IN	A	1.8.81.24
barra			IN	A	1.8.81.25
skye			IN	A	1.8.81.26
uist			IN	A	1.8.81.27
staffa			IN	A	1.8.81.28
arran			IN	A	1.8.81.29
soarplane		IN	A	1.8.81.99


