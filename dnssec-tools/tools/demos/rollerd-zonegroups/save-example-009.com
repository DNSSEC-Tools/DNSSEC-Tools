$TTL	30s

@	IN	SOA	example009.com.	tewok.leodhas.example009.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example009.com.

		IN	MX 10	leodhas.example009.com.


mull			IN	A	1.9.81.21
iona			IN	A	1.9.81.22
leodhas			IN	A	1.9.81.23
harris			IN	A	1.9.81.24
barra			IN	A	1.9.81.25
skye			IN	A	1.9.81.26
uist			IN	A	1.9.81.27
staffa			IN	A	1.9.81.28
arran			IN	A	1.9.81.29
soarplane		IN	A	1.9.81.99


