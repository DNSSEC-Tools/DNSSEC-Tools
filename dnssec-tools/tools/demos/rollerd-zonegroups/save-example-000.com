$TTL	30s

@	IN	SOA	example000.com.	tewok.leodhas.example000.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example000.com.

		IN	MX 10	leodhas.example000.com.


mull			IN	A	1.10.81.21
iona			IN	A	1.10.81.22
leodhas			IN	A	1.10.81.23
harris			IN	A	1.10.81.24
barra			IN	A	1.10.81.25
skye			IN	A	1.10.81.26
uist			IN	A	1.10.81.27
staffa			IN	A	1.10.81.28
arran			IN	A	1.10.81.29
soarplane		IN	A	1.10.81.99


