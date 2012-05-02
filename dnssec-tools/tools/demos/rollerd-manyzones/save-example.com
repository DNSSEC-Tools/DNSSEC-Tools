$TTL	20s

@	IN	soa	example.com.	tewok.leodhas.example.com. (
					2005033761	; serial
					3h		; refresh
					30m		; retry
					1m		; expire
					20s )		; minimum

@		IN  	NS 	leodhas.example.com.

		IN	MX 10	leodhas.example.com.


mull			IN	A	1.2.82.21
iona			IN	A	1.2.82.22
leodhas			IN	A	1.2.82.23
harris			IN	A	1.2.82.24
barra			IN	A	1.2.82.25
skye			IN	A	1.2.82.26
uist			IN	A	1.2.82.27
staffa			IN	A	1.2.82.28
arran			IN	A	1.2.82.29
soarplane		IN	A	1.2.82.99


