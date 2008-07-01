$TTL	1m

@	IN	soa	dummy.com.	tewok.leodhas.dummy.com. (
					2005034774	; serial
					3h		; refresh
					30m		; retry
					5m		; expire
					1m )		; minimum

@		IN  	NS 	leodhas.dummy.com.

		IN	MX 10	leodhas.dummy.com.


mull			IN	A	1.69.82.21
iona			IN	A	1.69.82.22
leodhas			IN	A	1.69.82.23
harris			IN	A	1.69.82.24
barra			IN	A	1.69.82.25
skye			IN	A	1.69.82.26
uist			IN	A	1.69.82.27
staffa			IN	A	1.69.82.28
arran			IN	A	1.69.82.29
soarplane		IN	A	1.69.82.99


