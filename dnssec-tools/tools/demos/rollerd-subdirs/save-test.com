$TTL	1m

@	IN	soa	test.com.	tewok.leodhas.test.com. (
					2005035548	; serial
					3h		; refresh
					30m		; retry
					5m		; expire
					1m )		; minimum

@		IN  	NS 	leodhas.test.com.

		IN	MX 10	leodhas.test.com.


mull			IN	A	200.69.82.21
iona			IN	A	200.69.82.22
leodhas			IN	A	200.69.82.23
harris			IN	A	200.69.82.24
barra			IN	A	200.69.82.25
skye			IN	A	200.69.82.26
uist			IN	A	200.69.82.27
staffa			IN	A	200.69.82.28
arran			IN	A	200.69.82.29
soarplane		IN	A	200.69.82.99


