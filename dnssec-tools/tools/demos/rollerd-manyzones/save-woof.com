$TTL	1m

@	IN	soa	woof.com.	tewok.leodhas.woof.com. (
					2005035597	; serial
					3h		; refresh
					30m		; retry
					1000m		; expire
					1000m )		; minimum

@		IN  	NS 	leodhas.woof.com.

		IN	MX 10	leodhas.woof.com.


mull			IN	A	1.4.82.21
iona			IN	A	1.4.82.22
leodhas			IN	A	1.4.82.23
harris			IN	A	1.4.82.24
barra			IN	A	1.4.82.25
skye			IN	A	1.4.82.26
uist			IN	A	1.4.82.27
staffa			IN	A	1.4.82.28
arran			IN	A	1.4.82.29
soarplane		IN	A	1.4.82.99


