$TTL	1m

@	IN	soa	yowzah.com.	tewok.leodhas.yowzah.com. (
					2005035597	; serial
					3h		; refresh
					30m		; retry
					3000m		; expire
					3000m )		; minimum

@		IN  	NS 	leodhas.yowzah.com.

		IN	MX 10	leodhas.yowzah.com.


mull			IN	A	1.6.82.21
iona			IN	A	1.6.82.22
leodhas			IN	A	1.6.82.23
harris			IN	A	1.6.82.24
barra			IN	A	1.6.82.25
skye			IN	A	1.6.82.26
uist			IN	A	1.6.82.27
staffa			IN	A	1.6.82.28
arran			IN	A	1.6.82.29
soarplane		IN	A	1.6.82.99


