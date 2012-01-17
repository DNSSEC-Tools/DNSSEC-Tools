$TTL	1m

@	IN	soa	xorn.com.	tewok.leodhas.xorn.com. (
					2005035597	; serial
					3h		; refresh
					30m		; retry
					1m		; expire
					1m )		; minimum

@		IN  	NS 	leodhas.xorn.com.

		IN	MX 10	leodhas.xorn.com.


mull			IN	A	202.1.82.21
iona			IN	A	202.1.82.22
leodhas			IN	A	202.1.82.23
harris			IN	A	202.1.82.24
barra			IN	A	202.1.82.25
skye			IN	A	202.1.82.26
uist			IN	A	202.1.82.27
staffa			IN	A	202.1.82.28
arran			IN	A	202.1.82.29
soarplane		IN	A	202.1.82.99


