$TTL	1m

@	IN	soa	xorn.com.	tewok.leodhas.xorn.com. (
					2005035597	; serial
					3h		; refresh
					30m		; retry
					2000m		; expire
					2000m )		; minimum

@		IN  	NS 	leodhas.xorn.com.

		IN	MX 10	leodhas.xorn.com.


mull			IN	A	1.5.82.21
iona			IN	A	1.5.82.22
leodhas			IN	A	1.5.82.23
harris			IN	A	1.5.82.24
barra			IN	A	1.5.82.25
skye			IN	A	1.5.82.26
uist			IN	A	1.5.82.27
staffa			IN	A	1.5.82.28
arran			IN	A	1.5.82.29
soarplane		IN	A	1.5.82.99


