$TTL	30

@	IN	SOA	demo.com.	tewok.leodhas.demo.com. (
					0	; serial
					3h		; refresh
					30m		; retry
					5m		; expire
					30 )		; minimum

@		IN  	NS 	leodhas.demo.com.

		IN	MX 10	leodhas.demo.com.


mull			IN	A	123.45.67.80
iona			IN	A	123.45.67.81
leodhas			IN	A	123.45.67.82
harris			IN	A	123.45.67.83
barra			IN	A	123.45.67.84
skye			IN	A	123.45.67.85
uist			IN	A	123.45.67.86
staffa			IN	A	123.45.67.87
arran			IN	A	123.45.67.88
soarplane		IN	A	123.45.67.89


