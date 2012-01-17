$TTL	30s

@	IN	SOA	example001.com.	tewok.leodhas.example001.com. (
					0	; serial
					3h		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	leodhas.example001.com.

		IN	MX 10	leodhas.example001.com.


mull			IN	A	1.1.81.21
iona			IN	A	1.1.81.22
leodhas			IN	A	1.1.81.23
harris			IN	A	1.1.81.24
barra			IN	A	1.1.81.25
skye			IN	A	1.1.81.26
uist			IN	A	1.1.81.27
staffa			IN	A	1.1.81.28
arran			IN	A	1.1.81.29
soarplane		IN	A	1.1.81.99


