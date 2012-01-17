$TTL	30s

@	IN	SOA	test.com.	mal.serenity.test.com. (
					2005033761	; serial
					30s		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	serenity.test.com.

		IN	MX 10	serenity.test.com.


serenity		IN	A	100.60.82.1
capn-mal		IN	A	100.60.82.21
zoe			IN	A	100.60.82.22
wash			IN	A	100.60.82.23
jayne			IN	A	100.60.82.24
book			IN	A	100.60.82.25
river			IN	A	100.60.82.26
simon			IN	A	100.60.82.27
inara			IN	A	100.60.82.28
kaylee			IN	A	100.60.82.29


