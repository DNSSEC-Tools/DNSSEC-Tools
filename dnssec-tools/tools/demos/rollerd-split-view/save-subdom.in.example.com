
;  inside view

$TTL	30s

@	IN	SOA	example.com.	tewok.example.com. (
					2008113761	; serial
					30s		; refresh
					30s		; retry
					30s		; expire
					30s )		; minimum

@		IN  	NS 	shelly.example.com.

		IN	MX 10	shelly.example.com.

webby			IN	A	1.2.3.10
ftpbox			IN	A	1.2.3.11

