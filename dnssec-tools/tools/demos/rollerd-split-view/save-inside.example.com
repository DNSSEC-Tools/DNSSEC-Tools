
;  inside view

$TTL	60s

@	IN	SOA	example.com.	sheleanor.example.com. (
					2008113761	; serial
					60s		; refresh
					60s		; retry
					60s		; expire
					60s )		; minimum

@		IN  	NS 	shelly.example.com.

		IN	MX 10	shelly.example.com.

shelly			IN	A	1.2.3.1
webby			IN	A	1.2.3.10
ftpbox			IN	A	1.2.3.11

