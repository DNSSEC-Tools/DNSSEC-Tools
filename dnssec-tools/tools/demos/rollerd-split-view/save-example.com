
;  outside view

$TTL	90s

@	IN	SOA	example.com.	sheleanor.example.com. (
					2008113761	; serial
					90s		; refresh
					90s		; retry
					90s		; expire
					90s )		; minimum

@		IN  	NS 	shelly.example.com.

		IN	MX 10	shelly.example.com.

shelly			IN	A	100.10.20.10
webby			IN	A	100.10.20.20
ftpbox			IN	A	100.10.20.21

