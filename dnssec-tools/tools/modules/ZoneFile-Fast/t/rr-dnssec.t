# This is -*- perl -*-

use Net::DNS::ZoneFile::Fast;

# we test multiple line and single line parsing for each record
# data is pulled from the dnssec-tools.org zone
BEGIN {
    @test = 
	(
	 q{dnssec-tools.org. 86400   RRSIG   SOA 5 2 86400 20060429134027 (
                                        20060330134027 42869 dnssec-tools.org.
                                        QZzAz5sVC5+n7vJhkXfFaN/sdjKXVpT/nv22
                                        NJI+sDde180Sj1pDXW6mFt+Efg4uUAuyLQup
                                        jLv20EVM8/oBPA7DjNu2CZHGe8UDeuAoqIth
                                        Q/79Ltw4NtP7W1zWAs/ms/oSKiKYrAUHqt0U
                                        UskiXkCA1GKn6RNqVT4+IuSUgALLYSMLjlaA
                                        2kE/KaffqeGnynIO2AC5BMFzUlxCSMDSxus3
                                        bJm2xAIxMiUYomw9XfbGfrkCtfIrH+H/LVG/
                                        X2K/kKxjcFcQhkukMUxjzzmAP3xJHq6vgwVM
                                        tpm/qaR0g5jH5B46iJefGYzwcMAyexbLOQEW
                                        uv1Xs6i/lBwQo9T7xw== )},
         q{.		86400	RRSIG	SOA 5 0 86400 20090913150000 (
					20090907150000 18160 .
					kgbUsnZwzY/s9zGcHvQ30tTNk5raweJuvo71
					9GzBI+Ennjn25bGp7CYbfLk0tMk9Fcai5nfg
					8hDshKwEUemign1r+SkHsiwISOr3vpTAUANg
					+GzQwLSrZHT81wvS06DYXE/O0L/pxSKfQBON
					8owuxhnczIDncP3xeh0Stai2jeU= )},

# failing oddly during text compare.  spacing is different.
	 q{nospace.dnssec-tools.org. 86400   RRSIG   SOA 5 2 86400 20060429134027 20060330134027 42869 dnssec-tools.org. QZzAz5sVC5+n7vJhkXfFaN/sdjKXVpT/nv22 NJI+sDde180Sj1pDXW6mFt+Efg4uUAuyLQup jLv20EVM8/oBPA7DjNu2CZHGe8UDeuAoqIth Q/79Ltw4NtP7W1zWAs/ms/oSKiKYrAUHqt0U UskiXkCA1GKn6RNqVT4+IuSUgALLYSMLjlaA 2kE/KaffqeGnynIO2AC5BMFzUlxCSMDSxus3 bJm2xAIxMiUYomw9XfbGfrkCtfIrH+H/LVG/ X2K/kKxjcFcQhkukMUxjzzmAP3xJHq6vgwVM tpm/qaR0g5jH5B46iJefGYzwcMAyexbLOQEW uv1Xs6i/lBwQo9T7xw= },
	 q{dnssec-tools.org. 10800   NSEC cvs.dnssec-tools.org A DNSKEY MX NS NSEC RRSIG SOA TXT},
	 q{THA2IPMDLT9RU307BO9LQ6MF5K565A6M.example.com. 10800 IN NSEC3 1 0 100 610b88f0d9f42c74 QIVB7DNNE2T5J9HLI4FRE9PN61F754CK A RRSIG},
	 q{THA2IPMDLT9RU307BO9LQ6MF5K565A6M.example.com. 10800 IN NSEC3 1 0 100 610b88f0d9f42c74 (
 QIVB7DNNE2T5J9HLI4FRE9PN61F754CK
 A RRSIG )},
	 q{THA2IPMDLT9RU307BO9LQ6MF5K565A6M.example.com. 10800 IN NSEC3 1 0 100 610b88f0d9f42c74 QIVB7DNNE2T5J9HLI4FRE9PN61F754CK},
	 q{THA2IPMDLT9RU307BO9LQ6MF5K565A6M.example.com. 10800 IN NSEC3 1 0 100 610b88f0d9f42c74 (
 QIVB7DNNE2T5J9HLI4FRE9PN61F754CK
 )},

	 q{example.com		0	NSEC3PARAM 1 0 100 610b88f0d9f42c74},

         q{dnssec-tools.org. 			86400	DNSKEY	256 3 5 (
					AQOfW6Uo0QQZS1fJmtx3XoX+B67Bxfyn+uhe
					py5JifpPWPnx+O0bR30+Oi4bpVrXtipGK3EW
					ouDWy4eAflrsdIgunotWE1H4/rQaXxc4IowJ
					V8dm5xejyMswUzPOxL3mnbhQ0gUtSTSO7/Ho
					EJisuqy50/pg1y8a09PiicJefXaB31IawDXn
					IZz2QYluyxS2zYPnb/2RjeCxgTzGgtjUYlw5
					0czRYDARyGlkAiwxch/RfgEcqoLk+dPwmSU9
					l4Shu8XkkpiAFEUqs3cTooA2UltVvKFpqoMT
					q0EVHcdHDuIExeGCxCw/RjsiOOIey3BKo86T
					NCU8USUWld3FinA4BPnB
					) ; key id = 42869},
         q{dnssec-tools.org. 			86400	DNSKEY	256 3 5 AQOfW6Uo0QQZS1fJmtx3XoX+B67Bxfyn+uhe py5JifpPWPnx+O0bR30+Oi4bpVrXtipGK3EW ouDWy4eAflrsdIgunotWE1H4/rQaXxc4IowJ V8dm5xejyMswUzPOxL3mnbhQ0gUtSTSO7/Ho EJisuqy50/pg1y8a09PiicJefXaB31IawDXn IZz2QYluyxS2zYPnb/2RjeCxgTzGgtjUYlw5 0czRYDARyGlkAiwxch/RfgEcqoLk+dPwmSU9 l4Shu8XkkpiAFEUqs3cTooA2UltVvKFpqoMT q0EVHcdHDuIExeGCxCw/RjsiOOIey3BKo86T NCU8USUWld3FinA4BPnB},
         q{dnssec-tools.org. 			86400	DNSKEY	256 3 5 AQOfW6Uo0QQZS1fJmtx3XoX+B67Bxfyn+uhe py5JifpPWPnx+O0bR30+Oi4bpVrXtipGK3EW ouDWy4eAflrsdIgunotWE1H4/rQaXxc4IowJ V8dm5xejyMswUzPOxL3mnbhQ0gUtSTSO7/Ho EJisuqy50/pg1y8a09PiicJefXaB31IawDXn IZz2QYluyxS2zYPnb/2RjeCxgTzGgtjUYlw5 0czRYDARyGlkAiwxch/RfgEcqoLk+dPwmSU9 l4Shu8XkkpiAFEUqs3cTooA2UltVvKFpqoMT q0EVHcdHDuIExeGCxCw/RjsiOOIey3BKo86T NCU8USUWld3FinA4BPnB},
         q{dnssec-tools.org. 			86400	DNSKEY	256 3 5 AQOfW6Uo0QQZS1fJmtx3XoX+B67Bxfyn+uhe py5JifpPWPnx+O0bR30+Oi4bpVrXtipGK3EW ouDWy4eAflrsdIgunotWE1H4/rQaXxc4IowJ V8dm5xejyMswUzPOxL3mnbhQ0gUtSTSO7/Ho EJisuqy50/pg1y8a09PiicJefXaB31IawDXn IZz2QYluyxS2zYPnb/2RjeCxgTzGgtjUYlw5 0czRYDARyGlkAiwxch/RfgEcqoLk+dPwmSU9 l4Shu8XkkpiAFEUqs3cTooA2UltVvKFpqoMT q0EVHcdHDuIExeGCxCw/RjsiOOIey3BKo86T NCU8USUWld3FinA4BPnB;bogus extra comment},
	 q{test.dnssec-tools.org.  86400   IN      DS      28827 5 1 23a4c97124ab46e7fb7abb58e36887ff78745ac8},
	 q{test.dnssec-tools.org.  86400   IN      DS      28827 5 2 7d06a161755f7c7ca0d15b8039c7d7b45fb8e5dd025fcebe209cb07756bbae07},
	 q{test.dnssec-tools.org.  86400 IN      DS      28827 5 2 ( 7d06a161755f7c7ca0d15b8039c7d7b45fb8e5dd025fcebe209cb07756bbae07 ) },
	 q{test.dnssec-tools.org.  86400   DS      28827 5 1 23a4c97124ab46e7fb7abb58e36887ff78745ac8},
	 # a specific test for ttl values that could accidentially match DS
	 q{test.dnssec-tools.org.          DS      28827 5 2 7d06a161755f7c7ca0d15b8039c7d7b45fb8e5dd025fcebe209cb07756bbae07},
	 # bind 10 puts parens in new places:
         q{example.com   10  RRSIG   SOA 5 2 10 20080613221109 (
                    20080514221109 51389 example.com.
                    rQ1d9a6ZCbZvwx47efKJL2s1FbcHzLt4SKca
                    F2Xwr8YyPyhMffjkdFwtXGLFwvaQ9SE2ocEU
                    /QpxKmvsqSyE3SyinuuCaR/XF/7XKK/PShUg
                    iRJ7S/GExtJDfheJ04zydDyIYM8M96GpE920
                    0LfJVZuo+gxwvrvTZiejVn1aNnc= )},
         q{example.com   10  RRSIG   SOA 5 2 10 (
                    20080613221109 20080514221109 51389 example.com.
                    rQ1d9a6ZCbZvwx47efKJL2s1FbcHzLt4SKca
                    F2Xwr8YyPyhMffjkdFwtXGLFwvaQ9SE2ocEU
                    /QpxKmvsqSyE3SyinuuCaR/XF/7XKK/PShUg
                    iRJ7S/GExtJDfheJ04zydDyIYM8M96GpE920
                    0LfJVZuo+gxwvrvTZiejVn1aNnc= )},

	 );
}

use Test::More tests => 2 * scalar @test;

for my $rrdata (@test) {
    my $rrset = Net::DNS::ZoneFile::Fast::parse($rrdata);
    (my $adata = $rrdata) =~ s/@/./;
    $adata =~ s/(IN SOA .* (\d+)) \)/ $2 $1/;
    my $rr = new Net::DNS::RR $adata;
    (my $rrcorrect = $rr->string) =~ s/\s+/ /g;
    ok(defined $rrset, "Parsing $rrdata");
    (my $rrtxt = $rrset->[0]->string) =~ s/\s+/ /g;

    if ($rrtxt =~ /^nospace/) {
	$rrtxt =~ s/\s//g;
	$rrcorrect =~ s/\s//g;
    }
    is($rrtxt, $rrcorrect, "RR comparison for $rrdata");
}

