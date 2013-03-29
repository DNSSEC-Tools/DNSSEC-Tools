use Net::DNS::SEC::Validator;
use Net::DNS::Packet;

$validator = new Net::DNS::SEC::Validator(
    nslist => "8.8.8.8",
#    log_target => "7:stderr",
    rec_fallback => 0,
);

$r = $validator->res_query("good-a.test.dnssec-tools.org", "IN", "A");
my ($pkt, $err) = new Net::DNS::Packet(\$r);
print ($validator->istrusted ? 
           "result is trusted\n" : 
           "result is NOT trusted\n");
#$pkt->print;

##################################################

$a = $validator->resolve_and_check("badsign-a.test.dnssec-tools.org", "IN", "A", 0);
#$a = $validator->resolve_and_check("good-a.test.dnssec-tools.org", "IN", "A", 0);
foreach $h (@$a) {
   print "Status: " .  ${$h}{status} . "\n"; 
   print ($validator->istrusted(${$h}{status}) ? 
           "result is trusted\n" : 
           "result is NOT trusted\n");

   $ac = ${$h}{answer}; 
   while ($ac) {
        print "AC status: " . ${$ac}{status} . "\n";
        $acr = ${$ac}{rrset};
        $acd = ${$acr}{data};
        foreach $d (@$acd) {
            print "Data RR status: " . ${$d}{rrstatus} . "\n";
#            ${$d}{rrdata}->print;
        }
        $acs = ${$acr}{sigs};
        foreach $d (@$acs) {
            print "Sig RR status: " . ${$d}{rrstatus} . "\n";
#            ${$d}{rrdata}->print;
        }
        $ac = ${$ac}{trust};
   } 
}


