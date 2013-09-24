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
foreach $h (@$a) {
   print "Status: " .  ${$h}{status} . "\n"; 
   print ($validator->istrusted(${$h}{status}) ? 
           "result is trusted\n" : 
           "result is NOT trusted\n");

   $acs = ${$h}{answer}; 
   foreach my $ac ($acs) {
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
   } 
}

##################################################

sub callback {

    my $tc = shift;
    my $ret = shift;
    my $a = shift;

    print "Completed = $tc\n";
    print "Retval = $ret\n";
    #print "Result = " . Data::Dumper::Dumper($a) . "\n";

    foreach $h (@$a) {
        print "Status: " .  ${$h}{status} . "\n"; 
        $acs = ${$h}{answer}; 
        foreach $ac (@$acs) {
            print "Answer AC status: " . ${$ac}{status} . "\n";
            $acr = ${$ac}{rrset};
            $acd = ${$acr}{data};
            foreach $d (@$acd) {
                print "\tData RR status: " . ${$d}{rrstatus} . "\n";
#                   ${$d}{rrdata}->print;
            }
            $acs = ${$acr}{sigs};
            foreach $d (@$acs) {
                print "\tSig RR status: " . ${$d}{rrstatus} . "\n";
#               ${$d}{rrdata}->print;
            }
        }
#        foreach $ac (${$h}{proofs}) {
#            print "Proof = " . Data::Dumper::Dumper($ac) . "\n";
#        }
    } 
}

my $val1 = new Net::DNS::SEC::Validator(
#    log_target => "7:stderr",
    rec_fallback => 0,
    policy => ":",
);

$val1->async_submit("good-a.test.dnssec-tools.org", "IN", "A", 0, \&callback, "V1-1/4");
$val1->async_submit("badsign-a.test.dnssec-tools.org", "IN", "A", 0, \&callback, "V1-2/4");
$val1->async_submit("www.dnssec-tools.org", "IN", "A", 0, \&callback, "V1-3/4");
$val1->async_submit("www.dnssec-deployment.org", "IN", "A", 0, \&callback, "V1-4/4");

my @valarr = ($val1);
my $DEFAULT_TMOUT = 10;
while (1)
{
    my $readfds = [];
    my $ref;
    my $ret;
    my $timeout = $DEFAULT_TMOUT;

    foreach my $val (@valarr) {
        $ref = $val->async_gather($readfds, $timeout);
        $ret = $ref->[0];
        $readfds = $ref->[1];
        $timeout = $ref->[2];
    }

    if (! @$readfds) {
        last;
    }

    @readyarr = IO::Select->new(@$readfds)->can_read($timeout);
    $ready = \@readyarr;

    foreach my $val (@valarr) {
        my @tmpready = @$ready;
        $ret = $val->async_check(\@tmpready);
    }
}

