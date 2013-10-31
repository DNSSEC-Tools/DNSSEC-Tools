use Net::DNS::SEC::Validator;
use Net::DNS::Packet;

my $flags = VAL_QUERY_AC_DETAIL;

sub print_result {

    my $tc = shift;
    my $ret = shift;
    my $a = shift;

    print "Completed = $tc\n";
    print "Retval = $ret\n";
    
    if (!$a) {
        print "Result = NULL\n";
        return;
    } 

#print "\Result: " .  Data::Dumper::Dumper($a) . "\n";

    foreach $h (@$a) {
        print "Status: " .  ${$h}{status} . "\n"; 
        $acs = ${$h}{answer}; 
        foreach $ac (@$acs) {

            print "Answer AC status: " . ${$ac}{status} . "\n";
            $acr = ${$ac}{rrset};
            $acd = ${$acr}{data};
            $acs = ${$acr}{sigs};

            foreach $d (@$acd) {
                print "\tData RR status: " . ${$d}{rrstatus} . "\n";
                my $rr = ${$d}{rrdata};
                if ($rr) {
                    print "\tData RR name: " . $rr->name() . "\n";
                    print "\tData RR class: " . $rr->class() . "\n";
                    print "\tData RR type: " . $rr->type() . "\n";
                    print "\tData RR ttl: " . $rr->ttl() . "\n";
                    print "\tData RR data: " . $rr->rdstring() . "\n";
                }
            }
            foreach $d (@$acs) {
                print "\tSig RR status: " . ${$d}{rrstatus} . "\n";
                my $rr = ${$d}{rrdata};
                if ($rr) {
                    print "\tSig RR name: " . $rr->name . "\n";
                    print "\tSig RR class: " . $rr->class . "\n";
                    print "\tSig RR type: " . $rr->type . "\n";
                    print "\tSig RR ttl: " . $rr->ttl . "\n";
                    print "\tSig RR data: " . $rr->rdstring() . "\n";
                }
            }
       }
        foreach $ac (${$h}{proofs}) {
            print "Proof = " . Data::Dumper::Dumper($ac) . "\n";
        }
    } 
}

##################################################

=pod
$val1 = new Net::DNS::SEC::Validator(
    nslist => "8.8.8.8",
    log_target => "7:stderr",
    rec_fallback => 0,
    policy => ":",
);

$r = $val1->res_query("good-a.test.dnssec-tools.org", "IN", "A");
my ($pkt, $err) = new Net::DNS::Packet(\$r);
print ($val1->istrusted ? 
           "result is trusted\n" : 
           "result is NOT trusted\n");
$pkt->print;

=cut

##################################################

=pod
my $val2 = new Net::DNS::SEC::Validator(
    nslist => "8.8.8.8",
    log_target => "7:stderr",
    rec_fallback => 0,
    policy => ":",
);
$a = $val2->resolve_and_check("badsign-a.test.dnssec-tools.org", "IN", "A", 0);
print_result("Test case sync 1", 0, $a); 
$a = $val2->resolve_and_check("good-cname-to-good-A.test.dnssec-tools.org", "IN", "A", $flags);
print_result("Test case sync 2", 0, $a); 
=cut

##################################################

my $val3 = new Net::DNS::SEC::Validator(
    nslist => "8.8.8.8",
    log_target => "7:stderr",
    rec_fallback => 0,
    policy => ":",
);

$val3->async_submit("good-a.test.dnssec-tools.org", "IN", "A", $flags, \&print_result, "async 1 ");
$val3->async_submit("badsign-a.test.dnssec-tools.org", "IN", "A", $flags, \&print_result, "async 2");
$val3->async_submit("www.dnssec-tools.org", "IN", "A", $flags, \&print_result, "async 3");
$val3->async_submit("www.dnssec-deployment.org", "IN", "A", $flags, \&print_result, "async 4");
$val3->async_submit("good-cname-to-good-A.test.dnssec-tools.org", "IN", "A", $flags, \&print_result, "V1-4/4"); 
$val3->async_submit("dnssec-tools.org", "IN", "DNSKEY", $flags, \&print_result, "async 5");

my @valarr = ($val3);
my $DEFAULT_TMOUT = 10;
my $done = 0;
while (!$done)
{
    my $readfds = [];
    my $ref;
    my $ret;
    my $timeout = $DEFAULT_TMOUT;

    $done = 1;

    foreach my $val (@valarr) {
        $ref = $val->async_gather($readfds, $timeout);
        $ret = $ref->[0];
        $readfds = $ref->[1];
        $timeout = $ref->[2];
    }

    @readyarr = IO::Select->new(@$readfds)->can_read($timeout);
    my $readyref = \@readyarr;

    foreach my $val (@valarr) {
        my $pending;
        $ref = $val->async_check($readyref);
        $pending = $ref->[0];
        $readyref = $ref->[1];
        if ($pending > 0) {
            $done = 0;
        }
    }
}

