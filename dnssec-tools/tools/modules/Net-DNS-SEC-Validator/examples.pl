#!/usr/bin/perl

use Net::DNS::SEC::Validator;
use Net::DNS::Packet;
use Data::Dumper;

my $flags = VAL_QUERY_AC_DETAIL|VAL_QUERY_CHECK_ALL_RRSIGS;

sub print_result {

    my $tc = shift;
    my $ret = shift;
    my $a = shift;

    print "*******************************\n";
    print "Completed = $tc Retval = $ret\n";
    
    if (!$a) {
        print "Result = NULL\n";
        return;
    } 

#print "\Result: " .  Data::Dumper::Dumper($a) . "\n";

    foreach $h (@$a) {
        my $ans = ${$h}{answer}; 

        print "Status: " .  ${$h}{status} . "\n"; 
        foreach $ac (@$ans) {

            my $acr = ${$ac}{rrset};
            my $acd = ${$acr}{data};
            my $acs = ${$acr}{sigs};
            my $serv = ${$acr}{respserv};

            print "Answer AC status: " . ${$ac}{status} . "\n";
            print "Response received from: " . $serv . "\n";
            foreach $d (@$acd) {
                print "\tData RR status: " .
                    Net::DNS::SEC::Validator::_ac_status(${$d}{rrstatus}) . "\n";
                my $rr = ${$d}{rrdata};
                if ($rr) {
                    print "\tData RR name: " . $rr->name() . "\n";
                    print "\tData RR class: " . $rr->class() . "\n";
                    print "\tData RR type: " . $rr->type() . "\n";
                    print "\tData RR ttl: " . $rr->ttl() . "\n";
                    print "\tData RR data: " . $rr->rdatastr() . "\n";
                }
            }
            foreach $d (@$acs) {
                print "\tSig RR status: " .
                    Net::DNS::SEC::Validator::_ac_status(${$d}{rrstatus}) . "\n";
                my $rr = ${$d}{rrdata};
                if ($rr) {
                    print "\tSig RR name: " . $rr->name . "\n";
                    print "\tSig RR class: " . $rr->class . "\n";
                    print "\tSig RR type: " . $rr->type . "\n";
                    print "\tSig RR ttl: " . $rr->ttl . "\n";
                    print "\tSig RR data: " . $rr->rdatastr() . "\n";
                }
            }
       }
#        foreach $ac (${$h}{proofs}) {
#            print "Proof = " . Data::Dumper::Dumper($ac) . "\n";
#        }
    } 
    print "\n";
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
#   log_target => "7:stderr",
    rec_fallback => 0,
    policy => ":",
    edns0_size => 1492,
);

#$val3->map_ns("dnssec-tools.org", "168.150.236.43");

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

