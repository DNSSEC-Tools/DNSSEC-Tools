# -*- perl -*-
use Test::More qw(no_plan);
use Data::Dumper;
use Net::DNS::SEC::Tools::Donuts::Rule;

# this tests a fairly complex case of building nested structures
# programatically

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts::Output::Format::Perl'); }
require_ok('Net::DNS::SEC::Tools::Donuts::Output::Format::Perl');

my $formatter = new Net::DNS::SEC::Tools::Donuts::Output::Format::Perl();

my $ref = $formatter->storage_ref();
ok(ref($ref) eq 'HASH', 'starting with a hash');

$formatter->StartOutput();
ok(ref($ref) eq 'HASH', 'still a hash');

my $struct = { foo => 'bar' };
$formatter->Output('foo','bar');
is_deeply($ref, $struct, "initial hash correct");

$struct->{'sub'} = { name => 'structure'};
$formatter->StartSection('sub', 'structure');
is_deeply($ref, $struct, "initial hash correct");

$struct->{'sub'}{'deeptag'} = 'octopus';
$formatter->Output('deeptag', 'octopus');

$formatter->EndSection();
is_deeply($ref, $struct, "hash still correct");

$struct->{'subarray'} = [];
$formatter->StartArray('subarray', 'blah');
is_deeply($ref, $struct, "added subarray");

$struct->{'subarray'}[0] = 'whee';
$formatter->Output('bogus', 'whee');
is_deeply($ref, $struct, "added whee");

$struct->{'subarray'}[1] = [];
$formatter->StartArray('subsubarray', 'blah');
is_deeply($ref, $struct, "added subsubarray");

$formatter->EndArray();
$formatter->EndArray();
is_deeply($ref, $struct, "hash still correct");
