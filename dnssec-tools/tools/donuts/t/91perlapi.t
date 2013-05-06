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
ok(ref($ref) eq 'ARRAY', 'starting with an array');

$formatter->StartOutput();
ok(ref($ref) eq 'ARRAY', 'still an ARRAY');

my $array = ['bar'];
$formatter->Output('foo','bar');
is_deeply($ref, $array, "initial array correct");

my $struct = {};
$array->[1] = $struct;
$formatter->StartSection('parentstruct', 'parentstruct');
$struct->{'name'} = 'parentstruct';
is_deeply($ref, $array, "parent struct correct");

$struct->{'sub'} = { name => 'structure'};
$formatter->StartSection('sub', 'structure');
is_deeply($ref, $array, "initial hash correct");

$struct->{'sub'}{'deeptag'} = 'octopus';
$formatter->Output('deeptag', 'octopus');

$formatter->EndSection();
is_deeply($ref, $array, "hash still correct");

$struct->{'subarray'} = [];
$formatter->StartArray('subarray', 'blah');
is_deeply($ref, $array, "added subarray");

$struct->{'subarray'}[0] = 'whee';
$formatter->Output('bogus', 'whee');
is_deeply($ref, $array, "added whee");

$struct->{'subarray'}[1] = [];
$formatter->StartArray('subsubarray', 'blah');
is_deeply($ref, $array, "added subsubarray");

$formatter->EndArray();
$formatter->EndArray();
is_deeply($ref, $array, "hash still correct");
