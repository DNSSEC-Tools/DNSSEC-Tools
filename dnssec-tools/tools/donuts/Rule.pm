package Net::DNS::SEC::Tools::Donuts::Rule;

use strict;
use Net::DNS;
use Text::Wrap;
our $VERSION="0.1";

sub new {
    my ($class, $ref) = @_;
    bless $ref, $class;
    return $ref;
}

# Print the results of an error for a given rule
sub print_error {
    my ($r, $err, $loc, $verb) = @_;
    my $class = $r->{class} || 'Error';
    print STDERR "$loc:\n";
    if ($verb) {
	print STDERR "  Rule Name:   $r->{name}\n";
	print STDERR "  Level:       $r->{level}\n";
    }
    print STDERR wrap(sprintf("  %-13s", "$class:"),
		      "               ",$err),"\n";
    if ($r->{desc} && $verb) {
	print STDERR wrap("  Details:     ","               ",$r->{desc}),"\n";
    }
    print STDERR "\n";
}

sub test_record {
    my ($r, $rec, $file, $level, $dolive, $verbose) = @_;
    if ((!exists($r->{'level'}) || $level >= $r->{'level'}) &&
	(!exists($r->{'type'}) || $rec->type eq $r->{'type'}) &&
	(!exists($r->{'live'}) || $dolive) &&
	(!exists($r->{'ruletype'}) || $r->{'ruletype'} ne 'name')) {
	my $res = $r->{'test'}->($rec, $r);
	if (ref($res) ne 'ARRAY') {
	    if ($res) {
		$res = [$res];
	    } else {
		return;
	    }
	}
	if ($#$res > -1) {
	    foreach my $result (@$res) {
		$r->print_error($result, "$file:$rec->{Line}",
				$verbose);
	    }
	}
    }
}

sub test_name {
    my ($r, $namerecord, $name, $file, $level, $dolive, $verbose) = @_;
    if ((!exists($r->{'level'}) || $level >= $r->{'level'}) &&
	(!exists($r->{'live'}) || $dolive) &&
	(exists($r->{'ruletype'}) && $r->{'ruletype'} eq 'name')) {
	my $res = $r->{'test'}->($namerecord, $r, $name);
	if (ref($res) ne 'ARRAY') {
	    if ($res) {
		$res = [$res];
	    } else {
		return;
	    }
	}
	if ($#$res > -1) {
	    foreach my $result (@$res) {
		$r->print_error($result, "$file::$name",
				$verbose);
	    }
	}
    }
}

sub config {
    my ($self, $prop, $val) = @_;
    $self->{$prop} = $val;
}

sub print_help {
    my ($self) = @_;
    return if (!$self->{'help'});
    foreach my $h (@{$self->{help}}) {
	printf STDERR wrap(sprintf("%-20s %-15s",
				   $self->{'name'}, $h->{'token'} . ":"),
			   " " x (20+15+1), $h->{'description'}) . "\n";
    }
}

sub print_description {
    my ($self) = @_;
    printf STDERR wrap(sprintf("%-40s ", $self->{'name'}),
		       " " x 41, $self->{'desc'} || "[no description]");
    print STDERR "\n\n";
}

1;

=head1 NAME

Net::DNS::SEC::Tools::Donuts::Rule - Check a DNS record for a problem.

=head1 SYNOPSIS

This class wraps around a rule definition which is used by the donuts
dns zone file checker.  It stores the data that implements a given
rule.

=head1 DESCRIPTION

Rules are defined in donuts rule configuration files using the
following syntax.  See the donuts manual page for details on where to
place those files and how to get them loaded.

=head1 RULE FILE FORMAT

Each rule file can contain multiple rules.  Each rule is composed of a
number of parts.  Minimally, it must contain a B<name> and a B<test>
portion.  Everything else is optional and/or has defaults associated
with it.  The format of a rule file is like the following example:

  name: rulename
  class: Warning
  test:
    my ($record) = @_;
    return "problem found"
      if ($record{xxx} != yyy);

Further details about each section can be found below.  Besides the
tokens below, other rule-specific data can be stored in tokens as well
and each rule is merely a hash of the above tokens as keys and the
associated data.  However, there are a few exceptions where special
tokens imply special meanings (like I<test>, I<init>, and others).
See below for details.

Each rule definition within a file should be seperated from each other
using a blank line.

Lines beginning with the '#' character will be discarded as a comment.

=over

=item name

The name of the rule.  This is mandatory, as the user may need to be
able to refer to names in the future for use with the -i flag,
specifying behaviour in configuration files, and for other uses.

By convention, all names should be specified using capital letters and
'_' characters between the words.  The left most word should give an
indication of a global category of test such as "DNSSEC", etc.  The
better named the rules are, the more power the user will have for
selecting certain types of rules via donuts' -i and other flags.

EG:

  name: DNSSEC_TEST_SOME_SECURE_FEATURE

=item level

The default level of every rule is 5.  The default level of rules
executed by donuts without a -l flag specified is also 5 (meaning no
rules above this level are run without the -l flag being specified).
Generally, more serious problems should receive lower numbers and less
serious problems should be placed at a higher number.  The maximum
value to be used should be 9 and should really be for debugging rules
only.  8 should be the maximum user-usable rule level.

  name: DNSSEC_TEST_SOME_SECURE_FEATURE
  level: 2

=item class

The class code merely indicates the type of problem.  It defaults to
"Error" and the only other value that should probably be specified
using it is "Warning".  It is displayed to the user so technically any
value could go here, but sticking to the Error/Warning convention is
probably wise as this requirement is be subject to change.

  name: DNSSEC_TEST_SOME_SECURE_FEATURE
  class: Warning

=item ruletype

Rules either fall into one of 2 types (currently): I<record> or
I<name>.  I<record> rules have their test evaluated for each record
being read from a zone file.  I<name> rules, on the other hand, get
called once per name stored in the database.  See the I<test>
description below for further details on what arguments are passed to
each rule type.

The default value for this clause is I<record>.

  name: DNSSEC_TEST_SOME_SECURE_FEATURE
  ruletype: record

=item type

Rules that test a particular type of record should specified the
I<type> field with the type of record it wants to test.  EG, if a rule
is testing a particular aspect of an MX record, it should specify MX
in this field.

  name: DNSSEC_TEST_SOME_SECURE_FEATURE
  type: MX

The rule will then not be executed except for records of that type
(this means less error checking for you in the I<test> section then).

=item init

A block of code to be excetuted immediately. This is useful for
boot-strapping where you want to perform something only once at
startup rather than per-every-rule-test-invocation.  EG, "use MODULE;"
type statements should go here.  I<init> sections contain special
formatting such as the following and the code statements appears on
the next few lines following the I<init:> line.  They B<MUST> begin
with whitespace!

  init:
    use My::Module;
    $value = calculate();

=item test

A block of code that defines the code used to test each record or name.

The test statement follows the same multi-line code specification
described in the I<init> clause above.  Specifically, the first line
follows the line with the test: token and each line of code B<MUST>
begin with whitespace!

The end result must be a subroutine reference which will be called by
the donuts program.  If when the code is evaluated it does not begin
with "sub {" then a "sub {" prefix and "}" suffix will be
automatically added to the code to turn the code-snippit into a
subroutine.

If the test fails, it should return an error string which will be
displayed for the user.  Note that the text will be line-wrapped
before display (and thus the text should not be formatted and
generally should be in english or other languages.

There are two types of tests (currently), and how the code snippit is
called depends on the ruletype clause above.

=over

=item I<record> tests

These code snippits are expected to test a single Net::DNS::RR record.

It is called with the two arguments:

  1) the record which is to be tested

  2) the rule definition itself.

=item I<name> tests

These code snippits are expected to test all the records, in some way,
associated with a given name record.

It is called with the three arguments:


  1) a hash reference to all the record types associated
     with that name (EG: 'A', 'MX', ...) and each value of
     the hash will contain an array of all the records for
     that type (IE, for names containing multiple 'A'
     records then more than one entry in the array reference
     will exist).

  2) The rule definition

  3) The record name being checked (the name associated with
     the data from 1) above).

=back

EG:

  # local rule to mandate that each record must have a
  # TTL > 60 seconds
  name: DNS_TTL_AT_LEAST_60
  level: 8
  type: record
  test:
    return "TTL too small" if ($_[0]->ttl < 60);

  # EG local policy to mandate that anything with an A record
  # must have a HINFO record too
  name: DNS_MX_MUST_HAVE_A
  level: 8
  type: name
  test:
    return "A records must have a HINFO record too"
      if (exists($_[0]{'A'}) && !exists($_[0]{'HINFO'}));

=back

=head1 COPYRIGHT

Copyright 2004 Sparta, Inc.  All rights reserved.
See the COPYING file included with the dnssec-tools package for details.

=head1 AUTHOR

Wes Hardaker <hardaker@users.sourceforge.net>

=head1 SEE ALSO

donuts, Net::DNS, Net::DNS::RR

http://dnssec-tools.sourceforge.net/

=cut

