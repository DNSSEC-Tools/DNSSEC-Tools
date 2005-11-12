#
# Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

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
    my ($r, $err, $loc, $verb, $rrname) = @_;
    my $class = $r->{class} || 'Error';
    print STDERR "$loc:\n";
    print STDERR "  Location:    $rrname\n" if ($rrname);
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
	(!exists($r->{'live'}) || $dolive) &&
	(!exists($r->{'ruletype'}) || $r->{'ruletype'} ne 'name')) {

	# this is a legal rule for this run.

	if (!exists($r->{'type'}) || $rec->type eq $r->{'type'}) {

	    # and the type matches

	    my $res = $r->{'test'}->($rec, $r);
	    if (ref($res) ne 'ARRAY') {
		if ($res) {
		    $res = [$res];
		} else {
		    return (1,0);
		}
	    }
	    if ($#$res > -1) {
		foreach my $result (@$res) {
		    $r->print_error($result, $rec->name,
				    $verbose, "$file:$rec->{Line}");
		}
		return (1,$#$res+1);
	    }
	}
	
	# it was a legal rule, so we count it but no errors
	return (1,0);
    }

    # rule will never be run with current settings (and no errors).
    return (0,0);
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
		return (1,0);
	    }
	}
	if ($#$res > -1) {
	    foreach my $result (@$res) {
		$r->print_error($result, "$file::$name",
				$verbose);
	    }
	    return (1,$#$res+1);
	}
	return (1,0);
    }
    return (0,0);
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
    print STDERR $self->{'name'},"\n";
    print STDERR wrap("  ", "  ", $self->{'desc'} || "[no description]");
    print STDERR "\n\n";
}

1;

=pod

=head1 NAME

  Net::DNS::SEC::Tools::Donuts::Rule - Define donuts DNS record-checking rules

=head1 DESCRIPTION

This class wraps around a rule definition which is used by the I<donuts>
DNS zone file checker.  It stores the data that implements a given rule.

Rules are defined in I<donuts> rule configuration files using the
following syntax.  See the I<donuts> manual page for details on where to
place those files and how to get them loaded.

=head1 RULE FILE FORMAT

Each rule file can contain multiple rules.  Each rule is composed of a
number of parts.  Minimally, it must contain a B<name> and a B<test>
portion.  Everything else is optional and/or has defaults associated
with it.  The rule file format follows this example:

  name: rulename
  class: Warning
  test:
    my ($record) = @_;
    return "problem found"
      if ($record{xxx} != yyy);

Further details about each section can be found below.  Besides the
tokens below, other rule-specific data can be stored in also tokens
and each rule is a hash of the above tokens as keys and their
associated data.  However, there are a few exceptions where special
tokens imply special meanings.  These special tokens include I<test>,
I<init>.  See below for details.

Each rule definition within a file should be separated using a blank line.

Lines beginning with the '#' character will be discarded as a comment.

=over

=item I<name>

The name of the rule.  This is mandatory, as the user may need to be
able to refer to names in the future for use with the I<-i> flag,
specifying behavior in configuration files, and for other uses.

By convention, all names should be specified using capital letters and
'_' characters between the words.  The leftmost word should give an
indication of a global category of test, such as "DNSSEC".  The
better-named the rules, the more power the user will have for
selecting certain types of rules via I<donuts -i> and other flags.

Example:

  name: DNSSEC_TEST_SOME_SECURE_FEATURE

=item I<level>

The rule's execution level, as recognized by I<donuts>.  Only those
rules at or above I<donuts>' current execution level will be run by
I<donuts>.  The execution level is specified by the I<-l> option to
I<donuts>; if not given, then the default execution level is 5.

The default I<level> of every rule is 5.

Generally, more serious problems should receive lower numbers and
less serious problems should be placed at a higher number.  The
maximum value is 9, which is reserved for debugging rules only.
8 is the maximum rule level that user-defined rules should use.

Example:

  name: DNSSEC_TEST_SOME_SECURE_FEATURE
  level: 2

=item I<class>

The I<class> code indicates the type of problem associated with the
rule.  It defaults to "I<Error>", and the only other value that should
be used is "I<Warning>".

This value is displayed to the user.  Technically, any value could be
specified, but using anything other than I<Error>/I<Warning> convention
could break portability in future versions.

Example:
  name: DNSSEC_TEST_SOME_SECURE_FEATURE
  class: Warning

=item I<ruletype>

Rules fall into one of two types (currently): I<record> or I<name>.
I<record> rules have their test evaluated for each record being in
a zone file.  I<name> rules, on the other hand, get called once per
name stored in the database.  See the I<test> description below for
further details on the arguments passed to each rule type.

The default value for this clause is I<record>.

Example:

  name: DNSSEC_TEST_SOME_SECURE_FEATURE
  ruletype: record

=item I<type>

Rules that test a particular type of record should specify the
I<type> field with the type of record it wants to test.  The rule
will only be executed for records of that type.  This will result
in less error checking for the user in the I<test> section.

For example, if a rule is testing a particular aspect of an MX record,
it should specify MX in this field.

Example:

  name: DNSSEC_TEST_SOME_SECURE_FEATURE
  type: MX

=item I<init>

A block of code to be executed immediately. This is useful for
boot-strap code to be performed only at start-up, rather than
at every rule-test invocation.  For example, "use MODULE;"
type statements should be used in I<init> sections.

I<init> sections contain special formatting such as the following.
The code lines B<MUST> begin with whitespace.

Example:

  init:
    use My::Module;
    $value = calculate();

=item I<test>

A block of code that defining the test for each record or name.
The test statement follows the same multi-line code specification
described in the I<init> clause above.  Specifically, the first line
follows the line with the I<test:> token and each line of code B<MUST>
begin with whitespace.

The end result must be a subroutine reference which will be called by
the I<donuts> program.  When the code is evaluated, if it does not
begin with "sub {" then a "sub {" prefix and "}" suffix will be
automatically added to the code to turn the code-snippet into a
subroutine.

If the test fails, it should return an error string which will be displayed
for the user.  The text will be line-wrapped before display (and thus should
be unformatted text.)  If the test is testing for multiple problems, a
reference to an array of error strings may be returned.  A reference to an
empty array being returned also indicates no error.

There are two types of tests (currently), and the code snippet is
called depending on the I<ruletype> clause above.

=over

=item I<record> tests

These code snippets are expected to test a single B<Net::DNS::RR> record.

It is called with two arguments:

  1) the record which is to be tested

  2) the rule definition itself.

=item I<name> tests

These code snippets are expected to test all the records
associated with a given name record.

It is called with three arguments:

  1) a hash reference to all the record types associated
     with that name (e.g., 'A', 'MX', ...) and each value of
     the hash will contain an array of all the records for
     that type (i.e., for names containing multiple 'A'
     records then more than one entry in the array reference
     will exist).

  2) The rule definition

  3) The record name being checked (the name associated with
     the data from 1) above).

=back

Examples:

  # local rule to mandate that each record must have a
  # TTL > 60 seconds
  name: DNS_TTL_AT_LEAST_60
  level: 8
  type: record
  test:
    return "TTL too small" if ($_[0]->ttl < 60);

  # local policy to mandate that anything with an A record
  # must have a HINFO record too
  name: DNS_MX_MUST_HAVE_A
  level: 8
  type: name
  test:
    return "A records must have a HINFO record too"
      if (exists($_[0]{'A'}) && !exists($_[0]{'HINFO'}));

=back

=head1 COPYRIGHT

Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wes Hardaker <hardaker@users.sourceforge.net>

=head1 SEE ALSO

B<donuts(8)>

B<Net::DNS>, B<Net::DNS::RR>

http://dnssec-tools.sourceforge.net

=cut

