#
# Copyright 2004-2007 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Rule;

use strict;
use Net::DNS;
my $have_textwrap = eval { require Text::Wrap };
our $VERSION="1.0";

sub new {
    my ($class, $ref) = @_;
    bless $ref, $class;
    return $ref;
}

sub output {
    my $r = shift;
    if (exists($r->{'gui'})) {
	# XXX:
	foreach my $spot (qw(location rulename)) {
	    push @{$r->{'gui'}{$spot}{$r->{$spot}}}, [@_];
	}
    } else {
	if ($#_ == 0) {
	    print STDERR "$_[0]\n";
	} else {
	    my $token = shift;
	    print STDERR "  ", sprintf("%-13s", $token), @_, "\n";
	}
    }
}

sub wrapit {
    my $r = shift;
    if (exists($r->{'gui'})) {
	# XXX:
	push @{$r->{'gui'}{$r->{'location'}}}, [[@_]];
    } else {
	if ($have_textwrap) {
	    print STDERR Text::Wrap::wrap(sprintf("  %-13s", $_[0]),
					  " " x 15, $_[1]),"\n";
	} else {
	    printf STDERR ("  %-12s %s\n", $_[0], $_[1]);
	}
    }
}


# Print the results of an error for a given rule
sub print_error {
    my ($r, $err, $loc, $verb, $rrname) = @_;
    my $class = $r->{class} || 'Error';
    my $output_width=13;
    my $indent = " " x ($output_width+2);  # to account for 2 space indent
    $r->{'location'} = $loc;
    $r->{'rulename'} = $r->{name};
    $r->output("$loc:");
    $r->output("Location:", $rrname) if ($rrname);
    if ($verb) {
	$r->output("Rule Name:", $r->{name});
	$r->output("Level:",     $r->{level});
    }
    # print the output error, with one of 3 formatting styles
    if ($r->{'noindent'} || $r->{'gui'}) {
	$r->output("$class:", $err);
    } elsif ($r->{'nowrap'}) {
	$err =~ s/\n/\n$indent/g;
	$r->output("$class:", $err);
    } else {
	$r->wrapit("$class:",$err);
    }
    if ($r->{desc} && $verb) {
	if ($r->{'gui'}) {
	    $r->output("Details:", $r->{desc});
	} else {
	    $r->wrapit("Details:", $r->{desc});
	}
    }
    $r->output("");
}

sub test_record {
    my ($rule, $record, $file, $level, $features, $verbose) = @_;
    if ((!exists($rule->{'level'}) || $level >= $rule->{'level'}) &&
	(!exists($rule->{'feature'}) ||
	 exists($features->{$rule->{'feature'}})) &&
	(!exists($rule->{'ruletype'}) || $rule->{'ruletype'} ne 'name')) {

	# this is a legal rule for this run.

	if (!exists($rule->{'type'}) || $record->type eq $rule->{'type'}) {

	    # and the type matches

	    $rrule = $rule;
	    my $res = eval { $rule->{'test'}->($record, $rule); };
	    if (!defined($res) && $@) {
		print STDERR "\nProblem executing rule $rule->{name}: \n";
		print STDERR "  Record:   " . $record->name . " -- (" 
		  . ref($record) . ")\n";
		print STDERR "  Location: $file:$record->{Line}\n\n";
		print STDERR "  Error:    $@\n";
		return (0,0);
	    }
	    if (ref($res) ne 'ARRAY') {
		if ($res) {
		    $res = [$res];
		} else {
		    return (1,0);
		}
	    }
	    if ($#$res > -1) {
		foreach my $result (@$res) {
		    $rule->print_error($result, $record->name,
				       $verbose, "$file:$record->{Line}");
		}
		return (1,$#$res+1);
	    }
	}
	
	# it was a legal rule, so we count it but no errors
	return (1,0);
    }

    # rule will never be run with current settings (and no errors.)
    return (0,0);
}

sub test_name {
    my ($rule, $namerecord, $name, $file, $level, $features, $verbose) = @_;
    if ((!exists($rule->{'level'}) || $level >= $rule->{'level'}) &&
	(!exists($rule->{'feature'}) ||
	 exists($features->{$rule->{'feature'}})) &&
	(exists($rule->{'ruletype'}) && $rule->{'ruletype'} eq 'name')) {
	my $res = $rule->{'test'}->($namerecord, $rule, $name);
	if (ref($res) ne 'ARRAY') {
	    if ($res) {
		$res = [$res];
	    } else {
		return (1,0);
	    }
	}
	if ($#$res > -1) {
	    foreach my $result (@$res) {
		$rule->print_error($result, "$file::$name",
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
	if ($have_textwrap) {
	    printf STDERR 
	      Text::Wrap::wrap(sprintf("%-20s %-15s",
				       $self->{'name'}, $h->{'token'} . ":"),
			       " " x (20+15+1), $h->{'description'}) . "\n";
	} else {
	    printf STDERR ("%-20s %-15s %s\n",
			   $self->{'name'}, $h->{'token'} . ":",
			     $h->{'description'})
	}
    }
}

sub print_description {
    my ($self) = @_;
    print STDERR $self->{'name'},"\n";
    if ($have_textwrap) {
	print STDERR Text::Wrap::wrap("  ", "  ", $self->{'desc'} || "[no description]");
    } else {
	print STDERR "  " . ($self->{'desc'} || "[no description]");
    }
    print STDERR "\n\n";
}

1;

=pod

=head1 NAME

  Net::DNS::SEC::Tools::Donuts::Rule - Define donuts DNS record-checking rules

=head1 DESCRIPTION

This class wraps around a rule definition which is used by the B<donuts>
DNS zone file checker.  It stores the data that implements a given rule.

Rules are defined in B<donuts> rule configuration files using the
following syntax.  See the B<donuts> manual page for details on where to
place those files and how to load them.

=head1 RULE FILE FORMAT

Each rule file can contain multiple rules.  Each rule is composed of a
number of parts.  Minimally, it must contain a B<name> and a B<test>
portion.  Everything else is optional and/or has defaults associated
with it.  The rule file format follows this example:

  name: rulename
  class: Warning
  <test>
    my ($record) = @_;
    return "problem found"
      if ($record{xxx} != yyy);
  </test>

Further details about each section can be found below.  Besides the
tokens below, other rule-specific data can be stored in tokens
and each rule is a hash of the above tokens as keys and their
associated data.  However, there are a few exceptions where special
tokens imply special meanings.  These special tokens include I<test>
and I<init>.  See below for details.

Each rule definition within a file should be separated using a blank line.

Lines beginning with the '#' character will be discarded as a comment.

=over

=item I<name>

The name of the rule.  This is mandatory, as the user may need to
refer to names in the future for use with the I<-i> flag,
specifying behavior in configuration files, and for other uses.

By convention, all names should be specified using capital letters and
'_' characters between the words.  The leftmost word should give an
indication of a global test category, such as "DNSSEC".  The
better-named the rules, the more power the user will have for
selecting certain types of rules via B<donuts -i> and other flags.

Example:

  name: DNSSEC_TEST_SOME_SECURE_FEATURE

=item I<level>

The rule's execution level, as recognized by B<donuts>.  B<donuts> will
run only those rules at or above B<donuts>' current execution level.
The execution level is specified by the I<-l> option to
B<donuts>; if not given, then the default execution level is 5.

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
specified, but using anything other than the I<Error>/I<Warning>
convention could break portability in future versions.

Example:
  name: DNSSEC_TEST_SOME_SECURE_FEATURE
  class: Warning

=item I<ruletype>

Rules fall into one of two types (currently): I<record> or I<name>.
I<record> rules have their test evaluated for each record in
a zone file.  I<name> rules, on the other hand, get called once per
name stored in the database.  See the I<test> description below for
further details on the arguments passed to each rule type.

The default value for this clause is I<record>.

Example:

  name: DNSSEC_TEST_SOME_SECURE_FEATURE
  ruletype: record

=item I<type>

Rules that test a particular type of record should specify the
I<type> field with the type of record it will test.  The rule
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
at every rule-test invocation.  For example, "I<use MODULE;>"
type statements should be used in I<init> sections.

I<init> sections are wrapped in an XML-like syntax which
specifies the start and end of the I<init> section of code.

Example:

  <init>
    use My::Module;
    $value = calculate();
  </init>

=item I<test>

A block of code defining the test for each record or name.  The
test statement follows the same multi-line code specification
described in the I<init> clause above.  Specifically, all the lines
between the <test> and </test> braces are considered part of the test
code.

The end result must be a subroutine reference which will be called by
the B<donuts> program.  When the code is evaluated, if it does not
begin with "sub {" then a "sub {" prefix and "}" suffix will be
automatically added to the code to turn the code-snippet into a
Perl subroutine.

If the test fails, it should return an error string which will be displayed
for the user.  The text will be line-wrapped before display (and thus should
be unformatted text.)  If the test is checking for multiple problems, a
reference to an array of error strings may be returned.  A return value of a
reference to an empty array also indicates no error.

There are two types of tests (currently), and the code snippet is
called with arguments which depend on the I<ruletype> clause above.
These arguments and calling conventions are as follows:

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
     that type.  (I.e., more than one entry in the array
     reference will exist for names containing multiple 'A'
     records.)

  2) The rule definition.

  3) The record name being checked (the name associated with
     the data from 1) above.)

=back

Examples:

  # local rule to mandate that each record must have a
  # TTL > 60 seconds
  name: DNS_TTL_AT_LEAST_60
  level: 8
  type: record
  <test>
    return "TTL too small" if ($_[0]->ttl < 60);
  </test>

  # local policy to mandate that anything with an A record
  # must have an HINFO record too
  name: DNS_MX_MUST_HAVE_A
  level: 8
  type: name
  <test>
    return "A records must have an HINFO record too"
      if (exists($_[0]{'A'}) && !exists($_[0]{'HINFO'}));
  </test>

=item I<feature:> B<NAME>

The feature tag prevents this rule from running unless the B<NAME>
keyword was specified using the I<--features> flag.

=item I<desc:> B<DESCRIPTION>

A short description of what the rule tests that will be printed to the
user in help output or in the error summary when B<donuts> outputs the
results.

=item I<help:> B<TOKEN:> B<TOKEN-HELP>

If the rule is configurable via the user's B<.donuts.conf> file, this
describes the configuration tokens for the user when they request
configuration help via the I<-H> or I<--help-config> flags.  Tokens may be
used within rules by accessing them within the rule argument passed to
the code (the second argument.)

Example:

  1) In the rule file (this is an incomplete definition):

     name:           SOME_TEST
     myconfig:       40
     help: myconfig: A special number to configure this test
     <test>
      my ($record, $rule) = @_;
      # ... use $rule->{'myconfig'}
     </test>

  2) This allows the user to change the value of myconfig via their
     .donuts.conf file:

     # change SOME_TEST config...
     name:     SOME_TEST
     myconfig: 40

  3) and running donuts -H will show the help line for myconfig.

=item I<noindent: 1>

=item I<nowrap: 1>

Normally B<donuts> will line-wrap the error summary produced by a rule
to enable automatic pretty-printing of error results.  Sometimes,
however, rules may not want this.  The I<nowrap> option indicates to
B<donuts> that the output is pre-formatted but should still be indented
to align with the output of the rest of the error text (currently about
15 spaces.)  The I<noindent> tag, however, indicates that neither
wrapping nor indenting should be performed, but that the error should
be printed as is.

=back

=head1 COPYRIGHT

Copyright 2004-2007 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wes Hardaker <hardaker@users.sourceforge.net>

=head1 SEE ALSO

B<donuts(8)>

B<Net::DNS>, B<Net::DNS::RR>

http://dnssec-tools.sourceforge.net

=cut

