#
# Copyright 2004-2013 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Rule;

use strict;
use Net::DNS;
use Net::DNS::SEC::Tools::Donuts::Output::Format::Text;

my $have_textwrap = eval { require Text::Wrap };
our $VERSION="2.1";

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(donuts_error donuts_status);

sub new {
    my ($class, $ref) = @_;

    # based on the rule type, eval the code 'test' string into a subroutine.
    #   - if it is already a CODE ref, let it be
    #   - if it has a sub { prefix, just eval as is
    #   - otherwise, prepend some local convenience variable names and sub {} it
    if (exists($ref->{'test'}) && ref($ref->{'test'}) ne 'CODE') {
	if ($ref->{'test'} !~ /^\s*sub\s*{/) {
	    my $code = "no strict;\n";
	    $code .=   "package main;\n";
	    $code .=   "sub {\n";

	    if(exists($ref->{'requires'})) {
		$code .= "my \$have_it;\n";
		foreach my $require (split(/\s+/, $ref->{'requires'})) {
		    $code .= "\$have_it = eval \"require $require;\";\n";
		    $code .= "if (!\$have_it) { \n";
		    $code .= "  return donuts_error('perl module \"$require\" is needed for this rule to run');\n";
		    $code .= "}\n";
		    $code .= "import $require;\n";
		}
	    }

	    if (exists($ref->{'ruletype'}) && $ref->{'ruletype'} eq 'name') {
		$code .= "  my (\$records, \$rule, \$recordname) = \@_;\n";
	    } else {
		# assume 'record' ruletype...
		$code .= "  my (\$record, \$rule) = \@_;\n";
	    }
	    $code .= "
                    $ref->{'test'}
                    }";
	    $ref->{'test'} = $code;
	}

	# create the CODE ref from the string
	$ref->{'test'} = eval("$ref->{test}");

	# if error, mention it
	if ($@) {
	    warn "broken code in test for rule '$ref->{name}': $@";
	}
    }

    bless $ref, $class;
    return $ref;
}

# XXX: deprecated
sub output {
    my $r = shift;
    if (exists($r->{'gui'})) {
	# XXX:
	foreach my $spot (qw(location rulename)) {
	    push @{$r->{'gui'}{$spot}{$r->{$spot}}}, [@_];
	}
    } elsif (exists($r->{'donuts'})) {
	if ($#_ == 0) {
	    $r->{'donuts'}->Output("$_[0]\n");
	} else {
	    my $token = shift;
	    $r->{'donuts'}->Output(sprintf("%-13s", $token) . join("", @_) . "\n");
	}
    } else {
	if ($#_ == 0) {
	    print "$_[0]\n";
	} else {
	    my $token = shift;
	    print "  ", sprintf("%-13s", $token), @_, "\n";
	}
    }
}

sub Output {
    my $r = shift;
    $r->{'donuts'}->output()->Output(@_);
}

sub ArrayObject {
    my $r = shift;
    $r->{'donuts'}->output()->ArrayObject(@_);
}

sub Separator {
    my $r = shift;
    $r->{'donuts'}->output()->Separator(@_);
}

sub StartSection {
    my $r = shift;
    $r->{'donuts'}->output()->StartSection(@_);
}

sub EndSection {
    my $r = shift;
    $r->{'donuts'}->output()->EndSection(@_);
}

sub Comment {
    my $r = shift;
    $r->{'donuts'}->output()->Comment(@_);
}

# XXX: deprecated
sub wrapit {
    my $r = shift;
    if (exists($r->{'gui'})) {
	# XXX:
	push @{$r->{'gui'}{$r->{'location'}}}, [[@_]];
    } else {
	if ($have_textwrap) {
	    $r->output(Text::Wrap::wrap(sprintf("  %-13s", $_[0]),
				       " " x 15, $_[1]) . "\n");
	} else {
	    $r->output(sprintf("  %-12s %s\n", $_[0], $_[1]));
	}
    }
}

sub output_error {
    my ($r, $err, $loc, $verb, $rrname, $record) = @_;
    my $class = $r->{class} || 'Error';

    $r->{'location'} = $loc;
    $r->{'rulename'} = $r->{name};
    $r->StartSection("$class", "$loc");
    $r->Output("Rule Type", $class);
    $r->Output("Location", $rrname) if ($rrname);
    if ($verb) {
	if ($verb >= 5) {
	    require Data::Dumper;
	    import Data::Dumper qw(Dumper);
	    $r->Output("Rule Dump", Dumper($r));
	} else {
	    $r->Output("Rule Name",  $r->{name});
	    $r->Output("Rule Level", $r->{level});
	    if ($verb >= 2) {
		$r->Output("Rule Type", $r->{'ruletype'} || 'record');
		$r->Output("Record Type", $r->{'type'}) if ($r->{'type'});
		$r->Output("Rule File", $r->{'code_file'});
		$r->Output("Rule Line", $r->{'code_line'});
	    }
	    if ($verb >= 3 && defined($record)) {
		$r->Output("Record", $record->string);
	    }
	    if ($verb >= 4) {
		$r->Output("Rule Code", $r->{'ruledef'});
	    }
	}
    }
    # print the output error, with one of 3 formatting styles
    $r->Output("Message", $err);
    $r->Output("Details", $r->{desc});
    $r->EndSection();
    $r->Separator("");
}

# Print the results of an error for a given rule
# XXX: deprecated
sub print_error {
    my ($r, $err, $loc, $verb, $rrname, $record) = @_;
    my $class = $r->{class} || 'Error';
    my $output_width=13;
    my $indent = " " x ($output_width+2);  # to account for 2 space indent
    $r->{'location'} = $loc;
    $r->{'rulename'} = $r->{name};
    $r->output("$loc:");
    $r->output("  Location:", $rrname) if ($rrname);
    if ($verb) {
	if ($verb >= 5) {
	    require Data::Dumper;
	    import Data::Dumper qw(Dumper);
	    $r->output("  Rule Dump:", Dumper($r));
	} else {
	    $r->output("  Rule Name:", $r->{name});
	    $r->output("  Level:",     $r->{level});
	    if ($verb >= 2) {
		$r->output("  Rule Type:", $r->{'ruletype'} || 'record');
		$r->output("  Record Type:", $r->{'type'}) if ($r->{'type'});
		$r->output("  Rule File:", $r->{'code_file'});
		$r->output("  Rule Line:", $r->{'code_line'});
	    }
	    if ($verb >= 3 && defined($record)) {
		$r->output("  Record:", $record->string);
	    }
	    if ($verb >= 4) {
		$r->output("  Rule Code:", $r->{'ruledef'});
	    }
	}
    }
    # print the output error, with one of 3 formatting styles
    if ($r->{'noindent'} || $r->{'gui'}) {
	$r->output("  $class:", $err);
    } elsif ($r->{'nowrap'}) {
	$err =~ s/\n/\n$indent/g;
	$r->output("  $class:", $err);
    } else {
	$r->wrapit("$class:",$err);
    }
    if ($r->{desc} && $verb) {
	if ($r->{'gui'}) {
	    $r->output("  Details:", $r->{desc});
	} else {
	    $r->wrapit("Details:", $r->{desc});
	}
    }
    $r->output("");
}

sub Error {
    my ($self, $error) = @_;
    if (exists($self->{'donuts'})) {
	$self->{'donuts'}->Error($error);
    } else {
	print STDERR $error;
    }
}

sub Status {
    my ($self, $status) = @_;
    if (exists($self->{'donuts'})) {
	$self->{'donuts'}->Status($status);
    } else {
	print STDERR $status;
    }
}

my ($current_errors, $current_warnings, $current_statuses);
sub donuts_error {
    push @$current_errors, @_;
    return;
}

sub donuts_status {
    push @$current_statuses, @_;
    return;
}

sub run_test_for_errors {
    my ($rule, $file, $testargs, $errorargs) = @_;

    $current_errors   = [];
    $current_statuses = [];

    # load the test and run it
    # (in an eval to detect crashes)
    my $res = eval {
	import Net::DNS::SEC::Tools::Donuts::Rule qw(donuts_error);

	# Set global variables needed by rules
	$main::current_domain = $rule->{'donuts'}->domain();

	$rule->{'test'}->(@$testargs);
    };

    # Did it fail to execute?  Report it
    if (!defined($res) && $@) {
	$rule->Error("\nProblem executing rule $rule->{name}: \n");
	$rule->Error("  ZoneData: $file\n");
	$rule->Error("  Location: $rule->{code_file}:$rule->{code_line}\n");
	$rule->Error("  Error:    $@\n");
	return (1,1,[]); # XXX: need to return this data instead
    }

    # pre-pend our summary statuses
    unshift @$current_errors, @$current_statuses; 

    # Create the resulting results array
    if (ref($res) ne 'ARRAY') {
	if ($res) {
	    $res = [@$current_errors, $res];
	} elsif ($#$current_errors > -1) {
	    $res = [@$current_errors];
	} else {
	    return (1,0,[]);
	}
    } elsif ($#$current_errors > -1) {
	$res = [@$current_errors, @$res];
    }
    return (1, 1 + $#$res, $res);
}

#
# Perform the same thing as run_test_for_errors, but print
# resulting errors out
#
sub run_test {
    my ($rule, $file, $testargs, $errorargs) = @_;

    my ($count1, $count2, $res) =
	$rule->run_test_for_errors($file, $testargs, $errorargs);
    if ($#$res > -1) {
	foreach my $result (@$res) {
	    $rule->output_error($result, @$errorargs);
	}
    }
    return ($count1, $count2);
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
	    my $line = $record->{Line} || "";

	    return $rule->run_test($file, [$record, $rule],
				   [$record->name, $verbose,
				    "${file}:$line", $record]);
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

	return $rule->run_test($file, [$namerecord, $rule, $name],
			       ["$name", $verbose]);
    }
    return (0,0);
}

sub config {
    my ($self, $prop, $val) = @_;
    return $self->{$prop} if (!defined($val));
    $self->{$prop} = $val;
}

sub feature_list {
    my ($self) = @_;
    return [$self->{'feature'}] if ($self->{'feature'});
}

sub help {
    my ($self) = @_;
    return $self->{'help'} || [];
}

sub print_help {
    my ($self) = @_;
    return if (!$self->{'help'});
    foreach my $h (@{$self->help()}) {
	if ($have_textwrap) {
	    $self->output(Text::Wrap::wrap(sprintf("%-20s %-15s",
						   $self->{'name'}, $h->{'token'} . ":"),
					   " " x (20+15+1), $h->{'description'}) . "\n");
	} else {
	    $self->output("%-20s %-15s %s\n",
			  $self->{'name'}, $h->{'token'} . ":",
			  $h->{'description'})
	}
    }
}

sub description {
    my ($self, $wrapifpossible) = @_;
    my $description = $self->{'desc'} || "[no description]";
    if ($wrapifpossible && $have_textwrap) {
	return Text::Wrap::wrap("  ", "  ", $description);
    }
    return $description;
}

sub name {
    my ($self) = @_;
    return $self->{'name'};
}

sub print_description {
    my ($self) = @_;
    $self->output($self->name(),"\n");
    $self->output($self->description(1));
    $self->output("\n\n");
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
I<record> rules have their test section evaluated for each record in a
zone file.  I<name> rules, on the other hand, get called once per
record name stored in the database.  See the I<test> description below
for further details on the arguments passed to each rule type.

The default value for this clause is I<record>.

Example:

  name: DNSSEC_TEST_SOME_SECURE_FEATURE
  ruletype: record

=item I<type>

Rules that test a particular type of record should specify the
I<type> field with the type of record it will test.  The rule
will only be executed for records of that type.

For example, if a rule is testing a particular aspect of an MX record,
it should specify "MX" in this field.

Example:

  name: DNSSEC_TEST_SOME_SECURE_FEATURE
  type: MX

=item I<init>

A block of code to be executed immediately as the rule is being parsed
from the rule definition file. This is useful for boot-strap code to
be performed only at start-up.  For example, perl "I<use
MODULE::NAME;>" or similar statements should be used in I<init> sections.

I<init> sections are wrapped in an XML-like syntax which
specifies the start and end of the I<init> section of code.

Example:

  <init>
    use My::Module;
    $value = calculate();
  </init>

=item I<test>

A block of code defining the test to be executed for each record or
record name.  The test statement follows the same multi-line code
specification described in the I<init> clause above.  Specifically,
all the lines between the <test> and </test> braces are considered
part of the test code.

The test contents must be a block of perl code.  If it is not in the
form of an anonymous subroutine (surrounded by "sub {" and "}"
markers), then the code will be automatically put inside a basic
subroutine block to turn it into an anonymous subroutine.

EG, the resulting code for a I<record> test will look like this:

  package main;
  no strict;
  sub
  {
    my ($record, $rule) = @_;  
    TESTCODE
  }

And for I<name> test will be:

  package main;
  no strict;
  sub
  {
    my ($records, $rule, $recordname) = @_;  
    TESTCODE
  }

(Again, this structure is only created if the I<test> definition
B<does not>b begin with "sub {" already)

When the testcode is run and the test fails, it should return an error
string which will be displayed for the user.  The text will be
line-wrapped before display (and thus should be unformatted text.)  If
the test is checking for multiple problems, a reference to an array of
error strings may be returned.  A test block that has no errors to
report should return either an empty string or a reference to an empty
array.

There are two types of tests (currently), and the test code is
called with arguments that depend on the I<ruletype> clause of the rule.
These arguments and calling conventions are as follows:

=over

=item I<record> tests

These code snippets are expected to test a single B<Net::DNS::RR> record.

It is called with two arguments:

  1) $record: The record which is to be tested

  2) $recordname: The Net::DNS::SEC::Tools::Donuts::Rule object
     reference and rule definition information.

These are bound to I<$record> and I<$rule> automatically for the test
code to use.

=item I<name> tests

These code snippets are expected to test all the records
associated with a given name record.

It is called with three arguments:

  1) $records: A hash reference to all the record types associated
     with that record name (e.g., 'example.com' might have a hash
     reference containing an entry for 'A', 'MX', ...).  Each value of
     the hash will contain an array of all the records for that type
     (for example, the hash entry for the 'A' key may contain an array
     with 2 Net::DNS::RR records, one for each A record attached to
     the 'example.com' entry).

  2) $rule: The Net::DNS::SEC::Tools::Donuts::Rule object reference
     and rule definition information.

  3) $recordname: The record name being checked (the name associated
     with the data from 1) above which might be "exmaple.com" for
     instance, or "www.example.com">).

These are bound to I<$records>, I<$rule> and I<$recordname>
automatically for the test code to use.

=back

Example rules:

  # local rule to mandate that each record must have a
  # TTL > 60 seconds
  name: DNS_TTL_AT_LEAST_60
  level: 8
  type: record
  <test>
    return "TTL for $record->{name} is too small" if ($record->ttl < 60);
  </test>

  # local policy rule to mandate that anything with an A record
  # must have an HINFO record too
  name: DNS_MX_MUST_HAVE_A
  level: 8
  type: name
  <test>
    return "$recordname has an A record but does not have an HINFO record"
      if (exists($records->{'A'}) && !exists($records->{'HINFO'}));
  </test>

=item I<feature:> B<NAME>

The feature tag prevents this rule from running unless the B<NAME>
keyword was specified using the I<--features> flag.

=item I<desc:> B<DESCRIPTION>

A short description of what the rule tests that will be printed to the
user in help output or in the error summary when B<donuts> outputs the
results.

=item I<requires:> B<PERLMODULE1> B<PERLMODULE2> ...

This allows rules to depend on installed perl modules.  They'll be
I<required> and I<imported> as the rule starts executing.  If they
don't exist, an error will be logged using donuts_error() stating that
the module is required for that rule to work.

=item I<help:> B<TOKEN:> B<TOKEN-HELP>

If the rule is configurable via the user's B<.donuts.conf> file, this
describes the configuration tokens for the user when they request
configuration help via the I<-H> or I<--help-config> flags.  Tokens may be
used within rules by accessing them using the $rule reference passed to
the code (the second argument).

Examples:

  1) In the rule file (this is an incomplete rule definition):

     name:           SOME_TEST
     myconfig:       40
     help: myconfig: A special number to configure this test
     <test>
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
however, rules may wish to self-format their outputs.  The I<nowrap>
option indicates to B<donuts> that the output is pre-formatted but
should still be indented to align with the output of the rest of the
error text (currently about 15 spaces.)  The I<noindent> tag, however,
indicates that neither wrapping nor indenting should be performed, but
that the error should be printed as is.

=back

=head1 COPYRIGHT

Copyright 2004-2013 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wes Hardaker <hardaker@users.sourceforge.net>

=head1 SEE ALSO

B<donuts(8)>

B<Net::DNS>, B<Net::DNS::RR>, B<Net::DNS::SEC::Tools::Donuts>

http://www.dnssec-tools.org/

=cut

