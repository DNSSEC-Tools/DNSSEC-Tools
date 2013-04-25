#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts;

use strict;
use Net::DNS;
use Net::DNS::SEC::Tools::Donuts::Rule;

my $have_textwrap = eval { require Text::Wrap };
our $VERSION="2.1";

#require Exporter;
#our @ISA = qw(Exporter);
#our @EXPORT = qw();

sub new {
    my $type = shift;
    my ($class) = ref($type) || $type;
    my $self = {};
    %$self = @_;
    bless($self, $class);

    # set some defaults:
    $self->{'ignorelist'} = [];
    $self->{'featurelist'} = [];
    $self->{'rules'} = [];
    $self->{'rulesByName'} = {};
    $self->{'featurehash'} = {};
    $self->{'config'} = {};

    # XXX: only really needed if 'live' is enabled
    $self->{'resolver'} = Net::DNS::Resolver->new;

    return $self;
}

#
# ignore list of rules to skip
#
sub set_ignore_list {
    my ($self, @list) = @_;
    $self->{'ignorelist'} = \@list;
}

sub ignore_list {
    my ($self) = @_;
    return @{$self->{'ignorelist'}};
}

#
# feature lists/hashes
#
sub set_feature_list {
    my ($self, @list) = @_;
    $self->{'featurelist'} = \@list;
    $self->create_feature_hash_from_list();
}

sub feature_list {
    my ($self) = @_;
    return @{$self->{'featurelist'}};
}

sub enable_features {
    my ($self, @list) = @_;
    foreach my $feature (@list) {
	if (!exists($self->{'featurehash'}{$feature})) {
	    $self->{'featurehash'}{$feature} = 1;
	    push @{$self->{'featurelist'}}, $feature;
	}
    }
}

sub create_feature_hash_from_list {
    my ($self, @list) = @_;

    $self->{'featurehash'} = {};
    foreach my $feature (@{$self->{'featurelist'}}) {
	$self->{'featurehash'}{$feature} = 1;
    }
}

#
# Loading and manipulating rules
#

sub rules {
    my ($self) = @_;
    return @{$self->{'rules'}};
}

sub load_rule_files {
    my ($self, @rulelists) = @_;
    foreach my $rulelist (@rulelists) {
	foreach my $rfexp (split(/,\s*/, $rulelist)) {
	    my @rfs = glob($rfexp);
	    foreach my $rf (@rfs) {
		next if (! -f $rf || $rf =~ /.bak$/ || $rf =~ /~$/);
		$self->Verbose("--- loading rule file $rf\n    rules:");
		if ($rf =~ /\.pl$/) {
		    do $rf;
		} else {
		    $self->parse_rule_file($rf);
		}
		$self->Verbose("\n");
	    }
	}
    }
}

sub add_rule {
    my ($self, $rule) = @_;

    # ignore certain rules

    foreach my $ignore (@{$self->{'ignorelist'}}) {
	if ($rule->{'name'} =~ /$ignore/) {
	    return;
	}
    }

    # merge in default values
    my %defaultrule = ( level => 5 );
    foreach my $key (keys(%defaultrule)) {
	$rule->{$key} = $defaultrule{$key} if (!exists($rule->{$key}));
    }

    # check rule validity for required fields
    if (!$rule->{'name'}) {
	$self->Warning("no name for a rule in file '$rule->{name}' rule\n");
    }
    if (!$rule->{'test'}) {
	$self->Warning("no test defined for the '$rule->{name}' rule\n");
    }

    $self->Verbose(" $rule->{'name'}");

    #if ($opts{'show-gui'}) {
    #	$rule->{'gui'} = \%outstructure; #XXX
    #}

    # remember the rule and have it remember us
    $rule->{'donuts'} = $self;
    $rule = new Net::DNS::SEC::Tools::Donuts::Rule($rule);
    push @{$self->{'rules'}}, $rule;
    $self->{'rulesByName'}{$rule->{name}} = $rule;
}

# parses a text based rule file
sub parse_rule_file {
    my ($self, $file) = @_;

    my ($rule, $err);
    open(RF, $file); #XXX use IO::File
    my $nextline;
    my $count;
    my $ruledef;

    $err = 0;
    while (($_ = $nextline) || ($_ = <RF>)) {
	$nextline = undef;
	$count++;
	next if (/^\s*#/);

	$ruledef .= $_;

	# deal with multi-line records
	if (/(<|)(test|init)(>|:)/) {
	    my $type = $2;
	    my $xmllike = 0;
	    $xmllike = 1 if ($1 eq '<');

	    # collect code
	    my $code;
	    while (<RF>) {
		# rule code must begin with white space
		$count++;
		last if ((!$xmllike && (!/^\s/ || /^\s*$/)) ||
			 ($xmllike && /<\/(test|init)>/));
		$code .= $_;
		$ruledef .= $_;
	    }
	    $ruledef .= $_ if (defined($_));

	    # evaluate it
	    if ($type eq 'init') {
		eval("$code");
		# if error, mention it
		if ($@) {
		    warn "broken code in $file:$count rule '$rule->{name}': $@";
		    $self->Verbose("IN CODE:\n  $code\n");
		    $err = 1;
		}
	    } else {
		$rule->{'test'} = $code;
	    }

	    if (defined($_) && !/^\s/ && !/<\/(test|init)/) {
		$count--;
		$nextline = $_;
	    }
	} elsif (/^\s*help:\s*(\w+):\s*(.*)/) {
	    push @{$rule->{'help'}}, { token => $1, description => $2 };
	} elsif (/^\s*(\w+):\s*(.*\S)\s*$/) {
	    $rule->{$1} = $2;
	} elsif (!/^\s*$/) {
	    print STDERR "illegal rule in $file:$count for rule $rule->{name}";
	}

	if ($rule && !exists($rule->{'code_file'})) {
	    $rule->{'code_file'} = $file;
	    $rule->{'code_line'} = $count;
	}

	# end of rule (can get here from inside a test end too, hence
	# not an else clause above)
	if (!defined($_) || /^\s*$/) {
	    if ($rule && !$err) {
		$rule->{'ruledef'} = $ruledef;
		$ruledef = '';
		$self->add_rule($rule);
	    }
	    $rule = undef;
	    $err = 0;
	}
    }
    if ($rule && !$err) {
	$rule->{'ruledef'} = $ruledef;
	$self->add_rule($rule);
    }
}


#
# configuration objects
#
sub set_config {
    my ($self, $name, $value) = @_;

    $self->{'config'}{$name} = $value;
}

sub config {
    my ($self, $name) = @_;

    return if (!exists($self->{'config'}{$name}));
    return $self->{'config'}{$name};
}

sub parse_config_file {
    my ($self, $file) = @_;

    open(I,$file);
    my $line;
    my $name;
    while (<I>) {
	$line++;
	next if (/^\s*#/);
	if (/^\s*$/) {
	    $name = undef;
	    next;
	}
	if (/^name:\s*(.*)/) {
	    $name = $1;
	    if (!exists($self->{'rulesByName'}{$name})) {
		$self->Warning("Warning in $file at $line: no such rule: $name\n");
	    }
	    next;
	}
	if (!$name) {
	    close(I);
	    $self->Error("Error in $file at line $line: no rule name found yet\n");
	    exit;
	}
	if (/^(test|init):/) {
	    close(I);
	    $self->Error("Error in $file at line $line: Illegal token in config file.\n");
	    exit;
	}
	if (!/^(\w+):\s*(.*)$/) {
	    close(I);
	    $self->Error("Error in $file at line $line: Illegal definition.\n");
	    exit;
	}
	if (exists($self->{'rulesByName'}{$name})) {
	    $self->{'rulesByName'}{$name}->config($1, $2);
	}
    }
}

#
# base warning/error/verbose/output functions
#
sub Error {
    my ($self, $message) = @_;
    print STDERR $message;
}

sub Warning {
    my ($self, $message) = @_;
    print STDERR $message;
}

sub Verbose {
    my ($self, $message, $level) = @_;
    if ($self->config('verbose')) {
	if (!defined($level) || $level >= $self->config('verbose')) {
	    print $message;
	}
    }
}

1;

=pod

=head1 NAME

  Net::DNS::SEC::Tools::Donuts - Execute DNS and DNSSEC lint-like tests on zone data

=head1 DESCRIPTION

=back

=head1 COPYRIGHT

Copyright 2013-2013 Parsons.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wes Hardaker <hardaker@users.sourceforge.net>

=head1 SEE ALSO

B<donuts(8)>

B<Net::DNS>, B<Net::DNS::RR>, B<Net::DNS::SEC::Tools::Donuts::Rule>

http://www.dnssec-tools.org/

=cut

