#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts;

use strict;
use Net::DNS;
use Net::DNS::SEC::Tools::Donuts::Rule;
use Net::DNS::SEC::Tools::dnssectools;

use Net::DNS::SEC::Tools::Donuts::Output;

our $VERSION="2.1";

my $global_donuts;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(donuts_records_by_name donuts_records_by_name_and_type);

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
    $self->{'resolver'} = Net::DNS::Resolver->new if (!exists($self->{'resolver'}));
    $self->{'output'} = Net::DNS::SEC::Tools::Donuts::Output->new if (!defined($self->{'output'}));

    $self->set_global();

    return $self;
}

sub set_global {
    $global_donuts = $_[0];
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

sub rule_is_ignored {
    my ($self, $rule) = @_;
    # ignore certain rules

    foreach my $ignore (@{$self->{'ignorelist'}}) {
	if ($rule->{'name'} =~ /$ignore/) {
	    return 1;
	}
    }
    return 0;
}


#
# ignore list of rules to skip
#
sub set_only_list {
    my ($self, @list) = @_;
    $self->{'onlylist'} = \@list;
}

sub only_list {
    my ($self) = @_;
    return @{$self->{'onlylist'}};
}

sub rule_is_only {
    my ($self, $rule) = @_;
    # only certain rules

    # if no onlylist is set, every rule is ok
    return 1 if ($#{$self->{'onlylist'}} == -1);

    # otherwise only certain ones should be considered
    foreach my $only (@{$self->{'onlylist'}}) {
	if ($rule->{'name'} =~ /$only/) {
	    return 1;
	}
    }
    return 0;
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

sub create_feature_hash_from_list {
    my ($self, @list) = @_;

    $self->{'featurehash'} = {};
    foreach my $feature (@{$self->{'featurelist'}}) {
	$self->{'featurehash'}{$feature} = 1;
    }
}

sub available_features {
    my ($self) = @_;
    my @rules = $self->rules();
    my %seen_features;

    foreach my $rule (@rules) {
	my $features = $rule->feature_list();
	foreach my $feature (@$features) {
	    if (!exists($seen_features{$feature})) {
		$seen_features{$rule->{'feature'}} = 1;
	    }
	}
    }

    return keys(%seen_features);
}

#
# Output formatting and location
#
sub set_output_format {
    my ($self, $format) = @_;

    $self->{'output'}->set_format($format);
}

sub output_format {
    my ($self) = @_;
    return $self->{'output'}->format();
}

sub output {
    my ($self) = @_;
    return $self->{'output'};
}

sub set_output {
    my ($self, $output) = @_;
    $self->{'output'} = $output;
}

sub set_output_location {
    my ($self, $location, $argument) = @_;
    $self->{'output'}->set_location($location, $argument);
}

#
# Loading and manipulating rules
#

sub rules {
    my ($self) = @_;
    return @{$self->{'rules'}};
}

sub rule {
    my ($self, $rulename) = @_;
    my @extracted_rules = grep { $_->{'name'} eq $rulename; } @{$self->{'rules'}};
    return if ($#extracted_rules == -1);
    return wantarray ? @extracted_rules : $extracted_rules[0];
}

sub load_rule_files {
    my ($self, @rulelists) = @_;
    foreach my $rulelist (@rulelists) {
	foreach my $rfexp (split(/,\s*/, $rulelist)) {
	    my @rfs = glob($rfexp);
	    foreach my $rf (@rfs) {
		next if (! -f $rf || $rf =~ /.bak$/ || $rf =~ /~$/);
		$self->output()->Comment("loading rule file $rf");
		$self->output()->Comment("Rules Run:");
		if ($rf =~ /\.pl$/) {
		    do $rf;
		} else {
		    $self->parse_rule_file($rf);
		}

		$self->output()->Comment(join(" ", keys(%{$self->{'rulesByName'}})));
		$self->output()->Separator();
	    }
	}
    }
}

sub add_rule {
    my ($self, $rule) = @_;

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
	    $self->output()->Error("illegal rule in $file:$count for rule $rule->{name}");
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
    my ($self, $message, $tag) = @_;
    print STDERR $message;
}

sub Warning {
    my ($self, $message, $tag) = @_;
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

#
# Zone Loading and manipulating
#

sub clear_zone_records {
    # nuke 
    my ($self) = @_;
    $self->{'RRs'} = [];
    delete $self->{'recordByNameTypeCache'};
}

sub zone_records {
    my ($self) = @_;
    return $self->{'RRs'};
}

sub set_zone_records {
    my ($self, $rrs) = @_;
    $self->{'RRs'} = $rrs;
}

sub domain {
    my ($self) = @_;
    return $self->{'domain'};
}

sub load_zone {
    my ($self, $file, $domain) = @_;
    
    $self->{'domain'} = $domain;
    $self->{'zonesource'} = $file;
    $self->clear_zone_records();
    $self->set_global();

    my $rrset;
    my $parseerror = 0;
    if ($file =~ /^live:/) {
	$rrset = $self->query_for_live_records($domain, $file);
    } elsif ($file =~ /^afxr:/) {
	$rrset = $self->afxr_records($domain, $file);
    } else {
	$rrset = dt_parse_zonefile(file => $file,
				   origin => "$domain.",
				   soft_errors => 1,
				   #on_error =>\&print_parse_error # XXX
	    );
    }
    $self->set_zone_records($rrset);
    return $parseerror;
}

#
# Analysis - combining it all together
#
sub analyze_records {
    my ($self, $level, $verbose, $recordByNameType) = @_;
    my $firstrun = 1;
    $self->set_global();

    my @rules = $self->rules();
    my $rrset = $self->zone_records();

    my ($errorsfound, $rulesrun);
    my ($rulecount, $errcount) = (0,0);

    $self->output()->StartOutput();
    $self->output()->StartArray("Record Results");
    $self->output()->Comment("Analyzing individual records in $self->{zonesource}");

    foreach my $rec (@$rrset) {
	foreach my $r (@rules) {
	    next if ($self->rule_is_ignored($r));
	    next if (!$self->rule_is_only($r));

	    ($rulesrun, $errorsfound) =
	      $r->test_record($rec, $self->{'zonesource'},
			      $level, $self->{'featurehash'}, $verbose);
	    $errcount += $errorsfound;
	    $rulecount += $rulesrun if ($firstrun);
	}

	# allow the calling function to cache things by name/type
	if (defined($recordByNameType)) {
	    push @{$recordByNameType->{lc($rec->name)}{$rec->type}}, $rec;
	}
	$firstrun = 0;
    }

    $self->output()->EndArray();
    $self->output()->EndOutput();

    return ($rulecount, $errcount);
}

sub create_name_type_cache {
    my ($self) = @_;
    # they didn't pass in a cache structure, so we need to 
    # create it ourselves.
    my $rrset = $self->zone_records();
    
    my %recordByNameTypeCache;
    foreach my $rec (@$rrset) {
	push @{$recordByNameTypeCache{lc($rec->name)}{$rec->type}}, $rec;
    }

    return \%recordByNameTypeCache;
}

sub analyze_names {
    my ($self, $level, $verbose, $recordByNameTypeCache) = @_;
    my $firstrun = 1;
    my ($rulecount, $errcount) = (0,0);
    my @rules = $self->rules();
    $self->set_global();

    my ( $errorsfound, $rulesrun);

    $self->output()->StartOutput();
    $self->output()->StartArray("Name Results");
    $self->output()->Comment("Analyzing records for each name in $self->{zonesource}");

    if (!defined($recordByNameTypeCache)) {
	# they didn't pass in a cache structure, so we need to 
	# create it ourselves.
	$recordByNameTypeCache = $self->create_name_type_cache();
    }

    foreach my $namerec (keys(%$recordByNameTypeCache)) {
        foreach my $r (@rules) {
	    next if ($self->rule_is_ignored($r));
	    
            ($rulesrun, $errorsfound) =
              $r->test_name($recordByNameTypeCache->{$namerec}, $namerec,
                            $self->{'zonesource'},
                            $level, $self->{'featurehash'}, $verbose);
            $errcount += $errorsfound;
            $rulecount += $rulesrun if ($firstrun);
        }
        $firstrun = 0;
    }

    $self->output()->EndArray();
    $self->output()->EndOutput();

    return ($rulecount, $errcount);
}

#
# finds records from the cache using a (fqdn) name and returns just
# the "type"'s sub-array
#
sub find_records_by_name_and_type {
    my ($self, $name, $type, $recordByNameTypeCache) = @_;

    if (ref($self) ne 'Net::DNS::SEC::Tools::Donuts') {
	$self = $global_donuts;
	($name, $type, $recordByNameTypeCache) = @_;
    }
    $type = uc($type);

    my $namerecords = $self->find_records_by_name($name, $recordByNameTypeCache);
    
    if (defined($namerecords) &&
	exists($namerecords->{$type}) &&
	$#{$namerecords->{$type}} > -1) {
	return $namerecords->{$type};
    }
    return undef; # yes, this is done anyway
}

#
# finds records from the cache using a (fqdn) name
#
sub find_records_by_name {
    my ($self, $name, $recordByNameTypeCache) = @_;
    if (ref($self) ne 'Net::DNS::SEC::Tools::Donuts') {
	$self = $global_donuts;
	($name, $recordByNameTypeCache) = @_;
    }
    $name = lc($name);
    if (!$recordByNameTypeCache) {
	if (!exists($self->{'recordByNameTypeCache'}) || !defined($self->{'recordByNameTypeCache'})) {
	    $self->{'recordByNameTypeCache'} = $self->create_name_type_cache();
	}
	$recordByNameTypeCache = $self->{'recordByNameTypeCache'};
    }
    return $self->{'recordByNameTypeCache'}{$name};
}

sub donuts_records_by_name {
    find_records_by_name(@_);
}

sub donuts_records_by_name_and_type {
    find_records_by_name_and_type(@_);
}

sub analyze {
    my ($self, $level) = @_;
    $self->set_global();

    my ($rulecount, $errcount) = (0,0);

    my $verbose = $self->config('verbose') || 0;
    $level = $level || $self->config('level') || 5;

    $self->output()->StartOutput();
    $self->output()->StartSection("Donuts Results", $self->{'domain'});
    $self->output()->Output("Source", $self->{'zonesource'});
    
    my %byNameTypeCache;
    ($rulecount, $errcount) = $self->analyze_records($level, $verbose, \%byNameTypeCache);

    my ($ruleadd, $erradd) = $self->analyze_names($level, $verbose, \%byNameTypeCache);
    $rulecount += $ruleadd;
    $errcount += $erradd;

    $self->output()->EndSection();
    $self->output()->EndOutput();

    $self->{'rulecount'} = $rulecount;
    $self->{'errcount'} = $errcount;
    return ($rulecount, $errcount);
}

sub summarize_results {
    my ($self) = @_;
    my $output = $self->output();
    $output->StartOutput();
    $output->StartSection("Donuts Summary",  $self->{'domain'});
    $output->Output("Rules Considered",      scalar($self->rules()));
    $output->Output("Rules Tested",          $self->{'rulecount'});
    $output->Output("Records Analyzed",      (1+$#{$self->zone_records()}));
    $output->Output("Names Analyzed",        $self->name_count());
    $output->Output("Errors Found",          $self->{'errcount'});
    $output->EndSection();
    $output->EndOutput();
}

sub error_count {
    my ($self) = @_;
    return $self->{'errcount'};
}

sub name_count {
    my ($self) = @_;
    my @names = keys(%{$self->create_name_type_cache()});
    return $#names + 1;
}

#
# Internal resolving capability
#
sub set_resolver {
    my ($self, $resolver) = @_;
    $self->{'resolver'} = $resolver;
}

sub create_dnssec_resolver {
    my ($self) = @_;
    my $resolver = Net::DNS::Resolver->new;
    $resolver->dnssec(1);
    $resolver->cdflag(1);
}

sub resolver {
    my ($self) = @_;
    if (!$self->{'resolver'}) {
	$self->create_dnssec_resolver();
    }
    return $self->{'resolver'};
}

sub afxr_records {
    my ($self, $domain, $specification) = @_;

    my @zone = $self->{'resolver'}->axfr($domain);
    return \@zone;
}    

# Pull records from a live zone
sub query_for_live_records {

    #
    # resolve various records from the DNS directly
    #   functionally this generates a "fake zone file"
    #

    # parse the input specification
    my ($self, $domain, $specification) = @_;
    $specification =~ s/^live://;

    my @names = split(/,/,$specification);

    $self->create_dnssec_resolver();

    my @results;
    my %results;

    # do known minimal queries for a domain
    $self->resolve_something(\%results, $domain, $domain, "DNSKEY");
    $self->resolve_something(\%results, $domain, $domain, "SOA");
    $self->resolve_something(\%results, $domain, $domain, "NS");

    foreach my $rrname (@{$results{$domain}{'NS'}}) {
	# this is primarily to pull all the rrsigs for a given NS record
	#print "resolving ", $rrname->nsdname, "\n";
	$self->resolve_something(\%results, $domain, $rrname->nsdname, "A");
    }

    foreach my $name (@names) {
	my $type = "A";
	if ($name =~ s/(.*):(.*)/$1/) {
	    $type = $2;
	}
	$self->resolve_something(\%results, $domain, "$name.$domain", $type);
    }

    foreach my $name (keys(%results)) {
	foreach my $type (keys(%{$results{$name}})) {
	    push @results, @{$results{$name}{$type}};
	}
    }
    return \@results;
}

sub resolve_something {
    my ($self, $datastorage, $basedomain, $name, $type) = @_;
    my $query = $self->{'resolver'}->query("$name", $type);
    if ($query) {
	$self->get_dns_packet_records($query, $basedomain, $datastorage);
	#print "resolved $name/$type: \n";
	#debug_dump_data($datastorage);
    } else {
	if ($self->{'resolver'}->errorstring ne 'NOERROR') {
	    # XXX: handle errors better
	    $self->Error("  DNS error for $name/$type -> " . $self->{'resolver'}->errorstring . "\n");
	    #$netdns_error = $resolver->errorstring;
	    exit 1 
	}
    }
}    

sub get_dns_packet_records {
    my ($self, $query, $basedomain, $datastorage) = @_;
    
    $self->record_data($datastorage, 0, $basedomain, $query->additional);
    $self->record_data($datastorage, 0, $basedomain, $query->authority);
    $self->record_data($datastorage, 1, $basedomain, $query->answer);
}

sub record_data {
    my ($self, $datastorage, $thisdatatrumps, $basedomain, @datas) = @_;
    my %donethese;

    foreach my $data (@datas) {
	if (!exists($datastorage->{$data->name}) || $thisdatatrumps || $data->type eq 'RRSIG') {
	    if ($data->name =~ /$basedomain$/) { # only record things within the base
		if (!exists($donethese{$data->name}{$data->type}) && $data->type ne 'RRSIG') {
		    delete $datastorage->{$data->name}{$data->type};
		    $donethese{$data->name}{$data->type} = 1;
		}
		push @{$datastorage->{$data->name}{$data->type}}, $data;
	    }
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

