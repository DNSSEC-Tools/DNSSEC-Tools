#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts;

use strict;
use Net::DNS;
use Net::DNS::SEC::Tools::Donuts::Rule;
use Net::DNS::SEC::Tools::QWPrimitives;
use Net::DNS::SEC::Tools::BootStrap;
use Net::DNS::SEC::Tools::conf;
use Net::DNS::SEC::Tools::dnssectools;

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
    $self->{'featurehash'} = {};

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

