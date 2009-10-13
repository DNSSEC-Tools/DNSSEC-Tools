package Net::DNS::SEC::Tools::TrustAnchor::Csv;

use strict;
use Net::DNS::SEC::Tools::TrustAnchor;
use Text::CSV;

our @ISA = qw(Net::DNS::SEC::Tools::TrustAnchor);
our $VERSION = '0.1';

use XML::Simple;

sub get_extra_info {
    return {VERSION => '0.1'};
}

sub read_content {
    my ($self, $location, $options) = @_;

    $location ||= $self->{'file'};
    $options ||= $self->{'options'};

    my $csv = Text::CSV->new();
    my ($status, @columns);

    my $struct = 
      { 'delegation' => {},
      };
    my $delegation = $struct->{'delegation'};

    open(I,"$location");

    my $paramline = <I>;

    return if ($paramline !~ /^# /);  # comment required
    my $localinfo = $self->parse_extra_info_string($paramline, $struct, "#");

    # only version we support right now
    return 0 if (!defined($localinfo) || $localinfo->{'VERSION'} ne '0.1');

    while (<I>) {
	chomp();
	$status = $csv->parse($_);
	@columns = $csv->fields();
	if ($columns[1] eq 'DS') {
	    # DS record
	    push @{$delegation->{$columns[0]}{'ds'}},
	      {
	       keytag => $columns[2],
	       algorithm => $columns[3],
	       digesttype => $columns[4],
	       content => $columns[5],
	      };
	} else {
	    # DNSKEY record
	    push @{$delegation->{$columns[0]}{'dnskey'}},
	      {
	       flags => $columns[2],
	       algorithm => $columns[3],
	       digesttype => $columns[4],
	       content => $columns[5],
	      };
	}
    }
    return $struct;
}

sub get_csv {
    $_[0]->{'csv'} = Text::CSV->new() if (!exists($_[0]->{'csv'}));;
    return $_[0]->{'csv'};
}

sub write_ds {
    my ($self, $fh, $name, $record) = @_;
    my $status;
    $status = $self->get_csv()->combine($name, 'DS', $record->{'keytag'},
					$record->{'algorithm'},
					$record->{'digesttype'},
					$record->{'content'});
    $fh->print($self->get_csv()->string() . "\n");
}

sub write_dnskey {
    my ($self, $fh, $name, $record) = @_;
    my $status;
    $status = $self->get_csv()->combine($name, 'DNSKEY', $record->{'flags'},
					$record->{'algorithm'},
					$record->{'digesttype'},
					$record->{'content'});
    $fh->print($self->get_csv()->string() . "\n");
}

=pod

=cut

