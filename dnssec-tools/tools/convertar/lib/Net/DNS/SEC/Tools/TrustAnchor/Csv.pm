package Net::DNS::SEC::Tools::TrustAnchor::Csv;

use Net::DNS::SEC::Tools::TrustAnchor;
use Text::CSV;

our @ISA = qw(Net::DNS::SEC::Tools::TrustAnchor);
our $VERSION = '0.1';

use XML::Simple;

sub read {
    my ($self, $location, $options) = @_;

    $location ||= $self->{'file'};
    $options ||= $self->{'options'};

    my $csv = Text::CSV->new();
    my ($status, @columns);

    my $struct = 
      { 'name' => '.',
	'delegation' => {},
      };
    my $delegation = $struct->{'delegation'};

    open(I,"$location");
    while (<I>) {
	chomp();
	$status = $csv->parse($_);
	@columns = $csv->fields();
	push @{$delegation->{$columns[0]}{'ds'}},
	  {
	   keytag => $columns[2],
	   algorithm => $columns[3],
	   digesttype => $columns[4],
	   content => $columns[5],
	  };
    }
    return $struct;
}

sub write {
    my ($self, $data, $location, $options) = @_;

    my $csv = Text::CSV->new();
    my $status;

    open(O, ">$location");
    foreach my $key (keys(%{$data->{'delegation'}})) {
	foreach my $record (@{$data->{'delegation'}{$key}{'ds'}}) {
	    $status = $csv->combine($key, 'DS', $record->{'keytag'},
				    $record->{'algorithm'},
				    $record->{'digesttype'},
				    $record->{'content'});
	    print O $csv->string(),"\n";
	}
    }
    return 0;
}

=pod
