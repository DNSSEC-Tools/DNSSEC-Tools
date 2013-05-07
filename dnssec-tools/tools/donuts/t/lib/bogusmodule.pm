package bogusmodule;

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(donuts_test_func);

sub donuts_test_func {
    return 42;
}

1;
