# misc procedures used in multiple testing scripts

# local variables

$dt_verbose = 0;
$dt_bail    = 0;

sub dt_testingtools_verbose {
  my($v) = @_;
  $dt_verbose = $v;
}

sub dt_testingtools_bail {
  my($v) = @_;
  $dt_bail = $v;
}


sub do_is {
  my ($test, $is1, $is2, $istext) = @_;
  if (! $test->is_eq($is1, $is2, $istext) ) {
    outdiff( $is1, $is2)  if ($dt_verbose);
    $test->BAIL_OUT("Cannot complete succeeding tests after a fail.")
      if ($dt_bail);
    return(0);
  }
  return(1);
}


sub do_ok {
  my ($test, $got, $expected, $outtext) = @_;
  $options{v} =1 ;
  if ( !$test->ok($got eq $expected, $outtext) ) {
    outdiff( $got, $expected)  if ($dt_verbose);
    $test->BAIL_OUT("Cannot complete succeeding tests after a fail.")
      if ($dt_bail);
    return(0);
  }
  return(1);
}


sub outdiff {
  my ($got, $expected) = @_;
  `echo \'$expected\' > ./expected.txt`;
  `echo \'$got\' > ./got.txt`;
  my $temp = `diff -E  got.txt expected.txt`;
  print "the diff got (<) / expected (>) is:\n$temp\n\n";
}


sub summary {
  my ($test, $outtext) = @_;
  my @status = $test->summary;
  my $success = 0;
  my $total = $#status +1;
  for (my $i=0; $i<=$#status; $i++) {
    $success++ if ($status[$i] == 1);
  }
  print "$outtext: $success/$total tests passed\n";
}

return 1;

