# misc procedures used in multiple testing scripts

# local variables

$dt_verbose  = 0;
$dt_bail     = 0;
$dt_bail_sub = 0;

sub dt_testingtools_verbose {
  my($v) = @_;
  $dt_verbose = $v;
}

sub dt_testingtools_bail {
  my($v,$subcall) = @_;
  $dt_bail        = $v;
  $dt_bail_sub    = $subcall;
}


sub dt_do_bail {
  my ($test) = @_;
  $dt_bail_sub->() if ($dt_bail_sub);
  $test->BAIL_OUT("Unable to attempt succeeding tests for this module after a failure.");
}

sub do_is {
  my ($test, $is1, $is2, $istext) = @_;
  if (! $test->is_eq($is1, $is2, $istext) ) {
    outdiff( $is1, $is2)  if ($dt_verbose);
    &dt_do_bail($test) if ($dt_bail);
    return(0);
  }
  return(1);
}


sub do_ok {
  my ($test, $got, $expected, $outtext) = @_;
  $options{v} =1 ;
  if ( !$test->ok($got eq $expected, $outtext) ) {
    outdiff( $got, $expected)  if ($dt_verbose);
    &dt_do_bail($test) if ($dt_bail);
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
  my $total   = $#status +1;
  my $planned = $test->expected_tests;
  for (my $i=0; $i<=$#status; $i++) {
    $success++ if ($status[$i] == 1);
  }

  if ( $planned == $success ) {
    printf "$success/$total : passed/attempted: $outtext\n";
  }
  else {
    printf "$success/$total ($planned) : passed/attempted: $outtext\n";

    $outtext = uc $outtext;
    printf "$outtext:\t *** FAILED %d test(s) ***\n\n",
      ($total - $success), ($planned - $total);
  }
  print "\n";
}


sub waittime {
  my($wait, $sleeptime, $msg) = @_;
  return if( ($wait <= 0) || ($sleeptime <= 0) );
  $msg = "Waiting" if ( $msg eq "" );
  my $totwait = $wait;

  print "$msg: $totwait seconds";
  sleep $sleeptime;
  while ($wait > 0) {
    printf "\r$msg: $wait/$totwait seconds     ";
    sleep $sleeptime;
    $wait = $wait - $sleeptime;
  }
  printf "\r$msg: $totwait seconds      \n";
}



return 1;

