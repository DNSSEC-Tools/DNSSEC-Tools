#!/usr/bin/perl

use IO::File;
use IO::Dir;
use strict;

my $downloaddir = $ENV{'SCRIPT_FILENAME'};
$downloaddir =~ s/(.*)\/(.*)/$1/;

my $rulesfilename = "RULES";
my $orderrules = "$downloaddir/$rulesfilename";

my %stuff;
my @rules;
our @names;
my %aliases;

foreach my $i (1..9) {
    $aliases{"h" . $i} = [
	"name %s",
	"  level $i",
        "INHERIT",
	"print <a name=\"goto%s\" />",
	"print <h$i>%s</h$i>",
	];
}

our %globalvars;

#
# print http headers
#
print "Content-Type: text/html\n\n";

#
# load the RULES file
#
load_rules();

#
# open the download directory 
#
load_files($downloaddir, "");

#
# print the results as the final list we've collected
#
print_results();

sub print_results {
    #
    # run through all the rule results and display the output
    #
    my $currentLevel = 0;

    # Preliminary processing for some rule types to collect some data
    foreach my $rule (@rules) {
	if ($rule->{'type'} eq 'name') {
	    push @names, $rule;
	}
    }

    my @nameList;
    foreach my $rule (@rules) {
	my $lastversion;

	# print STUFF
	if ($rule->{'type'} eq 'print') {
	    print "$rule->{'expression'}","\n";

	# printfile FILENAME
	} elsif ($rule->{'type'} eq 'printfile') {
	    print_file($rule->{'expression'});

	# buttonbar: prints a list of toggle buttons
	} elsif ($rule->{'type'} eq 'buttonbar') {
	    print_button_bar($rule);

        # name SOMETHING
	# names a section (which puts it in a html div wrapper that the
	# buttonbar will create buttons to show/hide it).
	} elsif ($rule->{'type'} eq 'name') {
	    my $strippedName = simplify_name($rule->{'expression'});
	    my $level = get_param($rule, 'level', 1);

	    if ($currentLevel >= $level) {
		print "</div>\n" x ($currentLevel - $level + 1);
	    } elsif ($currentLevel < $level) {
		print "<div>\n" x ($level - $currentLevel - 1 );
	    }

	    print "<div class=\"dcgiDownloadName dcgiLevel$level $strippedName\">\n";
	    push @nameList, "$strippedName";
	    $currentLevel = $level;

	# global THINGY VALUE: Allow global settings that affect all the rules
	} elsif ($rule->{'type'} eq 'global') {
	    my ($left, $right) = ($rule->{'expression'} =~ (/^(\w+)\s+(.*)/));
	    $globalvars{$left} = $right;

        # list REGEXP: list a bunch of files matching a regexp
	} elsif ($rule->{'type'} eq 'list') {
	    next if ($#{$rule->{'files'}} == -1);
	    my @files = @{$rule->{'files'}};

	    my $suffixes = get_param($rule, 'suffixes');
	    my @suffixes;
	    my %newfiles;
	    if ($suffixes) {
		@suffixes = split(/,*\s+/, $suffixes);

		# process the list of suffixes to group them together
		foreach my $file (@files) {
		    my $matches = 0;
		    foreach my $suffix (@suffixes) {
			if ($file =~ /(.*)($suffix)$/) {
			    # matches a known suffix; store the base file name
			    # and the suffix to go with it
			    $newfiles{$1}{$2} = $file;
			    $matches++;
			}
		    }
		    if ($matches == 0) {
			# no suffix matches; take the whole file
			$newfiles{$file}{'__left'} = $file;
		    }
		}

		@files = keys(%newfiles);
	    }

	    # XXX: better sort here
	    if (get_param($rule, 'sortby') eq 'name') {
		@files = sort @files;
	    } elsif (get_param($rule, 'sortby') eq 'date') {
		@files = sort sort_by_date @files;
	    } else {
		@files = sort sort_version_before_package @files;
	    }

	    my $firstItem = 1;
	    my $showdates = get_param($rule, 'showdates', 0);

	    # XXX: allow other rule-defined formats
	    my $format = " <li><a href=\"%s\">%s</a>%s</li>\n";

	    my %donefile; # for catching duplicates

	    # XXX: allow other rule-defined prefix/postfixes
	    print "<ul>\n";
	    my $suffixcount = 0;
	    foreach my $file (@files) {
		my $prefix = "";
		my $version = find_version($file);
		my $count = 0;

		if (defined($lastversion) && $lastversion ne $version) {
		    if (get_param($rule, 'versionspaces')) {
			$prefix = "<br />\n";
		    }
		    if (get_param($rule, 'versionheaders')) {
			$prefix .= "</ul>\n" if (defined($lastversion));
		    }
		    if ($firstItem) {
			$prefix .= "</ul>";
			$prefix .= "<div ";
			$prefix .= "id=\"$nameList[$#nameList]OlderVersion\" "
			    if ($nameList[$#nameList] ne '');
			$prefix .= "class=\"olderVersions\"><ul>\n";
			$firstItem = 0;
		    }
		    if (get_param($rule, 'versionheaders')) {
			$prefix .= "<li>$version</li>\n<ul>\n";
		    }
		}
		$lastversion = $version;

		if ($suffixes && exists($newfiles{$file})) {
		    my $result = "<li>";
		    my $linkformat = "<a href=\"%s\">%s</a>";
		    my $firstsuffix;
		    my $allowmultiple = get_param($rule, 'allowmultiple');
		    foreach my $suffix (sort keys(%{$newfiles{$file}})) {
			$suffix = "" if ($suffix eq '__left');
			$firstsuffix = $suffix if (!defined($firstsuffix));

			# catch duplicates from bad suffix configs
			if (!$allowmultiple) {
			    next if ($donefile{"$file$suffix"});
			    $donefile{"$file$suffix"} = 1;
			}

			# kill everything up to the first /
			my $nodirfile = "$file$suffix";
			$nodirfile =~ s/.*\///;

			if ($count == 0) {
			    print $prefix;
			    $result .=
				"<span class=\"dcgiLinks\"><div class=\"dcgiFirstLink\">" .
				sprintf($linkformat, $newfiles{$file}{$suffix},
					$nodirfile);

			    if ($showdates || 0) {
				$result .= 
				    get_date_string("$downloaddir/$file$firstsuffix");
			    }

			    $result .= "</div>";

			} else {
			    $result .= "<span class=\"dcgiOtherLinks\">" if ($count == 1);
			    $result .= " <span class=\"dcgiOtherLink\">" . sprintf($linkformat, $newfiles{$file}{$suffix}, "($suffix)") . "</span>";
			    $suffixcount++;
			}
			$count++;
		    }
		    next if ($count == 0);

		    $result .= "</span>" if ($count => 1); # /dcgiOtherLinks

		    $result .= "</span>"; # /dcgiLinks

		    $result .= "</li>\n";
		    print $result;
		} else {
		    my $dateinfo = "";
		    if ($showdates) {
			$dateinfo = 
			    get_date_string("$downloaddir/$file");
		    }

		    printf($format, $file, $file);
		}
	    }
	    print "</ul>\n";
	    if (! $firstItem) {
		my $name = $nameList[$#nameList];
		print "</div>\n";
		my $suffixclass =
		    $suffixcount > 0 ? " dcgiMoreButtonAfterSuffixes" : "";
		if (defined($name) && $name ne '') {
		    print "<span class=\"dcgiMoreButton$suffixclass\" onClick=\'toggleIt(\"${name}OlderVersion\")' id=\"${name}OlderVersionMoreButton\">older...</span>\n";
		    print "<span class=\"dcgiHideButton$suffixclass\" onClick=\'toggleIt(\"${name}OlderVersion\")' id=\"${name}OlderVersionHideButton\">hide older...</span>\n";
		}
	    }
	    if (defined($lastversion) && get_param($rule, 'versionheaders')) {
		print "  </ul>\n" ;
	    }

	# ignore REGEXP: ignores a files matching a particular expression
	} elsif ($rule->{'type'} eq 'ignore') {
	    # no op

        # error: unknown rule type
	} else {
	    print STDERR "Download ERROR: unknownrule type $rule->{'type'}\n";
	}
    }
}

sub get_date_string {
    my ($file) = @_;
    my @dateinfo = localtime((stat("$file"))[9]);
    return sprintf(" <span class=\"dcgiFileDate\">(%04d-%02d-%02d)</spann>",
		   ($dateinfo[5] + 1900),
		   ($dateinfo[4] + 1),
		   ($dateinfo[3]));
}    

# find_version() works against at least these:
#   net-snmp-5.4.tar.gz
#   ne-snmp-5.4.3.tar.gz
#   n-f-5.4.3.rc1.tar.gz
#   x-y-aoeu-auoe-5.4.3.pre1.tar.gz
#   x-y-aoeu-auoe-5.4.3.pre1-4.rpm
#   x-y-aoeu-auoe-5.4.3.pre1-4.rpm
#   dnssec-tools-libs-devel-1.10-1.fc15.x86_64.rpm 

sub find_version {
    # fetches the version number out of the first (and only) argument
    my $package = $_[0];

    # strip off "word-" prefixes
    while ($package =~ s/^[a-zA-Z]\w*-//g) { }

    # find the base package version number
    my $version;
    # matches
    #  	 NUMBER
    #  	 'p'NUMBER
    #  	 'rc'NUMBER
    #  	 'pre'NUMBER
    # (plus a trailing dot or slash)
    while ($package =~ s/^((\d+|\d+p\d+|rc\d+|pre\d+)[-\.])//) {
	$version .= $1;
    }

    if ($package =~ /^\d+$/) {
	# all numbers left
	$version .= $package;
    }

    # strip off the potential trailing . or -
    $version =~ s/[-\.]$//;

    return $version;
}

# sorting version numbers by newest first
# XXX: pretty much replaced by the next one; should go away?
sub sort_versions {
    my $aroot = $a;
    my $broot = $b;
    $aroot =~ s/.(pre|rc).*//;
    $broot =~ s/.(pre|rc).*//;
    if ($aroot eq $broot) {
        return 1 if ($a =~ /\.pre/ && $b !~ /pre/); # pre-releases issued first
        return 1 if ($a =~ /\.rc/ && $b !~ /rc/); # then rc releases
    }
    return $broot <=> $aroot if (($broot <=> $aroot) != 0);
    return $broot cmp $aroot;
}

sub sort_version_before_package {
    # figure out the version part of the file name
    my ($aversion) = ($a =~ /-(\d+.*)/);
    my ($bversion) = ($b =~ /-(\d+.*)/);

    $aversion =~ s/.(pre|rc).*//;
    $bversion =~ s/.(pre|rc).*//;

    $aversion =~ s/[-.][\D].*//;
    $bversion =~ s/[-.][\D].*//;

    my $aroot = $aversion;
    my $broot = $bversion;

    $aroot =~ s/\.(pre|rc).*//;
    $broot =~ s/\.(pre|rc).*//;

    if ($aroot eq $broot) {
	# pre-releases issued first
        return 1 if ($aversion =~ /\.pre/ && $bversion !~ /pre/);
	# then rc releases
        return 1 if ($aversion =~ /\.rc/ && $bversion !~ /rc/);
    }

    my $ret = 0 - compare_parts($aversion, $bversion);
    return $ret if ($ret != 0);
    return 0 - compare_parts($aroot, $broot);
}

sub compare_parts {
    my ($left, $right) = @_;

    my ($leftmaj, $leftrest) = ($left =~ /(\d+)\.(.*)/);
    my ($rightmaj, $rightrest) = ($right =~ /(\d+)\.(.*)/);

    if (!defined($leftmaj) && !defined($rightmaj)) {
	# last digit on both sides
	return $left <=> $right;
    }

    if (!defined($leftmaj) || !defined($rightmaj)) {
	if (defined($leftmaj)) {
	    # is the last on the right greater than the next left digit?
	    if ($right > $leftmaj) {
		return -1;
	    }
	    return 1;
	}

	# is the last on the left greater than the next right digit?
	if ($left > $rightmaj) {
	    return 1;
	}
	return -1;
    }

    if ($leftmaj == $rightmaj) {
	return compare_parts($leftrest, $rightrest);
    }

    return $leftmaj <=> $rightmaj;
}

sub sort_by_date {
    return (stat($a))[1] <=> (stat($a))[0];
}

sub match_rule {
    my ($file, $subdir) = @_;

    foreach my $rule (@rules) {

	if ($rule->{'type'} eq 'list') {

	    # eval the rule's expression first to make sure it is a valid regexp
	    # (and cache the expensive regexp testing results)
	    if (!exists($rule->{'regexpok'})) {
		eval('"" =~ /' . $rule->{'expression'} . '/');
		if ($@ ne '') {
		    print STDERR "RULE Expression error: $rule->{'expression'} is an invalid regexp\n";
		    $rule->{'regexpok'} = 0;
		    return;
		} else {
		    $rule->{'regexpok'} = 1;
		}
	    } elsif (! $rule->{'regexpok'}) {
		return;
	    }

	    my $topush = "$subdir/$file";
	    $topush =~ s/^\///;
	    if ($topush =~ /$rule->{'expression'}/) {
		push @{$rule->{'files'}}, $topush;
		return;
	    }
	}
    }
    print STDERR "Download ERROR: unmatched file in download directory: $file\n";
}

sub add_rule_from_line {
    my ($line, $ruleset) = @_;

    my @ruledata = ($line =~ /^\s*(\S+)\s+(.*)/);

    # if the line begins with white-space, it's an extra parameter
    if ($line =~ /^\s+/) {
	$ruleset->[$#$ruleset]{$ruledata[0]} = $ruledata[1];
	return;
    }

    push @$ruleset, { type => $ruledata[0], expression => $ruledata[1] };
}

    

sub load_rules {
    #
    # load the RULES file
    #
    my $fileh = new IO::File $orderrules;
    if (!defined $fileh) {
	Error("Error loading the download list\n");
    }

    while(<$fileh>) {

	# skip comments and blank lines
	next if (/^\s*#/ || /^\s*$/);

	my @lines = ($_);
	my @ruledata = (/^\s*(\S+)\s+(.*)/);

	foreach (@lines) { 
	    chomp();
	    add_rule_from_line($_, \@rules);
	}
    }
    $fileh->close();

    # post-process the rules to handle alias expansion and parsing globals
    my @newrules;
    foreach my $rule (@rules) {
	if (exists($aliases{$rule->{'type'}})) {
	    # we expand this to a bunch of replacement rules.
	    foreach my $aliaspart (@{$aliases{$rule->{'type'}}}) {
		# lines marked INHERIT mean the current rule gets the additional
		# parts from the original rule
		if ($aliaspart eq 'INHERIT') {
		    foreach my $key (keys(%$rule)) {
			next if ($key eq 'type' || $key eq 'expression');
			$newrules[$#newrules]{$key} = $rule->{$key};
		    }
		} else {
		    add_rule_from_line(sprintf($aliaspart,
					       $rule->{'expression'}),
				       \@newrules);
		}
	    }
	} elsif ($rule->{'type'} eq 'global' &&
		 $rule->{'expression'} =~ /^\s*recursive\s+1\s*$/) {
	    $globalvars{'recursive'} = 1;
	} else {
	    push @newrules, $rule;
	}
    }
    @rules = @newrules;
}

sub load_files {
    my ($masterdirectory, $subdirectory) = @_;
    #
    # load the files from the master directory into the rules
    #

    my $dirh = IO::Dir->new("$masterdirectory/$subdirectory");
    if (!defined($dirh)) {
	Error("Error in Generating a Download Listing");
    }

    #
    # loop through the directory contents collecting info
    #

    my $dir;
    while (defined($dir = $dirh->read)) {
	next if ($dir =~ /^\./);
	next if ($dir eq $rulesfilename);
	next if ($dir =~ /\//); # skip / containing files (bad bad)

	# treat directories specially: decend only if recursive is turned on
	if (-d "$masterdirectory/$subdirectory/$dir") {
	    if ($globalvars{'recursive'}) {
		# decend into the subdirectory collecting more files
		load_files($masterdirectory, "$subdirectory/$dir");
	    }
	    next;
	}

	my $subversion = "&nbsp;";

	match_rule($dir, $subdirectory);

	my ($name, $ver, $type) = ($dir =~ /([^\d]+)-([-\.\drcpre]+)\.(.*)/);
	if ($ver =~ s/-([\d\.]+)//) {
	    $subversion = $1;
	}

	if ($type) {
	    $stuff{$ver}{$subversion}{$name}{$type} =
		[$dir,$subversion,$masterdirectory];
	}
    }
}

my $have_printed_toggle_it = 0;
sub print_button_bar {
    my ($rule) = @_;

    #
    # print the needed javascript component inline for the first call
    #
    if (!$have_printed_toggle_it) {
	print "<noscript>","\n";
	print "<p style=\"color: #b00;\">Warning: You are using a web browser without javascript support.  This web page will work just fine without javascript but you won't benefit from the file-selection abilities that a javascript-enabled web browser will offer.</p>\n";
	print "</noscript>","\n";

	print '<script>',"\n", '"use strict";', "\n";

	print 'function toggleIt(name, opposite, same) {
               if ( $("." + name).is(":visible") || 
                    $("#" + name).is(":visible")) {
                 $("." + name).hide(200);
                 $("#" + name).hide(200);
                 $("#" + name + "MoreButton").show(200);
                 $("#" + name + "HideButton").hide(200);
                 for(var i = 0; i < 10 ; i ++) {
                   $("#" + name + "Button" + i).css("background-color","#fff");
                 }
                 if (opposite) {
                   $("." + opposite).show(200);
                 }
                 if (same) {
                   $("." + same).hide(200);
                 }
               } else {
                 $("." + name).show(200);
                 $("#" + name).show(200);
                 $("#" + name + "MoreButton").hide(200);
                 $("#" + name + "HideButton").show(200);
                 for(var i = 0; i < 10 ; i ++) {
                   $("#" + name + "Button" + i).css("background-color","#ccf");
                 }
                 if (same) {
                   $("." + same).show(200);
                 }
               }
           };', "\n";

	print 'var doitslider = true;
               var scrolledonce = false;
           function toggleButtonBars() {
               $("#toggleButtonBarHide").animate({width: "toggle"}, 200);
               $("#toggleButtonBarShow").animate({width: "toggle"}, 200);
               $(".dcgiButtonBarContainerHideable").animate({width: "toggle"}, 200);
               scrolledonce = true; // do not allow the scroll bar to affect us
        };', "\n";

	print "</script>\n";
    }

    $have_printed_toggle_it++;
    my $ButtonName = "Button" . $have_printed_toggle_it;
    my $buttonHTML = "";

    print "<div class=\"dcgiButtonBarOuterContainer\">\n";
    $buttonHTML .=  "<div class=\"dcgiButtonBarContainer\">\n";
    my $hidebutton = get_param($rule, 'hidebutton', 'hidebutton.svg');
    my $showbutton = get_param($rule, 'showbutton', 'showbutton.svg');
    $buttonHTML .=  "<span id=\"toggleButtonBarHide\"><img class=\"hideshowbutton\" src=\"$hidebutton\" height=\"200px\"/></span>\n";
    $buttonHTML .=  "<span id=\"toggleButtonBarShow\" style=\"display: none;\"><img class=\"hideshowbutton\" src=\"$showbutton\" height=\"200px\"/></span>\n";
    $buttonHTML .=  "<span class=\"dcgiButtonBarContainerHideable\">\n";
    if ($#names == -1) {
	$buttonHTML .=  "ack, no buttons</div>\n";
	print $buttonHTML;
	return;
    }

    my %levelButtons;
    my %doneName;

    my $showFilesName = get_param($rule, 'label', "Show Files: ");
    $buttonHTML .=  "<table border=0 class=\"dcgiHideShowButtons\"><tr><td class=\"dcgiButtonBarTitle\" rowspan=\"100\">$showFilesName</td>\n";
    foreach my $name (@names) {
	next if ($doneName{$name->{'expression'}});
	$doneName{$name->{'expression'}} = 1;

	my $strippedName = simplify_name($name->{'expression'});
	$levelButtons{get_param($name, 'buttongroup',
				get_param($name, 'level', 1))} .=
	    "  <span class=\"dcgiHideShowButton\" id=\"${strippedName}$ButtonName\">$name->{expression}</span>\n";
    }

    my $startText = "";
    my $levelcount = 0;
    my $maxlevel = get_param($rule, 'maxlevel', 100);
    foreach my $levelname (sort keys %levelButtons) {
	my $label = "";
	my $levelset = $levelButtons{$levelname};
	next if ($levelset eq '');
	next if ($levelname eq 'no');
	if ($levelname =~ /^\d+$/) {
	    next if (++$levelcount > $maxlevel);
	} else {
	    $label = $levelname . ": ";
	    $label =~ s/^\d*-*//;
	}
	$buttonHTML .=  "$startText<td class=\"dcgiButtonBarSection\">$label$levelset</td><tr />\n";
	$startText = "<tr>";
    }

    $buttonHTML .=  "$startText<td class=\"dcgiButtonBarSection\"><span class=\"dcgiHideShowButton\" id=\"olderVersionsButton\">Older Versions</a></td></tr>\n";

    $buttonHTML .=  "</table>\n";

    # my $strippedName = simplify_name($name->{'expression'});
    # $levelButtons[get_param($name, 'level', 1)] .=
    # 	"  <a class=\"hideshow\" href=\"#\" id=\"${strippedName}Button\">$name->{expression}</a>\n";

    $buttonHTML .=  "</span></div>\n";
    print "</div>\n";

    print "<script>\n\"use strict\";";

    $buttonHTML =~ s/\n//g;
    print "\$(\".dcgiButtonBarOuterContainer\").html('$buttonHTML');";

    print '$(document).ready(function() {',"\n";
    print "\$(\"\#toggleButtonBarHide\").click(function() { toggleButtonBars(); });\n";
    print "\$(\"\#toggleButtonBarShow\").click(function() { toggleButtonBars(); });\n";

    foreach my $name (@names) {
	next if ($doneName{$name->{'expression'}} == 2);
	$doneName{$name->{'expression'}} = 2;

	my $strippedName = simplify_name($name->{'expression'});
	print "\$(\"\#${strippedName}$ButtonName\").click(function() { toggleIt(\"${strippedName}\"); });\n";
	if ($name->{'hide'} ||
	    ($name->{'hideunless'} &&
	     $ENV{'HTTP_USER_AGENT'} !~ /$name->{'hideunless'}/)) {
	    print "\$(\"#${strippedName}$ButtonName\").click();";
	}
    }

    print "\$(\"\#olderVersionsButton\").click(function() { toggleIt(\"olderVersions\", \"moreButton\"); });\n";
    print "\$(\".dcgiHideButton\").hide();\n";
    print "toggleButtonBars();\n"; # shouldn't be needed twice but formats better
    print "toggleButtonBars();\n";
    print "scrolledonce = false;\n";
    print "toggleIt(\"olderVersions\");";
#    print "\$(\".scrollwatch\").scroll(function() { \$(\".dcgiButtonBarOuterContainer\").html(\"replaced\"); alert(\"scrolled\"); });";
    print "\$(window).scroll(function() { 
              if (! scrolledonce) {
                  toggleButtonBars();
              }
          });";

    print "});\n";

    print "</script>\n";

}

sub simplify_name {
    my $strippedName = shift;
    $strippedName =~ s/\W//g;
    return $strippedName;
}

#
# simply copies a file to stdout
#
sub print_file {
    my ($file) = @_;
    my $fh = new IO::File $file;
    if (!$fh) {
	Error("failed to open a file");
    }
    my $buf;
    while($fh->read($buf, 4096)) {
	print $buf;
    }
}

sub get_param {
    my ($rule, $name, $default) = @_;
    return ($rule->{$name} || $globalvars{$name} || $default);
}

sub Error {
    print "<h2>", $_[0], "</h2>\n";
    print "<p>please contact an administrator</p>\n";
    exit 1;
}

=pod

=head1 NAME

download.cgi -- Organize a download directory

=head1 SYNOPSIS

RULES file example syntax:

  printfile MyHtmlTopStuff.html

  print <h2>tar files:</h2>
  list .*\.tar\.(gz|bz2)

  print <h2>zip files:</h2>
  list .*\.zip

  ignore *~

=head1 INSTALLING

Typically this can be installed by simply copying it to the directory
it should serve and renaming it to I<index.cgi>
(e.g. I</var/www/my-server/download/index.cgi>) .  Make sure to make
it B<executable> and make sure to create a I<RULES> file for it to
read.

You may need to set the I<ExecCGI> option in an apache I<.htaccess>
file or I<httpd.conf> file as well:

  Options +ExecCGI

In addition, if your server doesn't support the .cgi extension, make sure this
line is uncommented in your I<httpd.conf> file:

  AddHandler cgi-script .cgi

=head1 RULES FILE PROCESSING

The script works by first reading in the I<RULES>. file and caching the
results.  Each line is expected to be a comment (prefixed by a #), a
blank line or a configuration token (described in the next section)
followed by argument(s) to the end of the line.

The I<download.cgi> script will then read in the directory in which it
was placed and process each file according to the ordered set of rules
loaded.  The first matching rule will win and the output will be
generated based on that rule.

=head1 CREATING RULES

There are a few different types of syntax lines can go into the I<RULES> file.
Per typical configuration files, lines starting with a # will be
ignore as a comment.

Note: Configuration lines must not start with white-space, as this will be
used to add optional configuration tokens to the rules in the future
and the code already treats white-space starting lines differently.

=head2 Rule Options

Rule options can be created by prefixing a line with a white-space
character.  Thus, the following is a valid single rule definition that
adds the "versionspaces" option to the rule:

    list .*.rpm
    	versionspaces 1

=head2 Rules

=over

=item printfile FILE

The B<printefile> directive takes a single argument and simply dumps that
file out.  It's functionally equivelent to a "include" statement.

=item print TEXT

The B<print> token simply prints the rest of the line to the output page.
It is useful especially for quick header syntax above a I<list>.

=item list REGEXP

This is the real power behind the I<download.cgi> script.  This allows
you to group files in a directory by regular expression matching.  The
list will be printed using HTML <ul> and <li> style tags [future
versions will allow for a more flexible output style].

The list will be sorted by version numbers as best as possible.  The
first number after a - will be considered the start of a version
number and high version numbers will be sorted to higher in the
displayed list (so 1.7.1 will be above 1.7).  The version sorting
algorithm treats I<.preN> and I<.rcN> suffixes differently so that
1.7.1.pre1 will be sorted below 1.7.1.  [future versions will allow
for a more flexible output style].

Note: make sure you realize that a regular expression is required and
typical unix globbing is not supported (yet).  IE, "*.tar.gz" is not a
valid argument.

Extra options:

=over

=item versionspaces 1

This adds a verical space between files of different versions.  This
is most useful for grouping file sets together such as multilpe RPMs
that make up a single version set.

    list mypackage.*.rpm
    	versionspaces 1

=item versionheaders 1

This adds version headers ahead of each section with different
versions so the results look something like:

    + 1.3
      + dnssec-tools-1.3.rpm
      + dnssec-tools-libs-1.3.rpm

    + 1.2
      + dnssec-tools-1.2.rpm
      + dnssec-tools-libs-1.2.rpm

=item suffixes LIST

This binds multiple suffixes together so that all similar file types
end up on the same line.  For example, if you distribute both .tar.gz
files as well as .zip and maybe .tar.gz.md5 and .zip.md5, then the
following line:

    list mypackage.*(zip|tar.gz)
       suffixes .tar.gz .zip .tar.gz.md5 .zip.md5

Will offer all downloads on a single lien that will look roughly like:

      + dnssec-tools-1.2.tar.gz | [.zip] [.tar.gz.md5] [.zip.md5] 

(assuming all the files were available, otherwise the missing ones are
excluded)

=item showdates 1

This will add the date for the last modification time of the file.  If
this is desired for all lists, use the 'global' property to set this
globally.

=item allowmultiple 1

This means that a given file may be listed more than once in the
results output.  Normally once a file is matched, it will be marked as
"done" and not shown again even if another rule matches the same file.
This option, when set on a match, means it won't mark it so future
rules will still be able to match it.  Also, if set on a later rule
even after a previous rule marked it as done, it'll ignore the 'done'
mark and show it anyway.

=back

=item global PARAMETER VALUE

This lets you set global parameters that affect all the rules.  For
example, you can have versionspaces turned on for all rules by putting
this at the top of the file:

    global versionspaces 1
    global versionheaders 1

=item name NAME

This lets you name sections of the output for showing/hiding using the
I<buttonbar> token.

Sub-options for this include:

=over

=item recursive 1

If set to 1, sub-directories will be decended into and all matching
files in the entire directory tree will be looked for.  I<list> and
other regexps will match the whole subdirectory-to-file path (but make
sure you include proprly escaped slashes, like \/, when creating
regular expressions with path components in them).

=item level N

Each named entry will get a E<LT>divE<GT> wrapper with a CSS classname
of dcgiLevelN attached to it.  This is useful for creating hierarchical sets
of CSS-designable sections.  Deeper levels of N will nested within
higher ones.  Additionally the buttonbar entries will be grouped into
E<LT>spanE<GT> sections as well so they can be structured using CSS.

=item buttongroup NAME

If a I<buttongroup> specification exists, all the various buttons for
the button bar will be grouped under a separate NAME section (after
the level sections).  The NAME will be printed before the row of
buttons and will be printed in alphabetical order.

If the NAME is prepended with numerical digits, the group will be
sorted and printed within the normal level sets but the number will be
stripped before displaying the name.

The special buttongroup name of 'no' will hide cause the button for
that box not to be printed at all.

=item hide 1

If the hide sub-token is specified (and is non-zero) then this section
will default to being hidden.

=item hideunless STRING

This lets the entry be hidden by default unless the browser's
usage-agent matches a particular string.  This is most useful when
STRING contains things like "Linux", "Windows" and "Macintosh" so that
only sections are shown that match the operating system of the user.

=back

=item h1 TITLE, h2 TITLE, h3 TITLE, ... hN TITLE, ...

This is a convenience token that translates the results into the
equivalent of:

  name TITLE
    level N
    [any other specified options]
  print <a name="gotoTITLE" />
  print <hN>TITLE</hN>

=item buttonbar 1

This token can be placed in the output and a bar of buttons that
toggle on/off sections of the page will be created.

Because this makes use of jquery, you'll need to add a source line to
the html header for pulling in the jquery code from somewher.  Such as:

  print <script type="text/javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.6.3/jquery.min.js"></script>

=over

=item maxlevel N

If the I<maxlevel> token is applied to the buttonbar line, then no
buttons at a deth greater than N will be printed.  This is useful when
you have a big hierarchy and the buttons get too messy with all of
them showing up showing.

=item label LABEL

Sets the label printed to the left of the buttonbar.  This defaults to
"Show Files:" if not set.  To erase the label, set it to &nbsp;.

=item hidebutton URLSPEC

=item showbutton URLSPEC

These change the hide/show image src parameters of the button box to
the URL spec.  They default to 'hidebutton.svg' and 'showbutton.svg'.
Examples of these can be found in the I<examples> directory.

=back

=item ignore REGEXP

This allows files to be ignored so that error messages about unknown
files don't get printed to the web server's error log.

=head1 NOTES

This will likely only work with apache as the script expects the
SCRIPT_FILENAME environment variable to be set, which may be an
apache-ism.

The output is rather plain unless some CSS rules are applied.  See the
I<download-style.css> file in the I<example> directory for a starting
set of CSS rules to add to the results.

=head1 EXAMPLE

See the I<example> directory for an example rule set and files to test
with.  Start by looking at the RULES file.  If you want to test the
directory, place it in a web server, copy the download.cgi script into
it (I suggest naming it index.cgi so the web server will automatically
pick it up as an index) and then point your web browser at it.

=head1 TODO

The following features would be 'nice to haves:' 

 - sort by various other methods
 - URL prefix other than current
 - generic list formatting mechanism 
 - hover notes
 - caching of data for speed (based on directory modification time)

=head1 AUTHOR

Wes Hardaker E<lt>opensource AT hardakers DOT netE<gt>

=head1 COPYRIGHT and LICENSE

Copyright (c) 2010-2013 Wes Hardaker

All rights reserved.  This program is free software; you may
redistribute it and/or modify it under the same terms as Perl itself.

