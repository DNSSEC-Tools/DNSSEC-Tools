			     DNSSEC-Tools
			Is your domain secure?

# Overview

The goal of the DNSSEC-Tools project is to create a set of tools,
patches, applications, wrappers, extensions, and plugins that will
help ease the deployment of DNSSEC-related technologies.

# About The Tools

For more information about this project and the tools that are being
developed and provided, please see our project web page at:

  http://www.dnssec-tools.org/

# Installation

Most of the tools, perl modules, and other things described on the
web page above are easily installed by following the instructions in
the INSTALL file.  However, some of the results of this package are
patches to external programs that will hopefully be fed back into
those projects where possible.  In the meantime, there are patches
included within this source tree that can be applied to those other
projects.

# Contents Description

The various pieces of the DNSSEC-Tools project are spread across several
directories.  These pieces are briefly described here.

Most of the tools take a --version flag to let you know their
individual version number.  The numbers reported will be < 0.9 if
they're to be considered "alpha" quality.  If >= 0.9 and < 1.0 then
they should be considered "beta".  Version numbers of 1.0 and above
should be considered more well-tested, robust and less likely to
change.

##  Tools:

### tools/scripts
Perl scripts for signing DNSSEC zones and maintaining
those signed zones.  See the tools/scripts/README file
for details.  The vast majority of the useful
DNSSEC-Tools scripts (like zonesigner) are contained
in this directory.

### validator/apps/validate
A tool which can display the sequence of queries and
their results used to validate a DNS query.  The
stderr output of this command can serve as input to
the drawvalmap tool described below.

### tools/donuts
A dnssec aware zone file checker / lint-like application.

### tools/donutsd
Runs donuts on zone files on a regular bases (eg,
daily) and emails the results.  Useful for knowing
when zone data breaks due to DNSSEC signatures
expiring or other data consistency issues).

### tools/logwatch
Patches to logwatch configuration files and scripts to
manage log files for BIND security function.  These
patches are now included in the recent releases of
logwatch and may not be needed if you have a recent
release.

### tools/dnspktflow
A tool which can produce visual diagrams of DNS
traffic flows which have been captured using tcpdump.

### tools/mapper
A tool that can generate graphical maps of DNS zones,
including color coding of DNSSEC related data.

### tools/modules
DNSSEC-Tools Perl modules.  These modules provide interfaces
for such things as reading configuration files and manipulating
DNSSEC-Tools-specific data.

### tools/modules/Net-DNS-SEC-Validator
A perl module wrapper around the libval library.

### tools/drawvalmap
A variation of dnspktflow which can produce visual diagrams of DNS
queries sent by the validator while performing DNSSEC validation.  The
input for this command can come from the validate tool described
above.

### tools/etc       
Data required by DNSSEC-Tools programs.

### tools/linux/ifup-dyn-dns
This is a script which can be used to securely
auto-update a DNS entry when an IP address is assigned
to an interface.

### tools/patches
Patch files to be applied to existing programs.

##  Libraries:

### validator/libsres
A library that is capable of sending queries to, and
receiving answers from a DNSSEC-aware name server.

### validator/libval
A library that provides DNSSEC resource-record
validation functionality.

##  Application Patches and DNSSEC Support:

### apps/libspf2-1.x.y_dnssec
Patches to libspf2 to provide DNSSEC validation of DNS
queries.

### apps/mozilla
Contains the following:
- Patches to firefox to enable DNSSEC name
  checking validation on visited URLs.
- Patches to thunderbird to enable DNSSEC name
  checking validation on visited URLs
- An extension that displays DNSSEC status information
- A thunderbird extension to display the x-dnssec field
  in the Received-SPF header.

### apps/sendmail
Patches to sendmail and spfmilter to provide DNSSEC
validation of DNS queries.

