#!/bin/sh

find rules | grep -v '~' | grep -v '.bak' | grep -v '.svn' > rules.list

rm -f donuts.`uname -s`

pp -A rules.list -o donuts.`uname -s`  -M Net::DNS -M Net::DNS::SEC -M Net::DNS::RR::DNSKEY -M Net::DNS::RR::DS -M Net::DNS::RR::NSEC -M Net::DNS::RR::RRSIG -M Getopt::GUI::Long -M Text::Wrap -M Date::Parse -M Gtk2 donuts
