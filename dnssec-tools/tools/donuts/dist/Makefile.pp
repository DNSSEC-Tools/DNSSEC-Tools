#!/bin/sh

find rules | grep -v '~' | grep -v '.bak' | grep -v '.svn' > rules.list

rm -f donuts.`uname -s`

pp -A rules.list -o donuts.`uname -s`  -M Getopt::GUI::Long -M Text::Wrap -M Date::Parse -M Gtk2 donuts
