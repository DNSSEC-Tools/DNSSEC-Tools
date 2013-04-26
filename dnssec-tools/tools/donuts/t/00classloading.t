#!/usr/bin/perl

use Test::More qw(no_plan);

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts'); }
require_ok('Net::DNS::SEC::Tools::Donuts');

BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts::Rule'); }
require_ok('Net::DNS::SEC::Tools::Donuts::Rule');

BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts::Output::Format'); }
require_ok('Net::DNS::SEC::Tools::Donuts::Output::Format');

BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts::Output::Format::Text'); }
require_ok('Net::DNS::SEC::Tools::Donuts::Output::Format::Text');

BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts::Output::Format::Text::Wrapped'); }
require_ok('Net::DNS::SEC::Tools::Donuts::Output::Format::Text::Wrapped');
