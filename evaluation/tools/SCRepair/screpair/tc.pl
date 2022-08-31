#!/usr/bin/env perl
# Author: Xiao Liang Yu
# 

use strict;
use GetOpt::Long;

my $T=`mktemp`;
my $H;
OPEN $H, '>', $T or die;

my @fs;
my $addr;
my $bin;
my $con;
my $LOCSTR;
my $CMD;

GetOptions(
    "path=s" => \@fs,
    'addr=s' => \$addr,
    'bin=s' => \$bin,
    'con=i' => \$con,
    'LOCSTR=s' => \$LOCSTR,
    'CMD=s' => \$CMD,
)

my $ps = join('","', @fs);
print { $H } "const main = require('tc/build/main/exec'); main.default({path_to_test_case_file: [\"$ps\"]}, '$addr', '$bin', false, $con, '$LOCSTR', '$CMD' });" or die;

close $H

system("node --max-old-space-size=4096 $T")
