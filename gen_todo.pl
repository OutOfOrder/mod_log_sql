#!/usr/bin/perl

#  Copyright 2003-2004 Edward Rudd
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

use strict;
my $rootdir = ".";
opendir(MYDIR, $rootdir) or die "Unable to open directory";
print "Building TODO file for source directory\n";
my $todo_header = "* Things TODO *\n\n";
if (open ( TODOFILE, "TODO.in")) {
	$todo_header = do { local $/; <TODOFILE> };
	close (TODOFILE);
}
open (TODOFILE, "> TODO");
print TODOFILE $todo_header;
print "Parsing...";
while (my $entry = readdir(MYDIR)) {
	next if (!($entry =~ /\.[ch]$/));
	print "$entry...";
	open(DAFILE, $rootdir.'/'.$entry) or die "Unable to open file\n";
	my $linenumber = 0;
	my $status = 0; # 0=no comment 1=comment 2=in todo block
	while (my $line = <DAFILE>) {
		$linenumber++;
		if ($status==0) {
			if ( ($line =~ /\/\/\s+TODO: (.*)/) || ($line =~ /\/\*\s+TODO: (.*)\s*\*\//) ){
				print TODOFILE $entry.":".$linenumber.": ".$1."\n";
			} else {
				if ($line =~ /\/\*\*/) {
					$status = 1;
				}
			}
		} else {
			if ($line =~ /\*\//) {
				$status = 0;
			} else {
				if ($status==1) {
					if ($line =~ /TODO:/) {
						$status=2;
					}
				} else {
					if ($line =~ /\* \s+-?\s*(.*)/) {
						print TODOFILE $entry.":".$linenumber.": ".$1."\n";
					}
				}
			}
		}
	}
	close(DAFILE);
}
print "\n";
closedir(MYDIR);
