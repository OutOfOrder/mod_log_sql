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

opendir(MYDIR, ".") or die "Unable to open directory";
print "Building TODO file for source directory\n";

open ( TODOFILE, "TODO.in");
my $todo_header = do { local $/; <TODOFILE> };
close (TODOFILE);
open (TODOFILE, "> TODO");
print TODOFILE $todo_header;
print "Parsing...";
while (my $entry = readdir(MYDIR)) {
	next if (!($entry =~ /\.[ch]$/));
	print "$entry...";
	open(DAFILE, $entry) or die "Unable to open file";
	my $linenumber = 0;
	while (my $line = <DAFILE>) {
		$linenumber ++;
		next if (!($line =~ /\/\* TODO: (.*)\*\//));
		print TODOFILE $entry.":".$linenumber.": ".$1."\n";
	}
	close(DAFILE);
}
print "\n";
closedir(MYDIR);
