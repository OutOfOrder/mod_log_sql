#!/usr/bin/perl

# $Id: make_combined_log.pl,v 1.1 2001/11/28 05:26:54 helios Exp $
#
# make_combined_log.pl
#
# Usage: make_combined_log <days> <virtual host>
#
# This perl script extracts the httpd access data from a MySQL database
# and formats it properly for parsing by 3rd-party log analysis tools.
#
# The script is intended to be run out by cron.  Its commandline arguments tell
# it how many days' worth of access records to extract, and which virtual_host
# you are interested in (because many people log several virthosts to one MySQL
# db.) This permits you to run it daily, weekly, every 9 days -- whatever you
# decide.
#
# Note: By "days" I mean "chunks of 24 hours prior to the moment this script is
# run." So if you run it at 4:34 p.m. on the 12th, it will go back through 4:34
# p.m. on the 11th.
#
# Known issues:
# * Because GET and POST are not discriminated in the MySQL log, we'll just
#   assume that all requests are GETs.  This should have negligible effect
#   on any analysis software.  This could be remedied IF you stored the full
#   HTTP request in your database instead of just the URI, but that's going to
#   cost you a LOT of space really quickly...
#
# * Because this is somewhat of a quick hack it doesn't do the most robust
#   error checking in the world.  Run it by hand to confirm your usage before
#   putting it in crontab.

$| = 1;

use DBI;

# Remember, $#ARGV is parameters minus one...
if ($#ARGV != 1) {
	die "Incorrect usage, please read the perl source code for correct usage."
}

$days     = $ARGV[0];
$virthost = $ARGV[1];

#
# Set up the proper variables to permit database access
#
$serverName = "your.dbmachine.com";
$serverPort = "3306";
$serverUser = "someuser";
$serverPass = "somepass";
$serverTbl  = "acc_log_tbl";
$serverDb   = "apache";

#
# Other constants
#
$st_tz = "-0800";
$dt_tz = "-0700";
$type = "GET";
$http = "HTTP/1.1";

$now = time();
$start = $now - (86400 * $days);

#
# Connect and fetch the records
#
$dbh = DBI->connect("DBI:mysql:database=$serverDb;host=$serverName;port=$serverPort",$serverUser,$serverPass);
if (not $dbh) {
	die "Unable to connect to the database.  Please check your connection variables. (Bad password? Incorrect perms?)";
}

$records = $dbh->prepare("select remote_host,remote_user,request_uri,request_duration,time_stamp,status,bytes_sent,referer,agent from $serverTbl where virtual_host='$virthost' and time_stamp >= $start");
$records->execute;
if (not $records) {
	die "No such table or the select returned no records."
}

#Right
#ariston.netcraft.com - - [14/Nov/2001:05:13:39 -0800] "GET / HTTP/1.0" 200 502 "-" "Mozilla/4.08 [en] (Win98; I)"
#ariston.netcraft.com - - [14/Nov/2001:05:13:39 -0800] "GET / HTTP/1.0" 200 502 "-" "Mozilla/4.08 [en] (Win98; I)"

#Bad
#ariston.netcraft.com - - [2001-11-14 05:13:39 -0800] "GET / HTTP/1.1" 200 502 "-" "Mozilla/4.08 [en] (Win98; I)"
#ariston.netcraft.com - - [2001-11-14 05:13:39 -0800] "GET / HTTP/1.1" 200 502 "-" "Mozilla/4.08 [en] (Win98; I)"


#
# Pull out the data row by row and format it
#
while (@data = $records->fetchrow_array) {
	($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($data[4]);
	$year=$year+1900;

	# Create format for leading-zero formatting
	if ($day < 10) { $day = "0$day"; }
	if ($month < 10) { $month = "0$month"; }	
	if ($hour < 10) { $hour = "0$hour"; }
	if ($min < 10) { $min = "0$min"; }
	if ($sec < 10) { $sec = "0$sec"; }
	
	# Convert numeric month to string month
    for ($mon) {
		if    (/00/)  { $mon = "Jan";} 
		elsif (/01/)  { $mon = "Feb";} 
		elsif (/02/)  { $mon = "Mar";} 
		elsif (/03/)  { $mon = "Apr";}
		elsif (/04/)  { $mon = "May";}
		elsif (/05/)  { $mon = "Jun";}
		elsif (/06/)  { $mon = "Jul";}
		elsif (/07/)  { $mon = "Aug";}
		elsif (/08/)  { $mon = "Sep";}
		elsif (/09/)  { $mon = "Oct";}
		elsif (/10/)  { $mon = "Nov";}
		elsif (/11/)  { $mon = "Dec";}
    }
    
    # Create the output
	print "$data[0] $data[1] - [$mday/$mon/$year:$hour:$min:$sec ";
	if ($isdst) {
		print "$dt_tz\] ";
	} else {
		print "$st_tz\] ";
	}
	print "\"$type $data[2] $http\" $data[5] $data[6] \"$data[7]\" \"$data[8]\"\n";
}

#
# Done
#
$records->finish;

