#!/usr/bin/perl -w
# $Id: mysql_import_combined_log.pl,v 1.4 2004/02/21 18:09:50 urkle Exp $
# Written by Aaron Jenson.
# Original source: http://www.visualprose.com/software.php
# Updated to work under Perl 5.6.1 by Edward Rudd
use strict;
use Getopt::Long qw(:config bundling);
use DBI;
use Date::Parse;

my %options = ();
my $i = 0;
my $sql = '';
my $valuesSql = '';
my $line = '';
my $dbh = 0;
my $sth = 0;
my @parts = ();
my $part;
my $TIMESTAMP = 3;
my $REQUEST_LINE = 4;
my @cols = (
	'remote_host',			## 0
	'remote_logname',		## 1
	'remote_user',			## 2
	'request_time',			## 3.string
	'time_stamp',			## 3.posix
	'request_line',			## 5
	'request_method',		## 6
	'request_uri',			## 7
	'request_args',			## 8
	'request_protocol',		## 9
	'status',				## 10
	'bytes_sent',			## 11
	'referer',				## 12
	'agent'					## 13
);
my $col = '';

GetOptions (\%options,
		"version" => sub { VERSION_MESSAGE(); exit 0; },
		"help|?" => sub { HELP_MESSAGE(); exit 0; },
		"host|h=s",
		"database|d=s",
		"table|t=s",
		"username|u=s",
		"password|p=s",
		"logfile|f=s");

$options{host} ||= 'localhost';
$options{database} ||= '';
$options{username} ||= '';
$options{password} ||= '';
$options{logfile} ||= '';

if( ! $options{database} )
{
	HELP_MESSAGE();
	print "Must supply a database to connect to.\n";
	exit 1;
}

if( ! $options{table} )
{
	HELP_MESSAGE();
	print "Must supply table name.\n";
	exit 1;
}

if( $options{logfile} )
{
	if( ! -e $options{logfile} )
	{
		print  "File '$options{logfile}' doesn't exist.\n";
		exit 1;
	}
	open(STDIN, "<$options{logfile}") || die "Can't open $options{logfile} for reading.";
}

$dbh = Connect();
if (! $dbh) {
	exit 1;
}

$sql = "INSERT INTO $options{table} (";
foreach $col (@cols)
{
	$sql .= "$col," if( $col );
}
chop($sql);
$sql .= ') VALUES (';
my ($linecount,$insertcount) = (0,0);
while($line = <STDIN>)
{
	$linecount++;
	@parts = SplitLogLine( $line );
	next if( $parts[$TIMESTAMP+1] == 0 );
	$valuesSql = '';
	for( $i = 0; $i < @cols; ++$i )
	{
		$parts[$i] =~ s/\\/\\\\/g;
		$parts[$i] =~ s/'/\\'/g;
		$valuesSql .= "'$parts[$i]'," if( $cols[$i] );
	}
	chop($valuesSql);

	$sth  = $dbh->prepare("$sql$valuesSql)");
	if( ! $sth->execute() )
	{
		print "Unable to perform specified query.\n$sql$valuesSql\n" . $sth->errstr() . "\n";
	} else {
		$insertcount++;
	}
	$sth->finish();
}
print "Parsed $linecount Log lines\n";
print "Inserted $insertcount records\n";
print "to table '$options{table}' in database '$options{database}' on '$options{host}'\n";

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Connects to a MySQL database and returns the connection.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
sub Connect
{
	my $dsn = "DBI:mysql:$options{database};hostname=$options{host}";
	return DBI->connect( $dsn, $options{username}, $options{password} );
}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Splits up a log line into its parts.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
sub SplitLogLine
{
	my $line = shift;
	my $i = 0;
	my $inQuote = 0;
	my $char = '';
	my $part = '';
	my @parts = ();
	my $count = 0;
	chomp($line);
	for( $i = 0; $i < length($line); ++$i )
	{
		$char = substr($line, $i, 1);
		if( $char eq ' ' && ! $inQuote )
		{
			## print "Found part $part.\n";
			if( $count == $TIMESTAMP )
			{
				push(@parts, "[".$part."]");
				$part = str2time($part);
			}
			push(@parts, $part);
			if( $count == $REQUEST_LINE )
			{
				my @request = split(/[ ?]/, $part);
				push(@parts, $request[0]);
				push(@parts, $request[1]);
				if( $request[3] )
				{
					push(@parts, $request[2]);
					push(@parts, $request[3]);
				}
				else
				{
					push(@parts, '');
					push(@parts, $request[2]);
				}
				$count += 5;
			}
			else
			{
				++$count;
			}
			$part = '';
		}
		elsif( $char eq '"' || $char eq '[' || $char eq ']' )
		{
			$inQuote = !$inQuote;
		}
		else
		{
			$part .= $char;
		}
	}
	push(@parts,$part) if $part;

	return @parts;
}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Prints the usage/help message for this program.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
sub HELP_MESSAGE
{
	print<<EOF;
Imports an Apache combined log into a MySQL database.
Usage: mysql_import_combined_log.pl -d <database name> -t <table name> [-h <hostname>] [-u <username>] [-p <password>] [-f <filename]
 --host|-h <host name>         The host to connect to.  Default is localhost.
 --database|-d <database name> The database to use.  Required.
 --username|-u <username>      The user to connect as.
 --password|-p <password>      The user's password.
 --table|-t <table name>       The name of the table in which to insert data.
 --logfile|-f <file name>      The file to read from.  If not given, data is read from stdin.
 --help|-?                     Print out this help message.
 --version                     Print out the version of this software.
EOF
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Prints the version information for this program
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
sub VERSION_MESSAGE
{
	print "mysql_import_combined_log.pl version 1.2\n";
	print "Version 1.0 Written by Aaron Jenson.\n";
	print "Update to work with perl 5.6.1 by Edward Rudd\n";
}

1;
