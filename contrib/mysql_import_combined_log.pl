#!/usr/bin/perl
use strict;
use Getopt::Std;
use DBI;
use Time::ParseDate;

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
	'remote_user',			## 1
	'',						## 2
	'time_stamp',			## 4
	'request_line',		## 5
	'request_method',		## 6
	'request_uri',			## 7
	'request_args',		## 8
	'request_protocol',	## 9
	'status',				## 10
	'bytes_sent',			## 11
	'referer',				## 12
	'agent'					## 13
);
my $col = '';

$Getopt::Std::STANDARD_HELP_VERSION = 1;	## if we show the help, exit afterwards.
getopts('h:u:p:d:t:f:', \%options);


$options{h} ||= 'localhost';
$options{d} ||= '';
$options{u} ||= '';
$options{p} ||= '';
$options{f} ||= '';

if( ! $options{d} )
{
	print "Must supply a database to connect to.\n";
	exit 1;
}

if( ! $options{t} )
{
	print "Must supply table name.\n";
	exit 1;
}

if( $options{f} )
{
	if( ! -e $options{f} )
	{
		print  "File '$options{f}' doesn't exist.\n";
		exit 1;
	}
	open(STDIN, "<$options{f}") || die "Can't open $options{f} for reading.";
}

$dbh = Connect();

$sql = "INSERT INTO $options{t} (";
foreach $col (@cols)
{
	$sql .= "$col," if( $col );
}
chop($sql);
$sql .= ') VALUES (';

while($line = <STDIN>)
{
	@parts = SplitLogLine( $line );
	next if( $parts[$TIMESTAMP] == 0 );
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
	}
	$sth->finish();
}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Connects to a MySQL database and returns the connection.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
sub Connect
{
	my $dsn = "DBI:mysql:$options{d};hostname=$options{h}";
	return DBI->connect( $dsn, $options{u}, $options{p} );
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
	my $count;
	chomp($line);
	for( $i = 0; $i < length($line); ++$i )
	{
		$char = substr($line, $i, 1);
		if( $char eq ' ' && ! $inQuote )
		{
			## print "Found part $part.\n";
			if( $count == $TIMESTAMP )
			{
				$part = parsedate($part, WHOLE => 1, DATE_REQUIRED => 1, TIME_REQUIRED => 2);
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
 -h <host name>      The host to connect to.  Default is localhost.
 -d <database name>  The database to use.  Required.
 -u <username>       The user to connect as.
 -p <password>       The user's password.
 -t <table name>     The name of the table in which to insert data.
 -f <file name>      The file to read from.  If not given, data is read from stdin.
 --help              Print out this help message.
 --version           Print out the version of this software.
EOF
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Prints the version information for this program
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
sub VERSION_MESSAGE
{
	print "mysql_import_combined_log.pl version 1.0\n";
}

1;

1;

