create table access_log (
	id char(19) ,
	agent varchar(255) ,
	bytes_sent int unsigned ,
	child_pid smallint unsigned,
	cookie varchar(255),
	machine_id varchar(25),
	request_file varchar(255),
	referer varchar(255) ,
	remote_host varchar(50) ,
	remote_logname varchar(50) ,
	remote_user varchar(50) ,
	request_duration smallint unsigned ,
	request_line varchar(255),
	request_method varchar(10) ,
	request_protocol varchar(10) ,
	request_time char(28),
	request_uri varchar(255),
	request_args varchar(255),
	server_port smallint unsigned,
	ssl_cipher varchar(25),
	ssl_keysize smallint unsigned,
	ssl_maxkeysize smallint unsigned,
	status smallint unsigned ,
	time_stamp int unsigned ,
	virtual_host varchar(255)
);

create table notes (
    id char(19),
    item varchar(80),
    val varchar(80)
);

create table headers_in (
    id char(19),
    item varchar(80),
    val varchar(80)
);

create table headers_out (
    id char(19),
    item varchar(80),
    val varchar(80)
);

create table cookies (
    id char(19),
    item varchar(80),
    val varchar(80)
);
