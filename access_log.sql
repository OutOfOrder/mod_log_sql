create table access_log (
	agent varchar(255) ,
	bytes_sent int ,
	child_pid smallint unsigned,
	cookie varchar(255),
	request_file varchar(255),
	referer varchar(255) ,
	remote_host varchar(50) ,
	remote_logname varchar(50) ,
	remote_user varchar(50) ,
	request_duration smallint ,
	request_line varchar(255),
	request_method varchar(6) ,
	request_protocol varchar(10) ,
	request_time char(28),
	request_uri varchar(50) ,
	server_port smallint unsigned,
	ssl_cipher varchar(25),
	ssl_keysize smallint unsigned,
	ssl_maxkeysize smallint unsigned,
	status smallint ,
	time_stamp int unsigned ,
	virtual_host varchar(50) 
)

