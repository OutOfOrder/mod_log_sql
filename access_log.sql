create table access_log (
	remote_host varchar(50) not null,
	remote_user varchar(50) not null,
	request_uri varchar(50) not null,
	request_duration smallint not null,
	virtual_host varchar(50) not null,
	time_stamp int unsigned not null,
	status smallint not null,
	bytes_sent int not null,
	referer varchar(255) not null,
	agent varchar(255) not null
)

