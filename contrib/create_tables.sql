CREATE TABLE apachelog (
    id character(28) NULL UNIQUE,
    service character varying(12) DEFAULT 'APACHE' NOT NULL,
    agent character varying(255),
    bytes_sent integer,
    bytes_recvd integer,
    child_pid integer,
    child_tid bigint,
    cookie character varying(255),
    machine_id character varying(25),
    request_file character varying(255),
    referer character varying(255),
    local_address character(15),
    server_name character varying(255),
    remote_address character(15),
    remote_host character varying(50),
    remote_logname character varying(50),
    remote_user character varying(50),
    request_duration integer,
    request_line character varying(255),
    request_method character varying(16),
    request_protocol character varying(10),
    request_time timestamp,
    request_uri character varying(255),
    request_args character varying(255),
    server_port integer,
    status integer,
    request_timestamp integer,
    virtual_host character varying(255),
    connection_status character(1),
    win32status integer,
    ssl_cipher character varying(25),
    ssl_keysize integer,
    ssl_maxkeysize integer
);

CREATE TABLE notes (
    id character(28) NOT NULL,
    item character varying(80),
    val character varying(255),
    FOREIGN KEY(id) REFERENCES apachelog(id)
      ON DELETE CASCADE
      ON UPDATE CASCADE
);

CREATE TABLE headers_in (
    id character(28) NOT NULL,
    item character varying(80),
    val character varying(255),
    FOREIGN KEY(id) REFERENCES apachelog(id)
      ON DELETE CASCADE
      ON UPDATE CASCADE
);

CREATE TABLE headers_out (
    id character(28) NOT NULL,
    item character varying(80),
    val character varying(255),
    FOREIGN KEY(id) REFERENCES apachelog(id)
      ON DELETE CASCADE
      ON UPDATE CASCADE
);

CREATE TABLE cookies (
    id character(28) NOT NULL,
    item character varying(80),
    val character varying(255),
    FOREIGN KEY(id) REFERENCES apachelog(id)
      ON DELETE CASCADE
      ON UPDATE CASCADE
);

CREATE VIEW inetlog AS
 SELECT
    remote_host AS "ClientHost",
    remote_user AS username,
    request_time AS "LogTime",
    service,
    machine_id AS machine,
    local_address AS serverip,
    remote_address AS clientip,
    request_duration AS processingtime,
    bytes_recvd AS bytesrecvd,
    bytes_sent AS bytessent,
    status AS servicestatus,
    win32status,
    request_method AS operation,
    request_uri AS target,
    request_args AS parameters
 FROM apachelog;
