create table machines
(
	id int unsigned not null auto_increment primary key,
	hostname varchar(255) not null,
	tpmvendor char(18) not null,
	challenge char(64),
	ekcertificatepem text not null,
	ekcertificatetext text not null,
	attestpub text not null,
	akcertificatepem text,
	akcertificatetext text,
	enrolled datetime,
	boottime datetime,
	imaevents int unsigned,
	imapcr char(64),
	pcr00sha256 char(64),
	pcr01sha256 char(64),
	pcr02sha256 char(64),
	pcr03sha256 char(64),
	pcr04sha256 char(64),
	pcr05sha256 char(64),
	pcr06sha256 char(64),
	pcr07sha256 char(64),
	pcr08sha256 char(64),
	pcr09sha256 char(64),
	pcr10sha256 char(64),
	pcr11sha256 char(64),
	pcr12sha256 char(64),
	pcr13sha256 char(64),
	pcr14sha256 char(64),
	pcr15sha256 char(64),
	pcr16sha256 char(64),
	pcr17sha256 char(64),
	pcr18sha256 char(64),
	pcr19sha256 char(64),
	pcr20sha256 char(64),
	pcr21sha256 char(64),
	pcr22sha256 char(64),
	pcr23sha256 char(64),
	pcr00sha1 char(64),
	pcr01sha1 char(64),
	pcr02sha1 char(64),
	pcr03sha1 char(64),
	pcr04sha1 char(64),
	pcr05sha1 char(64),
	pcr06sha1 char(64),
	pcr07sha1 char(64),
	pcr08sha1 char(64),
	pcr09sha1 char(64),
	pcr10sha1 char(64),
	pcr11sha1 char(64),
	pcr12sha1 char(64),
	pcr13sha1 char(64),
	pcr14sha1 char(64),
	pcr15sha1 char(64),
	pcr16sha1 char(64),
	pcr17sha1 char(64),
	pcr18sha1 char(64),
	pcr19sha1 char(64),
	pcr20sha1 char(64),
	pcr21sha1 char(64),
	pcr22sha1 char(64),
	pcr23sha1 char(64)
);

create table attestlog
(
	id int unsigned not null auto_increment primary key,
	userid varchar(255) not null,
	hostname varchar(255) not null,
	boottime datetime,
	timestamp datetime not null,
	nonce char(64) not null,
	pcrselect char(32) not null,
	quote text,
	pcr00sha256 char(64),
	pcr01sha256 char(64),
	pcr02sha256 char(64),
	pcr03sha256 char(64),
	pcr04sha256 char(64),
	pcr05sha256 char(64),
	pcr06sha256 char(64),
	pcr07sha256 char(64),
	pcr08sha256 char(64),
	pcr09sha256 char(64),
	pcr10sha256 char(64),
	pcr11sha256 char(64),
	pcr12sha256 char(64),
	pcr13sha256 char(64),
	pcr14sha256 char(64),
	pcr15sha256 char(64),
	pcr16sha256 char(64),
	pcr17sha256 char(64),
	pcr18sha256 char(64),
	pcr19sha256 char(64),
	pcr20sha256 char(64),
	pcr21sha256 char(64),
	pcr22sha256 char(64),
	pcr23sha256 char(64),
	pcr00sha1 char(64),
	pcr01sha1 char(64),
	pcr02sha1 char(64),
	pcr03sha1 char(64),
	pcr04sha1 char(64),
	pcr05sha1 char(64),
	pcr06sha1 char(64),
	pcr07sha1 char(64),
	pcr08sha1 char(64),
	pcr09sha1 char(64),
	pcr10sha1 char(64),
	pcr11sha1 char(64),
	pcr12sha1 char(64),
	pcr13sha1 char(64),
	pcr14sha1 char(64),
	pcr15sha1 char(64),
	pcr16sha1 char(64),
	pcr17sha1 char(64),
	pcr18sha1 char(64),
	pcr19sha1 char(64),
	pcr20sha1 char(64),
	pcr21sha1 char(64),
	pcr22sha1 char(64),
	pcr23sha1 char(64),
	pcrschanged bool,
	pcrinvalid bool,
	quoteverified bool,
	logverified bool,
	logentries int unsigned,
	imaevents int unsigned,
	imaver bool,
	imasigver bool,
	badimalog bool
);

create table imalog
(
	id int unsigned not null auto_increment primary key,
	hostname varchar(255),
	boottime datetime,
	timestamp datetime,
	entrynum int unsigned,
	ima_entry varbinary(1024),
	filename varchar(1024),
	badevent bool,
	nosig bool,
	nokey bool,
	badsig bool
);

create table bioslog
(
	id int unsigned not null auto_increment primary key,
	hostname varchar(255),
	timestamp datetime,
	entrynum int unsigned,
	bios_entry varbinary(1024),
	pcrindex tinyint,
	pcrsha1 char(64),
	pcrsha256 char(64),
	eventtype varchar(256),
	event varchar(256)
);
