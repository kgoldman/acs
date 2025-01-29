$Id: README.PVM.txt 1464 2019-04-16 17:13:47Z kgoldman $
Written by Chris Engel and Ken Goldman

The following instructions are for systems running PowerVM.

PowerVM provides two mechanisms to access attestation data from the TPM.

- Inband from a guest partition through hypervisor calls
- Out of band through the service processor

json note
---------

The distros can't seem to decide whether the json include directory is
/usr/include/json or /usr/include/json-c.

I use /usr/include/json.  If your distro uses json-c, just make a soft link:

# cd /usr/include
# ln -s json-c json


RHEL Install Libraries
-----------------

# For the attestation server:

$ yum install mysql mysql-devel openssl openssl-devel json-c json-c-devel php php-devel php-mysql
$ service mysqld start
$ service httpd start


# For the attestation client:

$ yum install openssl openssl-devel json-c json-c-devel


Centos and recent Fedora
------------------------

# For the attestation server:

$ dnf install mariadb mariadb-server
$ systemctl start mariadb.service
$ systemctl enable mariadb.service

Ubuntu
------

# For the attestation server:

$ apt-get apache2, php, php5-dev, php-mysql libjson-c3, libjson-c-dev

# For the attestation client:

$ apt-get libjson-c3, libjson-c-dev


---------------------------
ATTESTATION SERVER SETUP
---------------------------

Install the Database Schema
---------------------------

As root:

$ mysql
mysql> create database tpm2;
mysql> grant all privileges on tpm2.* to ''@'localhost';

As non-root:

> mysql -D tpm2 < dbinit.sql

Build Libraries and Applications
--------------------------------

1 - If using a SW TPM for the server

https://github.com/kgoldman/ibmswtpm2

> (cd .../tpm2/src && make)

2 - TSS and utilities:  creates libtss.so

https://github.com/kgoldman/ibmtss

> (cd .../tpm2/utils && make -f makefiletpm20)

3 - Since the TSS is not "installed", the ACS programs must be pointed
to the TSS library.  When the TSS is installed in /usr/lib as part of
a distribution, this step becomes unnecessary.

csh variants

> setenv LD_LIBRARY_PATH ../utils

bash variants

> export LD_LIBRARY_PATH=../utils

Replace ../utils as appropriate if the directory structure is
different.

4 - Attestation demo

As root:
$ mkdir /var/www/html/acs
$ chown user /var/www/html/acs
$ chgrp user /var/www/html/acs
$ chmod 777  /var/www/html/acs

Build the attestation server and default client

> (cd .../tpm2/acs && make)

	The makefile assumes that the TSS library libtss.so is in
	../utils and makes a link.  If the TSS is installed somewhere
	else, either copy libtss.so here or make a link to it.

Build the PowerVM out of band client

> (cd .../tpm2/acs && make -f makefile.pvm)

If running on a Linux partition on a PowerVM system you can use the inband attestation mechanism

> (cd .../tpm2/acs && make -f makefile.pvminband)

Provision the RSA EK Certificate CA Signing Key
-----------------------------------------------

*** This optional step is only required if changing the endorsement
    key CA signing key cakey.pem / cacert.pem included in the package.

*** This is done once per software install.

*** This is only required when using a SW TPM.

1 - Create an EK certificate server CA signing key

> cd .../tpm2/acs
> openssl genrsa -out cakey.pem -aes256 -passout pass:rrrr 2048

2 - Create a self signed EK root CA certificate

> openssl req -new -x509 -key cakey.pem -out cacert.pem -days 3650

Country Name (2 letter code) [XX]:US
State or Province Name (full name) []:NY
Locality Name (eg, city) [Default City]:Yorktown
Organization Name (eg, company) [Default Company Ltd]:IBM
Organizational Unit Name (eg, section) []:
Common Name (eg, your name or your server's hostname) []:EK CA
Email Address []:

3 - View the certificate for correctness.

> openssl x509 -text -in cacert.pem -noout

Issuer and subject should match.  Validity 20 years.  Etc.

4 - Install the cacert.pem in the directory where the HW TPM root
certificates are.  Currently, that's .../tpm2/utils/certificates.

The HW TPM vendor root certificates should already be there.

Provision the EC EK Certificate CA Signing Key
----------------------------------------------

*** This optional step is only required if changing the endorsement
    key CA signing key cakeyecc.pem / cacertecc.pem included in the
    package.

*** This optional step requires at least openssl 1.0.2. 1.0.1 will not
    work.

> openssl genpkey -out cakeyecc.pem -outform PEM -pass pass:rrrr -aes256 -algorithm ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve

2 - Create a self signed EK root CA certificate

> openssl req -new -x509 -key cakeyecc.pem -out cacertecc.pem -days 3650

Country Name (2 letter code) [XX]:US
State or Province Name (full name) []:NY
Locality Name (eg, city) [Default City]:Yorktown
Organization Name (eg, company) [Default Company Ltd]:IBM
Organizational Unit Name (eg, section) []:
Common Name (eg, your name or your server's hostname) []:EK EC CA
Email Address []:

3 - View the certificate for correctness.

openssl x509 -text -in cacertecc.pem -noout

Issuer and subject should match.  Validity 20 years.  Etc.

4 - Install the cacert.pem in the directory where the HW TPM root
certificates are.  Currently, that's .../tpm2/utils/certificates.


SW TPM Provisioning
-------------------

*** This is only required for a SW TPM.  HW TPMs come with EK
    certificates.

*** This is only required once per TPM.  It is installed in SW TPM
    non-volatile memory.

1 - Start the SW TPM

.../tpm2/src> tpm_server
.../tpm2/utils> powerup;startup

2 - Provision the SW TPM with EK certificates

(RSA public key and CA key)

.../tpm2/utils> createekcert -alg rsa -cakey cakey.pem -capwd rrrr -v

(EC public key and CA key)

.../tpm2/utils> createekcert -alg ecc -cakey cakeyecc.pem -capwd rrrr -caalg ec -v

CAUTION.  The EK and certificate will normally persist.  However,
running the TSS regression test rolls the EPS (endorsement hierarchy
primary seed), voiding everything.  You can reprovision and re-enroll,
but it's easier to make a copy of the SW TPM NV space now, and restore
it as necessary.

> cd .../tpm2/src
> cp NVChip NVChip.save

Provisioning the server
-----------------------

*** This is only required if changing privacy CA signing key
pcakey.pem/ pcacert.pem  included in the package.

1 - Create a privacy CA signing key

> cd .../tpm2/acs
> openssl genrsa -out pcakey.pem -aes256 -passout pass:rrrr 2048

2 - Create a self signed privacy CA certificate

> openssl req -new -x509 -key pcakey.pem -out pcacert.pem -days 3560

Use AK CA as the common name

3 - View the certificate for correctness.

> openssl x509 -text -in pcacert.pem -noout

Start the server
----------------

1 - The server uses a TPM as a crypto coprocessor.  It must point to a
different (typically a software) TPM and TSS data directory.

A - If the server is being run on the same machine as the client:

> cd .../tpm2/acs
	for example
> export TPM_DATA_DIR=/gsa/yktgsa/home/k/g/kgold/tpm2
	or
> setenv TPM_DATA_DIR /gsa/yktgsa/home/k/g/kgold/tpm2

B - If the server is being run on a different machine from the client:

	(and TPM 2.0 attestation key provisioning is needed)

> .../tpm2/src/tpm_server
> .../tpm2/utils/powerup
> .../tpm2/utils/startup

2 - Edit the file .../tpm2/utils/certificates/rootcerts.txt

Change the path name to wherever the directory is installed.

4 - Set the server port

setenv ACS_PORT	2323

5 - Optional: Set the mysql userid/password

The mysql instructions above don't set a DB host and port, userid and
password, or database name.  However if you have one set in your
configuration you can set it using these environment variables.

ACS_SQL_HOST - defaults to localhost
ACS_SQL_PORT - defaults to 0, MySQL will use its default
ACS_SQL_USERID - defaults to current user
ACS_SQL_PASSWORD - defaults to empty
ACS_SQL_DATABASE - defaults to tpm2

setenv ACS_SQL_USERID root
setenv ACS_SQL_PASSWORD 12345

6 - Start the attestation server.

E.g.,

> server -v -root ../utils/certificates/rootcerts.txt -imacert imakey.der >! serverenroll.log4j

-v and piping to a file are optional.


----------------------------------
ATTESTATION CLIENT SETUP : INBAND
----------------------------------

Provisioning a Client
---------------------

NOTE: With a hardware TPM, this can take several minutes, and appear
to hang.  Creating a primary key on a hardware TPM is a long
calculation.

This installs the client attestation key certificate at the
attestation server.  The attestation key is stored in the local
directory for reuse later.  This key must be saved for all further
attestations of this client or you will need to re-enroll the system.

> acsPvmClientEnroll -alg rsa -v -ho <attestServer> -ma <systemName> >! clientenroll.log4j

  -ho is the hostname of the attestation server
  -ma is the name of the system being attested, typically not the name of the partition
  -v and piping to a file are optional.


Running an Attestation
----------------------

As often as desired, run an attestation.

> acsPvmClient -alg rsa -ho <attestServer> -ma <systemName> -v >! client.log4j

  -ho is the hostname of the attestation server
  -ma is the name of the system being attested, typically not the name of the partition
  -v and piping to a file are optional.

----------------------------------
ATTESTATION CLIENT SETUP : OUTOFBAND
----------------------------------

Provisioning a Client
---------------------

NOTE: With a hardware TPM, this can take several minutes, and appear
to hang.  Creating a primary key on a hardware TPM is a long
calculation.

This installs the client attestation key certificate at the
attestation server.  The attestation key is stored in the local
directory for reuse later.  This key must be saved for all further
attestations of this client or you will need to re-enroll the system.

> acsPvmClientEnroll -alg rsa -v -ho <attestServer> -ma <systemName> -sphost <fsp> >! clientenroll.log4j

  -ho is the hostname of the attestation server
  -ma is the name of the system being attested, typically not the name of the partition
  -sphost is the system service processor hostname 
  -v and piping to a file are optional.


Running an Attestation
----------------------

As often as desired, run an attestation.

> acsPvmClient -alg rsa -ho <attestServer> -ma <systemName> -sphost <fsp> -v >! client.log4j

  -ho is the hostname of the attestation server
  -ma is the name of the system being attested, typically not the name of the partition
  -sphost is the system service processor hostname 
  -v and piping to a file are optional.

Code Structure
--------------

The client side is separated into the main acsPvmClient and acsPvmClientEnroll
executables and a clientlocal set of utilities.

The structure permits the client and clientenroll functions to be run
in a different space (perhaps a VM) than the (clientlocal) space that
has the TPM.

Clearing a hostname from attestation server for testing
-------------------------------

delete from machines where hostname = 'cainl.watson.ibm.com';
delete from attestlog where hostname = 'cainl.watson.ibm.com';
delete from imalog where hostname = 'cainl.watson.ibm.com';

delete from machines where hostname = 'cainlec.watson.ibm.com';
delete from attestlog where hostname = 'cainlec.watson.ibm.com';
delete from imalog where hostname = 'cainecl.watson.ibm.com';

Database Tables
---------------

machines - all machines

	id - primary key for machine
	hostname - typically the fully qualified domain name, untrusted
	tpmvendor - TPM manufacturer name,  untrusted
	challenge - server to client enrollment challenge
	ekcertificatepem - endorsement key certificate, pem format
	ekcertificatetext - endorsement certificate, dump
	attestpub - attestation public key 
	akcertificatepem - attestation key certificate, pem format
	akcertificatetext - attestation certificate, dump
	enrolled - date of attestation key enrollment
	boottime - last boot time,  untrusted,
		whatever the client provides
	imaevents - next IMA event to be processed
		set to zero on enrollment
		set back to zero on first quote or reboot
	imapcr - value corresponding to imaevents, used for incremental update
	pcr00-pcr23 - sha1 and sha256, white list, values from first valid quote

attestlog - all attestations for all machines

	id - primary key for attestation
	userid - userid of attestation, untrusted
		whatever the client provides
	hostname - typically the fully qualified domain name, untrusted,
		whatever the client provides
	boottime - last boot time, untrusted,
		whatever the client provides
	timestamp - date  of attestation
	nonce - freshness nonce
	pcrselect - which PCRs are selected, currently hard coded to 0-23
	quote - quote data in json, for debug and forensics
	pcr00-pcr23 - current value from quote
	pcrschanged - boolean flag, pcrs changed from last attestation
	quoteverified - boolean flag, signature over quote data is valid
	logverified - boolean flag, bios event log verifies against its PCRs
	logentries - number of entries in BIOS event log
	imaevents - number of entries in IMA event log
	pcrinvalid - boolean flag, pcrs different from white list
	imaver -  boolean flag, IMA event log verifies against its PCR
	badimalog - boolean flag, IMA event log is malformed

imalog - current IMA event log for all machines

	id - primary key for attestation
	hostname - typically the fully qualified domain name, untrusted,
		whatever the client provides
	boottime - last boot time,  untrusted,
		whatever the client provides
	timestamp - server time of attestation
	entrynum - ima event number
	ima_entry - the raw ima event as hex ascii
	filename - ima event file name
	badevent - if the template data hash did not verify, or the template data could not be
		unmarshaled
	nosig - if the template data lacked a signature
	nokey - if the key referenced by the template data is unknown
	badsig - if the BIOS entry signature did not verify

bioslog - current BIOS event log for all machines
	id - primary key for attestation
	hostname - typically the fully qualified domain name, untrusted,
		whatever the client provides
	timestamp - server time of attestation
	entrynum - bios event number
	bios_entry - the raw ima event as hex ascii
	eventtype - TCG_PCR_EVENT2.eventType as ascii
	event - TCG_PCR_EVENT2.event as ascii

At enroll
	machines insert
		hostname
		tpmvendor
		ekcertificatepem
		ekcertificatetext
		challenge
		attestpub 
		akcertificatepem	null, then certificate
		akcertificatetext	null, then certificate
		imaevents		null, then 0
		enrolled		null, then time
		pcrnn			null
		imapcr			null

At nonce
	attestlog insert
		userid
		hostname
		timestamp
		nonce
		pcrselect

		boottime		null
		quoteverified		null
		pcrnn			null
		quote			null
		pcrinvalid		null
		logverified		null
		logentries		null
		imaver			null
		badimalog		null


At quote
	machines update

		if quote verified
			if storePcrWhiteList		(first time)
				pcrnn
			if storePcrWhiteList or new boottime
				imaevents	0
				imapcr		00...00
			boottime

	atestlog update
		if quote verified
			pcrchanged
			pcrnn
		if !storePcrWhiteList
			pcrinvalid
		quoteverified
		quote
		boottime


At BIOS


	atestlog update
		logverified
		logentries

At IMA

	machines update
		if ima pcr verified
			imaevents		last event for incremental
			imapcr			current PCR value

	atestlog update
		badimalog
		imaver
		imaevents			last event for this quote
