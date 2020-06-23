$Id: README.txt 1630 2020-06-04 18:37:01Z kgoldman $
Written by Ken Goldman
IBM Thomas J. Watson Research Center

json note
---------

The distros can't seem to decide whether the json include directory is
/usr/include/json or /usr/include/json-c.

I use /usr/include/json.  If your distro uses json-c, just make a soft link:

# cd /usr/include
# ln -s json-c json


RHEL Install Libraries
----------------------

For the attestation server
- - - - - - - - - - - - -

# yum install (the following packages)

openssl
openssl-devel		(tested with 1.0.x, not tested with 1.1.x)
json-c
json-c-devel
mysql
mysql-devel
php
php-devel
php-mysql


# service mysqld start
# service httpd start

For the attestation client
- - - - - - - - - - - - -

# yum install (the following packages)

openssl 
openssl-devel 
json-c 
json-c-devel 

Centos and recent Fedora
------------------------

For the attestation server

# dnf install mariadb mariadb-server
# systemctl start mariadb.service
# systemctl enable mariadb.service

Ubuntu
------

For the attestation server

# apt-get (the following packages)

libjson-c3
libjson-c-dev
apache2
php
php5-dev
php-mysql

For the attestation client

# apt-get (the following packages)

libjson-c3
libjson-c-dev

Install the Database Schema at the attestation server
---------------------------

As root:

# mysql
mysql> create database tpm2;
mysql> grant all privileges on tpm2.* to ''@'localhost';

As non-root:

> mysql -D tpm2 < dbinit.sql

Build Libraries and Applications
--------------------------------

The makefiles and these instructions assume that the TSS is built in
../utils.  If not, adjust accordingly.  When the TSS is installed in
/usr/lib as part of a distribution, this becomes unnecessary.

1 - If using a SW TPM

https://sourceforge.net/projects/ibmswtpm2/

> cd .../tpm2/src
> make

2 - TSS and utilities:  creates libtss.so

https://sourceforge.net/projects/ibmtpm20tss/

	For a TPM 2.0 TSS

> cd .../tpm2/utils
> make -f makefiletpm20

	For a combined TPM 1.2 and TPM 2.0 TSS

> cd .../tpm2/utils
> make -f makefiletpmc
> cd .../tpm2/utils12
> make -f makefiletpmc

3 - Since the TSS is not "installed", the ACS programs must point
to the TSS library [path].  When the TSS is installed in /usr/lib as
part of a distribution, this step becomes unnecessary.

csh variants

> setenv LD_LIBRARY_PATH [path]/tpm2/utils:[path]/tpm2/utils12

bash variants

> export LD_LIBRARY_PATH=[path]/tpm2/utils:[path]/tpm2/utils12

4 - Attestation demo

# mkdir /var/www/html/acs
# chown user /var/www/html/acs
# chgrp user /var/www/html/acs
# chmod 777  /var/www/html/acs

> cd .../tpm2/acs

For TPM 2.0 client and server

> make

For TPM 1.2 client (requires TPM 1.2 / TPM 2.0 server)

> make -f makefiletpm12

For TPM 1.2 and TPM 2.0 client and TPM 1.2 / TPM 2.0 server

> make -f makefiletpmc
	
	These notes are not required once the TSS is installed in the
	system area through a package manager.

	The makefile assumes that the TSS include and library
	directories are in ../utils.  If not, specify that [path].

	> setenv CPATH [path-to]/tpm2/utils
	> setenv LIBRARY_PATH [path-to]/tpm2/utils

	For TPM 1.2

	> setenv CPATH [path-to]/tpm2/utils:[path-to]/tpm2/utils12
	> setenv LIBRARY_PATH [path-to]/tpm2/utils:[path-to]/tpm2/utils12
	


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

4 - Install the cacertecc.pem in the directory where the HW TPM root
certificates are.  Currently, that's .../tpm2/utils/certificates.


SW TPM Provisioning
-----------------------

*** This is only required for a SW TPM.  HW TPMs come with EK
    certificates.

*** This is only required once per TPM.  It is installed in SW TPM
    non-volatile memory.

TPM 2.0
- - - -

The TSS will normally default to these.	

	setenv TPM_COMMAND_PORT 2321
	setenv TPM_SERVER_TYPE mssim

1 - Start the SW TPM

.../tpm2/src> tpm_server
.../tpm2/utils> powerup;startup

2 - Provision the SW TPM with EK certificates

(RSA public key and CA key)


.../tpm2/utils> createekcert -rsa 2048 -cakey cakey.pem -capwd rrrr -v

(EC public key and CA key)

.../tpm2/utils> createekcert -ecc nistp256 -cakey cakeyecc.pem -capwd rrrr -caalg ec -v

CAUTION.  The EK and certificate will normally persist.  However,
running the TSS regression test rolls the EPS (endorsement hierarchy
primary seed), voiding everything.  You can reprovision and re-enroll,
but it's easier to make a copy of the SW TPM NV space now, and restore
it as necessary.

> cd .../tpm2/src
> cp NVChip NVChip.save

TPM 1.2
- - - -

setenv TPM_COMMAND_PORT 6543
setenv TPM_SERVER_TYPE rawsingle
setenv TPM_ENCRYPT_SESSIONS 0

1 - Start the SW TPM

Remove the 00.permall state file, so that an EK certificate index can be defined with the D bit set

.../tpm/src> tpm_server >! tpm.log

2 - Startup, Create an EK, create an SRK, use the default all zeros SRK password

.../utils12> tpminit; startup

.../utils12> createendorsementkeypair

.../utils12> oiap

.../utils12> takeownership -pwdo ooo -se0 [handle from OIAP] 0

2 - Provision the SW TPM with EK certificates.  Does the following

	starts an OSAP session and uses it to define the EK certificate NV index
	secures the NV space
	reads the EK public key
	creates and provisions the EK certificate
	reads the certificate back for testing

All in the .../utils12 directory

$OSAP is the handle from the OSAP command
$OIAP is the handle from the OIAP command

> osap -ha 40000001 -pwd ooo

> nvdefinespace -ha 1000f000 -sz 1400 -per 20002 -se0 $OSAP 0 

> nvdefinespace -ha ffffffff -sz 0

> oiap

> ownerreadinternalpub -ha ek -pwdo ooo -op ekpub.bin -se0 $OIAP 0

> createekcert -pwdo ooo -iek ekpub.bin -of ekcert.der -cakey ../utils/cakey.pem -capwd rrrr

> oiap

> nvreadvalue -ha 1000f000 -pwdo ooo -cert -se0 $OIAP 0

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


6 - Start the attestation server.  

E.g., 

> server -v -root ../utils/certificates/rootcerts.txt -imacert imakey.der >! serverenroll.log4j

-v and piping to a file are optional.

Client Setup
-------------

Set the TSS environment variables (e.g. TPM_INTERFACE_TYPE) if a
client HW TPM is being used.  See the TSS docs.

Optionally, set ACS_DIR to an existing directory where the ACS clients
store the AK private and public keys.

Provisioning a Client
---------------------

NOTE: With a hardware TPM, this can take several minutes, and appear
to hang.  Creating a primary key on a hardware TPM is a long calculation.

This installs the client attestation key certificate at the
attestation server.

TPM 2.0
- - - -

> clientenroll -alg rsa -v -ho cainl.watson.ibm.com -co akcert.pem >! clientenroll.log4j

or a different machine with EC

> clientenroll -alg ec -v -ho cainl.watson.ibm.com -ma cainlec.watson.ibm.com -co akeccert.pem >! clientenroll.log4j

where -ho is the hostname of the server, and is optional for
localhost.

-v and piping to a file are optional.

TPM 1.2 
- - - -

> clientenroll12 -pwdo ooo -co akcert12.pem -v

Running an Attestation
----------------------

*** One time per client reboot, if the client does not have an event
log (and none do today), and the PCRs are uninitialized, extend the
test event log tpm2bios.log into the TPM PCRs.  If the firmware has
already extended the PCRs, the event log will not match.

TPM 2.0
- - - -

tpm2bios.log is a sample event log.

> .../utils/eventextend -if tpm2bios.log -tpm -v >! b.log4j

imasig.log is a sample IMA log

> .../utils/imaextend -if imasig.log -le -v > ! i.log4j

As often as desired, run an attestation.

> client -alg rsa -ifb tpm2bios.log -ifi imasig.log -ho cainl.watson.ibm.com -v >! client.log4j

or 

> client -alg ec -ifb tpm2bios.log -ifi imasig.log -ho cainl.watson.ibm.com -v -ma cainlec.watson.ibm.com >! client.log4j

where -ho is the hostname of the server, and is optional for
localhost.

TPM 1.2
- - - -

> .../utils12//eventextend -if tpmbios.log -tpm 

> .../utils12/imaextend -if imasig.log -le

As often as desired, run an attestation.

> client12 -ifb tpmbios.log -ifi imasig.log -v

Code Structure
--------------

The client side are separated into the main client and clientenroll
executables and a clientlocal set of utilities.

The structure permits the client and clientenroll functions to be run
in a different space (perhaps a VM) than the (clientlocal) space that
has the TPM.  An interface would have to be provided to pass the
function parameters through.

Minimal TSS
-----------

For a client with a minimal local client environment, build a separate
minimal TSS.

> cd .../utils

To run with a HW TPM on a platform with no socket library, add to CCFLAGS  
	-DTPM_NOSOCKET
	
create the minimal TSS for the ACS first, then the fill TSS for the utilities

> make -f makefile.min clean all
> make clean all

build the ACS against the minimal TSS

> cd .../acs

build the server and the test code against the full TSS

> make clean server

build the client code against the minimal TSS

> make -f makefile.min clean all

Clearing a hostname for testing
-------------------------------

delete from machines where hostname = 'cainl.watson.ibm.com';
delete from attestlog where hostname = 'cainl.watson.ibm.com';
delete from imalog where hostname = 'cainl.watson.ibm.com';

delete from machines where hostname = 'cainlec.watson.ibm.com';
delete from attestlog where hostname = 'cainlec.watson.ibm.com';
delete from imalog where hostname = 'cainlec.watson.ibm.com';


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
	pcr00-pcr23 - white list, values from first valid quote

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
	logverified - boolean flag, PCR digest from event logs matches quote
	imaver -      boolean flag, PCR digest from event logs matches quote
	logentries - number of entries in BIOS event log
	imaevents - number of entries in IMA event log
	pcrinvalid - boolean flag, pcrs different from white list
	badimalog - boolean flag, obsolete

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
	bios_entry - the raw bios event as hex ascii
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
	machines update
		boottime		
		imaevents		0
		imapcr			0000...

	attestlog insert
		userid
		hostname
		timestamp
		nonce
		pcrselect
		boottime

		new boot:
			pcrnn = 0000...
		incremental:
			pcrnn = previous pcrnn
				
At quote
	machines update

		if quoteverified
			boottime
			if logverified
				imapcr  
				imaevents
				if storePcrWhiteList	(first time)
					pcrnn
				imaevents	0
				imapcr		00...00
				
	atestlog update
		quote
		quoteverified 
		if quoteverified
			logverified
			imaver 
			if logverified
				logentries 
				pcrnn
				if !storePcrWhiteList	(not first time)
					pcrinvalid 
				pcrchanged
				imasigver
				
	bioslog
		if quoteverified and logverified 
			(for each event)
			hostname
			timestamp
			entrynum
			bios_entry
			pcrindex
			pcrsha1
			pcrsha256
			eventtype
			event
	
	imalog
		if quoteverified and logverified
			(for each event)
			hostname
			boottime
			timestamp
			entrynum
			ima_entry
			filename
			badevent
			nosig
			nokey
			badsig

