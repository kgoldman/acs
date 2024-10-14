# IBM Attestation Client Server

This includes installation, running, and design documentation for the
IBM Attestation Client Server.

The IMA event log format is documented at
https://ima-doc.readthedocs.io/en/latest/event-log-format.html# with
the document source at https://github.com/linux-integrity/ima-doc.

**Table of Contents**

1. [Installation](#installation)
   1. [RHEL, Centos and recent Fedora](#rhel-centos-and-recent-fedora)
   2. [RHEL attestation server](#rhel-attestation-server)
   3. [Centos and Recent Fedora Attestation Server](#centos-and-recent-fedora-attestation-server)
   4. [Ubuntu](#ubuntu)
   5. [Ubuntu Attestation Server](#ubuntu-attestation-server)
   6. [Database Schema at Attestation Server](#database-schema-at-attestation-server)
   7. [Build Libraries and Applications](#build-libraries-and-applications)
      1. [SW TPM](#sw-tpm)
      2. [TSS and Utilities](#tss-and-utilities)
      3. [PATH](#PATH)
      4. [Server Attestation Demo](#server-attestation-demo)
   8. [Provision the Server EK Certificate CA Signing Keys](#provision-the-server-ek-certificate-ca-signing-keys)
   9. [SW TPM Key Provisioning](#sw-tpm-key-provisioning)
   10. [Server Key Provisioning](#server-key-provisioning)
2. [Running the Server](#running-the-Server)
3. [Running a Client](#running-a-Client)
   1. [Enrolling a Client](#enrolling-a-client)
   2. [Running an Attestation](#running-an-attestation)
4. [Web UI](#web-ui)
4. [Code Structure](#code-structure)
5. [Database](#database)
   1. [Clearing a Database](#clearing-a-database)
   2. [Database Tables](#database-tables)
   3. [Code Flow at Database](#code-flow-at-database)
5. [Network Messages](#network-messages)
   1. [Enrollment](#enrollment)
      1. [Client to Server Initiation](#client-to-server-initiation)
      2. [Server to Client Challenge](#server-to-client-challenge)
      3. [Client to Server Response to the Challenge](#client-to-server-response-to-the-challenge)
      4. [Server to Client Attestation Key Certificate](#server-to-client-attestation-key-certificate)
   2. [Attestation](#attestation)
      1. [Client to Server Request for Nonce](#client-to-server-request-for-nonce)
      2. [Full Attestation Request - Server to Client](#full-attestation-request---server-to-client)
      3. [Attestation Response - Client to Server](#attestation-response---client-to-server)
      4. [Incremental Attestation Request - Server to Client](#incremental-attestation-request---server-to-client)
      5. [Incremental Attestation Response - Client to Server](#incremental-attestation-response---client-to-server)

## Installation

Some steps are only for the client (attesting program), some only for
the server (verifier).  If not noted, the steps are for both the
client and server.  and some are for both.

### json note

The distros can't seem to decide whether the json include directory is
/usr/include/json or /usr/include/json-c.

This uses /usr/include/json.  If your distro uses json-c, just make a soft link:

```
# cd /usr/include
# ln -s json-c json
```

### RHEL, Centos and recent Fedora

Install these packages.

* openssl
* openssl-devel		(tested with 1.0.x, not tested with 1.1.x)
* json-c
* json-c-devel

### RHEL Attestation **Server**

Install these packages.

* mysql
* mysql-devel
* php
* php-devel
* php-mysql or php-mysqlnd

```
# service mysqld start
# service httpd start
```

### Centos and Recent Fedora Attestation **Server**

Install these packages.

* mariadb
* mariadb-server

```
# systemctl start mariadb.service
# systemctl enable mariadb.service
```

### Ubuntu

Install these packages. The names may vary with the distro version.

* libjson-c3 or libjson-c4
* libjson-c-dev

### Ubuntu Attestation **Server**

Install these packages.

* apache2
* mariadb-server
* libmysqlclient-dev
* php
* php5-dev
* php-mysql


### Database Schema at Attestation **Server**

Install the Database Schema at the attestation **server**

As **root**

```
# /etc/init.d/apache2 start

# mysql
mysql> create database tpm2;
mysql> grant all privileges on tpm2.* to ''@'localhost';
```

For the error "Can't find any matching row in the user table"

```
mysql> grant all privileges on tpm2.* to ''@'localhost' identified by '';
```


As **non-root**

```
> mysql -D tpm2 < dbinit.sql
```

### Build Libraries and Applications

The makefiles and these instructions assume that the TSS is built in
../utils.  If not, adjust accordingly.  When the TSS is installed in
/usr/lib as part of a distribution, this becomes unnecessary.

#### SW TPM

If using a SW TPM, The SW TPM is [here] (https://sourceforge.net/projects/ibmswtpm2/)

```
> cd .../tpm2/src
> make
```

#### TSS and Utilities

Create the TSS and utilities.  create libtss.so

The TSS is [here] (https://sourceforge.net/projects/ibmtpm20tss/)

1. For a TPM 2.0 TSS

```
> cd .../tpm2/utils
> make -f makefiletpm20
```

2. For a combined TPM 1.2 and TPM 2.0 TSS

```
> cd .../tpm2/utils
> make -f makefiletpmc
> cd .../tpm2/utils12
> make -f makefiletpmc
```

#### PATH

If the TSS is not *installed*, the ACS programs must point
to the TSS library [path].  When the TSS is installed in /usr/lib as
part of a distribution, this step becomes unnecessary.

* csh variants

```
> setenv LD_LIBRARY_PATH [path]/tpm2/utils:[path]/tpm2/utils12
```

* bash variants

```
> export LD_LIBRARY_PATH=[path]/tpm2/utils:[path]/tpm2/utils12
```

#### Server Attestation Demo

```
# mkdir /var/www/html/acs
# chown user /var/www/html/acs
# chgrp user /var/www/html/acs
# chmod 777  /var/www/html/acs


> cd .../tpm2/acs
```

1. For TPM 2.0 client and server

```
> make
```

2. For TPM 1.2 client (requires TPM 1.2 / TPM 2.0 server)

```
> make -f makefiletpm12
```

For TPM 1.2 and TPM 2.0 client and TPM 1.2 / TPM 2.0 server

3. For TPM 2.0 and 1.2 client and server

```
> make -f makefiletpmc
```

4. Path

These notes are not required once the TSS is installed in the system
area through a package manager.

The makefile assumes that the TSS include and library directories are
in ../utils.  If not, specify that [path].


```
> setenv CPATH [path-to]/tpm2/utils
> setenv LIBRARY_PATH [path-to]/tpm2/utils
```

For TPM 1.2

```
> setenv CPATH [path-to]/tpm2/utils:[path-to]/tpm2/utils12
> setenv LIBRARY_PATH [path-to]/tpm2/utils:[path-to]/tpm2/utils12
```

### Provision the **Server** EK Certificate CA Signing Keys

This **optional** step is only required if changing the endorsement
key CA signing key cakey.pem / cacert.pem included in the package.

This is done **once per software install**.

This is **only** required when using a SW TPM.

1. Create an RSA EK certificate server CA signing key

```
> cd .../tpm2/acs
> openssl genrsa -out cakey.pem -aes256 -passout pass:rrrr 2048
```

2. Create a self signed EK root CA certificate

```
> openssl req -new -x509 -key cakey.pem -out cacert.pem -days 3650

Country Name (2 letter code) [XX]:US
State or Province Name (full name) []:NY
Locality Name (eg, city) [Default City]:Yorktown
Organization Name (eg, company) [Default Company Ltd]:IBM
Organizational Unit Name (eg, section) []:
Common Name (eg, your name or your server's hostname) []:EK CA
Email Address []:
```

3. View the certificate for correctness.  

```
> openssl x509 -text -in cacert.pem -noout
```

Issuer and subject should match.  Validity 20 years.  Etc.

4. Install the cacert.pem in the directory where the HW TPM root
certificates are.  Currently, that's .../tpm2/utils/certificates.

The HW TPM vendor root certificates should already be there.

5. Provision the ECC EK Certificate CA Signing Key

This **optional** step is only required if changing the endorsement
key CA signing key cakeyecc.pem / cacertecc.pem included in the
package.

This **optional** step requires at least openssl 1.0.2. 1.0.1 will not
work.

```
> openssl genpkey -out cakeyecc.pem -outform PEM -pass pass:rrrr -aes256 -algorithm ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve
```

6. Create a self signed EK root CA certificate

```
> openssl req -new -x509 -key cakeyecc.pem -out cacertecc.pem -days 3650

Country Name (2 letter code) [XX]:US
State or Province Name (full name) []:NY
Locality Name (eg, city) [Default City]:Yorktown
Organization Name (eg, company) [Default Company Ltd]:IBM
Organizational Unit Name (eg, section) []:
Common Name (eg, your name or your server's hostname) []:EK EC CA
Email Address []:
```

7. View the certificate for correctness.

```
openssl x509 -text -in cacertecc.pem -noout
```

Issuer and subject should match.  Validity 20 years.  Etc.

8. Install the cacertecc.pem in the directory where the HW TPM root
certificates are.  Currently, that's .../tpm2/utils/certificates.


### SW TPM Key Provisioning

This is **only** required for a SW TPM.  HW TPMs come with EK
certificates.

This is **only** required once per TPM.  It is installed in SW TPM
non-volatile memory.

The TPM 1.2 steps may be skipped for SW TPM 2.0 only Provisioning
 
1. TPM 2.0 Environment

The TSS will normally default to these.	

```
setenv TPM_COMMAND_PORT 2321
setenv TPM_SERVER_TYPE mssim
```

2. Start the SW TPM 2.0

```
.../tpm2/src> tpm_server
.../tpm2/utils> powerup;startup
```

3. Provision the SW TPM 2.0 with EK certificates

RSA public key and CA key

```
.../tpm2/utils> createekcert -rsa 2048 -cakey cakey.pem -capwd rrrr -v
```

ECC public key and CA key

```
.../tpm2/utils> createekcert -ecc nistp256 -cakey cakeyecc.pem -capwd rrrr -caalg ec -v
```

**CAUTION**  The EK and certificate will normally persist.  However,
running the TSS regression test rolls the EPS (endorsement hierarchy
primary seed), voiding everything.  You can reprovision and re-enroll,
but it's easier to make a copy of the SW TPM NV space now, and restore
it as necessary.

```
> cd .../tpm2/src
> cp NVChip NVChip.save
```

4. TPM 1.2 environment

```
setenv TPM_COMMAND_PORT 6543
setenv TPM_SERVER_TYPE rawsingle
setenv TPM_ENCRYPT_SESSIONS 0
```

4. Start the SW TPM 1.2

Remove the 00.permall state file, so that an EK certificate index can be defined with the D bit set

```
.../tpm/src> tpm_server >! tpm.log
```

5. Startup, Create TPM 1.2 EK, create an SRK, use the default all zeros SRK password

```
.../utils12> tpminit; startup
.../utils12> createendorsementkeypair
.../utils12> oiap
.../utils12> takeownership -pwdo ooo -se0 [handle from OIAP] 0
```

2 - Provision the SW TPM 1.2 with EK certificates.  Does the following

* starts an OSAP session and uses it to define the EK certificate NV index
* secures the NV space
* reads the EK public key
* creates and provisions the EK certificate
* reads the certificate back for testing

All in the .../utils12 directory

$OSAP is the handle from the OSAP command
$OIAP is the handle from the OIAP command

```
> osap -ha 40000001 -pwd ooo
> nvdefinespace -ha 1000f000 -sz 1400 -per 20002 -se0 $OSAP 0 
> nvdefinespace -ha ffffffff -sz 0
> oiap
> ownerreadinternalpub -ha ek -pwdo ooo -op ekpub.bin -se0 $OIAP 0
> createekcert -pwdo ooo -iek ekpub.bin -of ekcert.der -cakey ../utils/cakey.pem -capwd rrrr
> oiap
> nvreadvalue -ha 1000f000 -pwdo ooo -cert -se0 $OIAP 0
```

### Server Key Provisioning

This is **only** required if changing privacy CA signing key
pcakey.pem / pcacert.pem included in the package.

1. Create a privacy CA signing key

```
> cd .../tpm2/acs
> openssl genrsa -out pcakey.pem -aes256 -passout pass:rrrr 2048
```

2. Create a self signed privacy CA certificate

```
> openssl req -new -x509 -key pcakey.pem -out pcacert.pem -days 3560
```

Use AK CA as the common name

3. View the certificate for correctness.  

```
> openssl x509 -text -in pcacert.pem -noout
```
## Running the Server

1. The server uses a TPM as a crypto coprocessor.  It must point to a
different (typically a software) TPM and TSS data directory.

  1. If the server is being run on the same machine as the client:

```
> cd .../tpm2/acs
	for example
> export TPM_DATA_DIR=/gsa/yktgsa/home/k/g/kgold/tpm2
	or
> setenv TPM_DATA_DIR /gsa/yktgsa/home/k/g/kgold/tpm2
```

  2. Start the SW TPM service

```
> .../tpm2/src/tpm_server
> .../tpm2/utils/powerup
> .../tpm2/utils/startup
```

2. Edit the file .../tpm2/utils/certificates/rootcerts.txt 

Change the path name to wherever the directory is installed.

3. Set the server port

```
setenv ACS_PORT	2323
```

4. **Optional:** Set the mysql userid/password

The mysql instructions above don't set a DB host and port, userid and
password, or database name.  However if you have one set in your
configuration you can set it using these environment variables.

```
ACS_SQL_HOST - defaults to localhost
ACS_SQL_PORT - defaults to 0, MySQL will use its default
ACS_SQL_USERID - defaults to current user
ACS_SQL_PASSWORD - defaults to empty
ACS_SQL_DATABASE - defaults to tpm2
```

5. Start the attestation server 

E.g., 

```
> server -v -root ../utils/certificates/rootcerts.txt -imacert imakey.der >! serverenroll.log4j
```

-v and piping to a file are optional.

## Running a Client

Set the TSS environment variables (e.g. TPM_INTERFACE_TYPE) if a
client HW TPM is being used.  See the TSS docs.

Optionally, set ACS_DIR to an existing directory where the ACS clients
store the AK private and public keys.

### Enrolling a Client

NOTE: With a hardware TPM, this can take several minutes, and appear
to hang.  Creating a primary key on a hardware TPM is a long
calculation.

This installs the client attestation key certificate at the
attestation server.

1. TPM 2.0

```
> clientenroll -alg rsa -v -ho cainl.watson.ibm.com -co akcert.pem >! clientenroll.log4j
```

2. or a different machine with ECC

```
> clientenroll -alg ec -v -ho cainl.watson.ibm.com -ma cainlec.watson.ibm.com -co akeccert.pem >! clientenroll.log4j
```

where -ho is the hostname of the server, and is **optional** for localhost.

-v and piping to a file are optional.

2. TPM 1.2 


```
> clientenroll12 -pwdo ooo -co akcert12.pem -v
```

### Running an Attestation

1. One time per client reboot

If the client does not have an event log, and the PCRs are
uninitialized, extend the test event log into the TPM PCRs.  If the
firmware has already extended the PCRs, the event log will not match.
Simimarly, extend a test IMA event log.

#### TPM 2.0

tpm2bios.log is a sample event log. imasig.log is a sample IMA log.

```
> .../utils/eventextend -if tpm2bios.log -tpm -v >! b.log4j
> .../utils/imaextend -if imasig.log -le -v > ! i.log4j
```

#### TPM 1.2

tpmbios.log is a sample event log. imasig.log is a sample IMA log.

```
> .../utils12//eventextend -if tpmbios.log -tpm 
> .../utils12/imaextend -if imasig.log -le
```

2. As often as desired, run an attestation.

#### TPM 2.0


```
> client -alg rsa -ifb tpm2bios.log -ifi imasig.log -ho cainl.watson.ibm.com -v >! client.log4j
or
> client -alg ec -ifb tpm2bios.log -ifi imasig.log -ho cainl.watson.ibm.com -v -ma cainlec.watson.ibm.com >! client.log4j
```


where -ho is the hostname of the server, and is **optional** for localhost.

#### TPM 1.2 Attestation

```
> client12 -ifb tpmbios.log -ifi imasig.log -v
```

## Web UI

The demo web UI is at http://hostname/acs  where hostname is the web server is running.

The intent of the UI is to demo the internals of the TCG attestation
technology.  It is not what a datacenter cloud administrator would
see.

There are pages to 

* view the enrolled machines and their certificates
* view reports
* view BIOS / UEFI pre-OS event logs
* view IMA post-OS event logs

## Code Structure

The client side is separated into the main client and clientenroll
executables and a clientlocal set of utilities.

The structure permits the client and clientenroll functions to be run
in a different space (perhaps a VM) than the (clientlocal) space that
has the TPM.  An interface would have to be provided to pass the
function parameters through.

### Minimal TSS  **Option**

For a client with a minimal local client environment, build a separate
minimal TSS.

```
> cd .../utils
```

To run with a HW TPM on a platform with no socket library, add to CCFLAGS
	-DTPM_NOSOCKET

create the minimal TSS for the ACS first, then the full TSS for the utilities

```
> make -f makefile.min clean all
> make clean all
```

build the ACS against the minimal TSS

```
> cd .../acs
```

Build the server and the test code against the full TSS

```
> make clean server
```

Build the client code against the minimal TSS

```
> make -f makefile.min clean all
```

## Database

### Clearing a Database

To erase a host completely for testing

For example:

```
delete from machines where hostname = 'cainl.watson.ibm.com';
delete from attestlog where hostname = 'cainl.watson.ibm.com';
delete from imalog where hostname = 'cainl.watson.ibm.com';

delete from machines where hostname = 'cainlec.watson.ibm.com';
delete from attestlog where hostname = 'cainlec.watson.ibm.com';
delete from imalog where hostname = 'cainlec.watson.ibm.com';
```


### Database Tables

This design retains all enrollment and attestation at the attestation
server database to permit post-incident forensics.  It decouples the
attestation and the UI display.


```
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
```

## Code Flow at Database

```
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

```

## Network Messages

Below are example messages.

Messages are a push (client to server) rather than a pull (server to client) for several reasons:

* Client machines are likely to be behind a restricted firewall, blocking incoming messages
* Client machines must be secured, and listening on an Internet port is an attack point
* Client machines may be powered down and should not be woken for an attestation
* Embedded devices may be resource constrained or performing critical tasks, and should not be interrupted for attestation.

### Enrollment

#### Client to Server Initiation

```
{
  "command":"enrollrequest",
  "hostname":"cainl.watson.ibm.com",
  "tpmvendor":"IBM ",
  "intermediatecert":"3082021b308201c1a003..."
  "ekcert":"3082033e30820224a0...",
  "akpub":"0001000b00050472000..."
}
```

#### Server to Client Challenge

```
{
  "response":"enrollrequest",
  "credentialblob":"004400201e1e1d6e18f...",
  "secret":"01009ca04f45c64b668243b25f6d5b..."
}

```

#### Client to Server Response to the Challenge

```
{
  "command":"enrollcert",
  "hostname":"cainl.watson.ibm.com",
  "challenge":"428108c592b7d6e9f044b75ac..."
}
```


#### Server to Client Attestation Key Certificate

```
{
  "response":"enrollcert",
  "akcert":"-----BEGIN CERTIFICATE-----\nMIICQjCCASq...-----END CERTIFICATE-----\n"
}
```


### Attestation


#### Client to Server Request for Nonce

```
{
  "command":"nonce",
  "hostname":"cainl.watson.ibm.com",
  "userid":"kgold"
  "boottime":"2016-12-07 21:51:55"
}
```


#### Full Attestation Request - Server to Client

The 0's indicate a new boot cycle, so the server requests full logs.


```
{
  "response":"nonce",
  "nonce":"20cc9ed33d0e38857e33291d16ff3022939c1107a56b5bf90ca322fb333003a4",
  "pcrselect":"00000002000b03ff0400000403000000"
  "biosentry":"0",
  "imaentry":"0"
}
```

#### Attestation Response - Client to Server

eventn are pre-OS (BIOS, UEFI) events.  imaeventn are post-OS (IMA) events.


```
{
  "command":"quote",
  "hostname":"cainl.watson.ibm.com",
  "quoted":"ff54434780180022000b69aa5045716e7...",
  "signature":"0014000b010009550bf47342b92052...",
  "event0":"00000000000000030000000000055a480000010046...",
  "event1":"000000010000000500000002000b00000000000000...",
  "imaevent0":"0000000a17f427af544b919270aa8ac3dd06e8a...",
  "imaevent1":"0000000a661ae12f7a72e3dff4226ecb6426f6a...",
  "imaevent2":"0000000af50d178680908e72f5f53128255507d...",
```


#### Incremental Attestation Request - Server to Client

The design implements incremental attesation to greatly improve
performance.

The server has detected the same boot cycle.  The -1 indicates that
the pre-OS event log need not be sent.  The 11 indicates that IMA
events starting with 11 should be sent.

```
{
  "response":"nonce",
  "nonce":"ef4efe07f2943d15c93061e681af95da9ebf94bab6124c4d3621c81a09afc61d",
  "pcrselect":"00000002000b03ff0700000403000000",
  "biosentry":"-1",
  "imaentry":"11"
}
```
#### Incremental Attestation Response - Client to Server

In this case, the client has no new IMA events to send.


```
{
  "command":"quote",
  "hostname":"cainl.watson.ibm.com",
  "quoted":"ff54434780180022000b69aa5045716e7...",
  "signature":"0014000b010009550bf47342b92052...",
}
```

