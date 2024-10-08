#!/bin/bash
#

#################################################################################
#										#
#			ACS Client Server Regression Test			#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2024					        #
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

# where server is running
export SERVER="cain.watson.ibm.com"
# Start the server in another window
#server -root ../utils/certificates/rootcerts.txt -imacert imakey.der -imacert fedora-40-ima.der &

# client base name, add suffix for AK calgorithms
export CLIENT="cain.watson.ibm.com"

# directory for TSS commands
export TSSDIR=../../tss2/utils/

checkSuccess()
{
    if [ $1 -ne 0 ]; then
	echo " ERROR:"
	cat run.out
	exit 255
    else
	echo " INFO:"
    fi
}

checkFailure()
{
    if [ $1 -eq 0 ]; then
	echo " ERROR:"
	cat run.out
	exit 255
    else
	echo " INFO:"
    fi
}

echo "Reset the databases"

echo "Reset RSA 2K AK"
mysql -D tpm2 -e "delete from machines  where hostname = 'rsa2k${CLIENT}';"
mysql -D tpm2 -e "delete from attestlog where hostname = 'rsa2k${CLIENT}';"
mysql -D tpm2 -e "delete from imalog    where hostname = 'rsa2k${CLIENT}';"

echo "Reset RSA 3K AK"
mysql -D tpm2 -e "delete from machines  where hostname = 'rsa3k${CLIENT}';"
mysql -D tpm2 -e "delete from attestlog where hostname = 'rsa3k${CLIENT}';"
mysql -D tpm2 -e "delete from imalog    where hostname = 'rsa3k${CLIENT}';"

echo "Reset ECC P256 AK"
mysql -D tpm2 -e "delete from machines  where hostname = 'ecp256${CLIENT}';"
mysql -D tpm2 -e "delete from attestlog where hostname = 'ecp256${CLIENT}';"
mysql -D tpm2 -e "delete from imalog    where hostname = 'ecp256${CLIENT}';"

echo "Reset ECC P384 RSA AK"
mysql -D tpm2 -e "delete from machines  where hostname = 'ecp384${CLIENT}';"
mysql -D tpm2 -e "delete from attestlog where hostname = 'ecp384${CLIENT}';"
mysql -D tpm2 -e "delete from imalog    where hostname = 'ecp384${CLIENT}';"

echo "Power up the TPM"
${TSSDIR}powerup
checkSuccess $?

echo "Startup theTPM"
${TSSDIR}startup
checkSuccess $?

echo "Create EK Certificate RSA 2048"
${TSSDIR}createekcert -rsa 2048       -cakey cakey.pem    -capwd rrrr           -v > run.out
checkSuccess $?

echo "Create EK Certificate RSA 3072"
${TSSDIR}createekcert -high -rsa 3072 -cakey cakey.pem    -capwd rrrr           -v > run.out
checkSuccess $?

echo "Create EK Certificate ECC P256"
${TSSDIR}createekcert -ecc nistp256   -cakey cakeyecc.pem -capwd rrrr -caalg ec -v > run.out
checkSuccess $?

echo "Create EK Certificate ECC P384"
${TSSDIR}createekcert -ecc nistp384   -cakey cakeyecc.pem -capwd rrrr -caalg ec -v > run.out
checkSuccess $?

echo "Enroll the Attestation Key RSA 2048"
clientenroll -alg rsa 2048    -v -ho ${SERVER} -ma rsa2k${CLIENT}  -co akcert2k.pem     > run.out
checkSuccess $?

echo "Enroll the Attestation Key RSA 3072"
clientenroll -alg rsa 3072    -v -ho ${SERVER} -ma rsa3k${CLIENT}  -co akcert3k.pem     > run.out
checkSuccess $?

echo "Enroll the Attestation Key ECC P256"
clientenroll -alg ec nistp256 -v -ho ${SERVER} -ma ecp256${CLIENT} -co akeccertp256.pem > run.out
checkSuccess $?

echo "Enroll the Attestation Key ECC P384"
clientenroll -alg ec nistp384 -v -ho ${SERVER} -ma ecp384${CLIENT} -co akeccertp384.pem > run.out
checkSuccess $?

echo ""
echo "Hash agile IMA event logs"
echo ""

echo "Extend UEFI PCRs"
${TSSDIR}eventextend -tpm -if tpm2bios.log
checkSuccess $?

echo "Extend IMA PCR"
${TSSDIR}imaextend  -le -if ${TSSDIR}sha256.log -ealg sha256 > run.out
checkSuccess $?

for EALG in sha1 sha256 sha384 sha512
do
    echo "Client attestation Event Log ${EALG} AK Alg RSA 2048 machine rsa2k${CLIENT}"
    client -alg rsa -ifb tpm2bios.log -ifi ../utils/${EALG}.log -ho ${SERVER} -ma rsa2k${CLIENT} -ealg ${EALG} -bt -v > run.out
    checkSuccess $?

    echo "Client attestation Event Log ${EALG} AK Alg RSA 3072 machine rsa3k${CLIENT}"
    client -alg rsa -ifb tpm2bios.log -ifi ../utils/${EALG}.log -ho ${SERVER} -ma rsa3k${CLIENT} -ealg ${EALG} -bt -v > run.out
    checkSuccess $?

    echo "Client attestation Event Log ${EALG} AK Alg ECC P256 machine ecp256${CLIENT}"
    client -alg ec  -ifb tpm2bios.log -ifi ../utils/${EALG}.log -ho ${SERVER} -ma ecp256${CLIENT} -ealg ${EALG} -bt -v > run.out
    checkSuccess $?

    echo "Client attestation Event Log ${EALG} AK Alg ECC P384 machine ecp384${CLIENT}"
    client -alg ec  -ifb tpm2bios.log -ifi ../utils/${EALG}.log -ho ${SERVER} -ma ecp384${CLIENT} -ealg ${EALG} -bt -v > run.out
    checkSuccess $?

done

echo ""
echo "IMA synthetic test IMA event log"
echo ""

echo "Reset RSA 2K AK"
mysql -D tpm2 -e "delete from machines  where hostname = '${CLIENT}';"
mysql -D tpm2 -e "delete from attestlog where hostname = '${CLIENT}';"
mysql -D tpm2 -e "delete from imalog    where hostname = '${CLIENT}';"

echo "Power up the TPM"
${TSSDIR}powerup
checkSuccess $?

echo "Startup theTPM"
${TSSDIR}startup
checkSuccess $?

echo "Create EK Certificate RSA"
${TSSDIR}createekcert -rsa 2048 -cakey cakey.pem -capwd rrrr -v > run.out
checkSuccess $?

echo "Enroll the Attestation Key RSA 2048"
clientenroll -alg rsa 2048 -v -ho ${SERVER} -ma ${CLIENT} -co akcert2k.pem > run.out
checkSuccess $?

echo "Extend UEFI PCRs"
${TSSDIR}eventextend -tpm -if tpm2bios.log > run.out
checkSuccess $?

echo "Extend IMA PCR"
${TSSDIR}imaextend  -le -if imasig.log -ealg sha1 > run.out
checkSuccess $?

echo "Client Attestation"
client -alg rsa -ifb tpm2bios.log -ifi imasig.log -ho ${SERVER} -ma ${CLIENT} > run.out
checkSuccess $?



