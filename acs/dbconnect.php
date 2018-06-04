<?php
/* $Id: dbconnect.php 1198 2018-05-04 15:06:06Z kgoldman $			*/
/*										*/
/* (c) Copyright IBM Corporation 2018.						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* connect to the database */

/* host and port */

$acs_sql_host = getenv('ACS_SQL_HOST');
if ($acs_sql_host == false) {
    $acs_sql_host = ini_get("mysql.default.host");
    if ($acs_sql_host == false) {
	$acs_sql_host = "localhost";
    }
}

$acs_sql_port = getenv('ACS_SQL_PORT');
if ($acs_sql_port == false) {
    $acs_sql_port = ini_get("mysql.default.port");
}
if ($acs_sql_port == true) {
    $acs_sql_host .= ":" . $acs_sql_port;
}

/* user ID and password */

$acs_sql_userid = getenv('ACS_SQL_USERID');
if ($acs_sql_userid == false) {
    $acs_sql_userid = ini_get("mysql.default.user");
}

$acs_sql_password = getenv('ACS_SQL_PASSWORD');
if ($acs_sql_password == false) {
    $acs_sql_password = ini_get("mysql.default.password");
} 

/* database name */

$acs_sql_database = getenv('ACS_SQL_DATABASE');
if ($acs_sql_database == false) {
    $acs_sql_database = "tpm2";
}

$connect = new mysqli($acs_sql_host, $acs_sql_userid, $acs_sql_password, $acs_sql_database);
if (!$connect) {
    die("Could not connect to database: " . $acs_sql_database . "\n" . mysqli_error() . "\n");
}

?>
