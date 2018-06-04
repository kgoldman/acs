<?php
/* $Id: machines.php 1198 2018-05-04 15:06:06Z kgoldman $			*/
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

ini_set('display_errors', 1);

/* connect to the database */
require("dbconnect.php");

?>

<html>
<head>
<title>TPM 2.0 Attestation Machines</title>  
<link rel="stylesheet" type="text/css" href="demo.css">
</head>

<body>
<div id="header">
<img src="ibm.png" style="float:right;width:200px;height:100px">
<h2>TPM 2.0 Attestation Machines</h2>
<?php
require 'header.php';
?>
</div>
<?php
require 'navigation.php';
?>

<h2>Enrolled Machines</h2>
<table border=1>
<tr>
<th>Machine</th>
<th>TPM Vendor</th>
<th>Enrolled</th>
<th>EK Certificate</th>
<th>AK Certificate</th>
<th>Boot Time</th>
</tr>

<?php

$where = "";

if(isset($_GET["hostname"]))
{
    $hostname = $_GET["hostname"];
    $where = " WHERE hostname = '$hostname'";
}

$result = mysqli_query($connect, "SELECT id, hostname, tpmvendor, enrolled, boottime, akcertificatepem FROM machines " . $where . " ORDER BY id DESC");
if(!mysqli_num_rows($result)) {
    echo "<tr><td>No Results</td></tr>";
}
else {
    while($row = mysqli_fetch_array($result)) {
	echo "<tr>";

	echo "<td><a href=\"reports.php?hostname=" . $row["hostname"] . "\">" . $row["hostname"] . "</td>";

	if (!is_null($row["akcertificatepem"])) {

	    echo "<td>" . $row["tpmvendor"] . "</td>";
	    echo "<td>" . $row["enrolled"] . "</td>";

	    echo "<td align=\"center\"><a href=\"ekcertificate.php?id=" . $row["id"] . "\"><img src=\"cert.png\" width=\"16\" height=\"16\" ></a></td>";
	    echo "<td align=\"center\"><a href=\"akcertificate.php?id=" . $row["id"] . "\"><img src=\"cert.png\" width=\"16\" height=\"16\" ></a></td>";

	}
            else {
		echo "<td></td>";
		echo "<td></td>";
		echo "<td align=\"center\"><img src=\"red.png\" width=\"16\" height=\"16\"></td>\n";
		echo "<td align=\"center\"><img src=\"red.png\" width=\"16\" height=\"16\"></td>\n";
	    }

	    echo "<td>" . $row["boottime"] . "</td>";

	    echo "</tr>";
	}
	}
?>

</table>

<?php
require 'footer.php';

/* close the database connection */
mysqli_close($connect);
?>

</body>
</html>
