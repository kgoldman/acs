<?php
// $Id: bios.php 1198 2018-05-04 15:06:06Z kgoldman $

/* (c) Copyright IBM Corporation 2017, 2018.					*/
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
require("dbconnect.php");
?>

<html>
<head>
<title>TPM 2.0 BIOS Reports</title>  
<link rel="stylesheet" type="text/css" href="demo.css">
</head>

<body>
<div id="header">
<img src="ibm.png" style="float:right;width:200px;height:100px">
<h2>TPM 2.0 BIOS Reports</h2>
<?php
require 'header.php';
?>
</div>
<?php
require 'navigation.php';
?>

<?php

$where = "";

if(isset($_GET["hostname"]))
{
    $hostname = $_GET["hostname"];
    $where = " WHERE hostname = '$hostname'";
    echo "<h2>BIOS Report for <a href=\"machines.php?hostname=" . $hostname . "\">" . $hostname . "</a></h2>\n";
}
else {
    echo "<h2>No hostname!</h2>\n";
}

if(isset($_GET["timestamp"]))
{
    $timestamp = $_GET["timestamp"];
    $where .= " AND timestamp  = '$timestamp'";
}
else {
    echo "<h2>No timestamp!</h2>\n";
}
?>

<table>
<tr>
<th>Timestamp</th>

<?php

// default
$order = " ORDER BY bioslog.entrynum ASC";
$sorttype = "sort=entrynumasc";
$filtertype = "";

if(isset($_GET["sort"]))
{
	$sort = $_GET["sort"];
	switch($sort)
	    {
	      case "entrynumasc":
		$order = " ORDER BY bioslog.entrynum ASC";
		$sorttype = "sort=entrynumasc";
		break;
	      case "entrynumdesc":
		$order = " ORDER BY bioslog.entrynum DESC";
		$sorttype = "sort=entrynumdesc";
		break;
	      default:
		$order = " ORDER BY bioslog.entrynum ASC";
		$sorttype = "sort=entrynumasc";
		break;
	    }
}

// Event number column

switch($sorttype)
{
	case "sort=entrynumdesc":
		echo "<th><a href=\"bios.php?sort=entrynumasc&hostname=" . $hostname . "&timestamp=" . $timestamp . "\">Event<br>Number</a></th>\n";
		break;
	case "sort=entrynumasc":
		echo "<th><a href=\"bios.php?sort=entrynumdesc&hostname=" . $hostname . "&timestamp=" . $timestamp . "\">Event<br>Number</a></th>\n";
		break;
	default:
		echo "<th><a href=\"bios.php?sort=entrynumasc&hostname=" . $hostname . "&timestamp=" . $timestamp . "\">Event<br>Number</a></th>\n";
		break;
}

//  PCR number column
echo "<th>PCR<br/>Number</th>\n";

//  PCR value column
echo "<th>SHA-1 Hash<br/>SHA-256 Hash</th>\n";

// Event Type
echo "<th>Event<br/>Type</th>\n";

// Event
echo "<th>Event</th>\n";

echo "</tr>\n";

$result = mysqli_query($connect, "SELECT id, hostname, timestamp, entrynum, pcrindex, pcrsha1, pcrsha256, eventtype, event FROM bioslog " . $where . $filtertype . $order);

if(!mysqli_num_rows($result)) {
    echo "<tr><td>No Results</td></tr>";
}

else {
    while($row = mysqli_fetch_array($result)) {

	echo "<tr>";

	echo "<td>" . $row["timestamp"] . "</td>\n";

	echo "<td><a href=\"biosevent.php?hostname=" . $row["hostname"] . "&entrynum=" . $row["entrynum"] . "&timestamp=" . $row["timestamp"] . "\">" . $row["entrynum"] . "</td>\n";

	echo "<td>" . $row["pcrindex"] . "</td>\n";

	echo "<td>" . $row["pcrsha1"] . "<br>" . $row["pcrsha256"] . "</td>\n";
	
	echo "<td>" . $row["eventtype"] . "</td>\n";

	echo "<td>" . $row["event"] . "</td>\n";

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
