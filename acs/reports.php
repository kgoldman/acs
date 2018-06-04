<?php
// $Id: reports.php 1198 2018-05-04 15:06:06Z kgoldman $

/* (c) Copyright IBM Corporation 2016, 2018.					*/
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
	<title>TPM 2.0 Attestation Reports</title>  
	<link rel="stylesheet" type="text/css" href="demo.css">
    </head>

    <body>
	<div id="header">
	    <img src="ibm.png" style="float:right;width:200px;height:100px">
	    <h2>TPM 2.0 Attestation Reports</h2>
	    <?php
	    require 'header.php';
	    ?>
	</div>
	<?php
	require 'navigation.php';
	?>

	<h2>Attestation Reports</h2>
	<table>
	    <tr>
		<th>Machine</th>
		<th>User</th>
		<th>Report</th>
		<th align="center">Quote<br/>Signature</th>
		<th align="center">BIOS<br>PCRs<br/>Unchanged</th>
		<th align="center">BIOS<br>PCRs<br/>Valid</th>
		<th align="center">Invalid<br>BIOS<br>PCRs</th>
		<th align="center">BIOS<br/>Event<br/>Log<br/>Verified</th>
		<th align="center">BIOS<br/>Events</th>
		<th align="center">IMA<br/>Event<br/>Log<br/>Verified</th>
		<th align="center">IMA<br/>Signatures<br/>Verified</th>
		<th align="center">IMA<br/>Events</th>
	    </tr>

	    <?php

	    $where = "";

	    if(isset($_GET["hostname"]))
	    {
		$hostname = $_GET["hostname"];
		$where = " WHERE hostname = '$hostname'";
	    }
	    // get all attestlog rows

	    $aresult = mysqli_query($connect, "SELECT id, userid, hostname, boottime, timestamp, quoteverified, imaver, pcrschanged, pcrinvalid, logverified, logentries, imaevents, imasigver FROM attestlog " . $where . "ORDER BY id DESC");

	    if(!mysqli_num_rows($aresult)) {
		echo "<tr><td>No Results</td></tr>";
	    }

	    else {
		while($arow = mysqli_fetch_array($aresult)) {

		    // get the machines DB row for the hostname 

		    //	$mresult = mysqli_query($connect, "SELECT id, imaevents FROM machines WHERE hostname = '" . $arow["hostname"] . "'");
		    //	$mrow = mysqli_fetch_array($mresult);

		    echo "<tr>";

		    // machine
		    echo "<td><a href=\"machines.php?hostname=" . $arow["hostname"] . "\">" . $arow["hostname"] . "</td>\n";

		    // user
		    echo "<td>" . $arow["userid"] . "</td>\n";

		    // report timestamp with link to id
		    echo "<td><a href=\"report.php?id=" . $arow["id"] . "\">" . $arow["timestamp"] . "</td>\n";

		    // quote verified
		    if ($arow["quoteverified"] == "1") {

			// quote signature
			echo "<td align=\"center\"><img src=\"green.png\" width=\"16\" height=\"16\"></td>\n";
			
			// PCRs unchanged
			if ($arow["pcrschanged"] == "0") {
			    echo "<td align=\"center\"><img src=\"green.png\" width=\"16\" height=\"16\"></td>\n";
			}
			else if ($arow["pcrschanged"] == "1") {
			    echo "<td align=\"center\"><img src=\"red.png\" width=\"16\" height=\"16\"></td>\n";
			}
			else {
			    echo "<td></td>\n";
			}

			// PCRs valid
			if ($arow["pcrinvalid"] == "0") {
			    echo "<td align=\"center\"><img src=\"green.png\" width=\"16\" height=\"16\"></td>\n";
			    echo "<td></td>\n";
			}
			else if ($arow["pcrinvalid"] == "1") {
			    echo "<td align=\"center\"><img src=\"red.png\" width=\"16\" height=\"16\"></td>\n";
			    echo "<td><a href=\"pcrinvalid.php?id=" . $arow["id"] . "\">PCR</td>\n";
			}
			else {
			    echo "<td></td>\n";
			    echo "<td></td>\n";
			}

			// BIOS event log verified
			if ($arow["logverified"] == "1") {
			    echo "<td align=\"center\"><img src=\"green.png\" width=\"16\" height=\"16\"></td>\n";
			}
			else if ($arow["logverified"] == "0") {
			    echo "<td align=\"center\"><img src=\"red.png\" width=\"16\" height=\"16\"></td>\n";
			}
			else {
			    echo "<td></td>\n";
			}
			
			// BIOS events with link to bios.php based on hostname and boottime
			if ($arow["logverified"] == "1") {
			    echo "<td><a href=\"bios.php?hostname=" . $arow["hostname"] . "&timestamp=" . $arow["timestamp"] . "\">" . $arow["logentries"] . "</td>\n";
			}
			else {
			    echo "<td></td>\n";
			}

			// IMA event log verified
			if ($arow["imaver"] == "1") {
			    echo "<td align=\"center\"><img src=\"green.png\" width=\"16\" height=\"16\"></td>\n";
			}
			else if ($arow["imaver"] == "0") {
			    echo "<td align=\"center\"><img src=\"red.png\" width=\"16\" height=\"16\"></td>\n";
			}
			else {
			    echo "<td></td>\n";
			}

			// IMA signatures verified
			if ($arow["imasigver"] == "1") {
			    echo "<td align=\"center\"><img src=\"green.png\" width=\"16\" height=\"16\"></td>\n";
			}
			else if ($arow["imasigver"] == "0") {
			    echo "<td align=\"center\"><img src=\"red.png\" width=\"16\" height=\"16\"></td>\n";
			}
			else {
			    echo "<td></td>\n";
			}
			
			// the ima event count comes from the machines table for this hostname
			if ($arow["imaver"] == "1") {
			    echo "<td><a href=\"ima.php?hostname=" . $arow["hostname"] . "&boottime=" . $arow["boottime"] . "&entrynum=" . $arow["imaevents"] .  "\">" . $arow["imaevents"] . "</td>\n";
			}
			else {
			    echo "<td></td>\n";
			}

		    }

		    /* quote not verified */
		    else {
			// quote failed
			if ($arow["quoteverified"] == "0") {	
			    echo "<td align=\"center\"><img src=\"red.png\" width=\"16\" height=\"16\"></td>\n";
			}
			// quote not processed yet
			else {
			    echo "<td></td>\n";	// quote signature
			}
			echo "<td></td>\n";		// pcrs unchanged
			echo "<td></td>\n";		// pcrs valid
			echo "<td></td>\n";		// PCR
			echo "<td></td>\n";		// BIOS event log verified
			echo "<td></td>\n";		// BIOS Events
			echo "<td></td>\n";		// IMA event log verified
			echo "<td></td>\n";		// IMA Signatures verified
			echo "<td></td>\n";		// IMA Events
		    }
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
