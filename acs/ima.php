<?php
// $Id: ima.php 1198 2018-05-04 15:06:06Z kgoldman $

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
<title>TPM 2.0 Integrity Measurement Architecture (IMA) Reports</title>  
<link rel="stylesheet" type="text/css" href="demo.css">
</head>

<body>
    <div id="header">
	<img src="ibm.png" style="float:right;width:200px;height:100px">
	<h2>TPM 2.0 Integrity Measurement Architecture (IMA) Reports</h2>
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
	echo "<h2>Integrity Measurement Architecture (IMA) Reports for <a href=\"machines.php?hostname=" . $hostname . "\">" . $hostname . "</a></h2>\n";
    }
    else {
	echo "<h2>No hostname!</h2>\n";
    }

    if(isset($_GET["boottime"]))
    {
	$boottime = $_GET["boottime"];
	$where .= " AND boottime  = '$boottime'";
    }
    else {
	echo "<h2>No boottime!</h2>\n";
    }

    if(isset($_GET["entrynum"]))
    {
	$entrynum = $_GET["entrynum"];
	$where .= " AND entrynum < '$entrynum'";
    }
    else {
	echo "<h2>No entrynum!</h2>\n";
    }
    ?>

    <table>
	<tr>
	    <th>Timestamp</th>

	    <?php

	    // default
	    $order = " ORDER BY imalog.entrynum ASC";
	    $sorttype = "sort=entrynumasc";
	    $filtertype = "";

	    if(isset($_GET["sort"]))
	    {
		$sort = $_GET["sort"];
		switch($sort)
		{
		    case "entrynumasc":
		    $order = " ORDER BY imalog.entrynum ASC";
		    $sorttype = "sort=entrynumasc";
		    break;
		    case "entrynumdesc":
		    $order = " ORDER BY imalog.entrynum DESC";
		    $sorttype = "sort=entrynumdesc";
		    break;
		    case "filenameasc":
		    $order = " ORDER BY imalog.filename ASC";
		    $sorttype = "sort=filenameasc";
		    break;
		    case "filenamedesc":
		    $order = " ORDER BY imalog.filename DESC";
		    $sorttype = "sort=filenamedesc";
		    break;
		    default:
		    $order = " ORDER BY imalog.entrynum ASC";
		    $sorttype = "sort=entrynumasc";
		    break;
		}
	    }

	    if(isset($_GET["filter"]))
	    {
		$filter =  $_GET["filter"];
		switch($filter)
		{
		    case "badevent":
		    $filtertype = " AND badevent = '1'";
		    break;
		    case "nosig":
		    $filtertype = " AND badevent = '0' AND nosig = '1'";
		    break;
		    case "nokey":
		    $filtertype = " AND badevent = '0' AND nosig = '0' AND nokey = '1'";
		    break;
		    case "badsig":
		    $filtertype = " AND badevent = '0' AND nosig = '0' AND nokey = '0' AND badsig = '1'";
		    break;
		}
	    }


	    // Event number column

	    switch($sorttype)
	    {
		case "sort=entrynumdesc":
		echo "<th><a href=\"ima.php?sort=entrynumasc&hostname=" . $hostname . "&boottime=" . $boottime . "&entrynum=" . $entrynum . "\">Event</a></th>\n";
		break;
		case "sort=entrynumasc":
		echo "<th><a href=\"ima.php?sort=entrynumdesc&hostname=" . $hostname . "&boottime=" . $boottime . "&entrynum=" . $entrynum . "\">Event</a></th>\n";
		break;
		default:
		echo "<th><a href=\"ima.php?sort=entrynumasc&hostname=" . $hostname . "&boottime=" . $boottime . "&entrynum=" . $entrynum . "\">Event</a></th>\n";
		break;
	    }

	    // badevent column
	    echo "<th><a href=\"ima.php?filter=badevent&hostname=" . $hostname . "&boottime=" . $boottime . "&entrynum=" . $entrynum . "\">Event</a></th>\n";

	    // nosig column
	    echo "<th><a href=\"ima.php?filter=nosig&hostname=" . $hostname . "&boottime=" . $boottime . "&entrynum=" . $entrynum . "\">Signed</a></th>\n";

	    // nokey column
	    echo "<th><a href=\"ima.php?filter=nokey&hostname=" . $hostname . "&boottime=" . $boottime . "&entrynum=" . $entrynum . "\">Key</a></th>\n";

	    // badsig column
	    echo "<th><a href=\"ima.php?filter=badsig&hostname=" . $hostname . "&boottime=" . $boottime . "&entrynum=" . $entrynum . "\">Sig</a></th>\n";

	    // File Name

	    switch($sorttype)
	    {
		case "sort=filenamedesc":
		echo "<th><a href=\"ima.php?sort=filenameasc&hostname=" . $hostname . "&boottime=" . $boottime . "&entrynum=" . $entrynum . "\">File Name</a></th>\n";
		break;
		case "sort=filenameasc":
		echo "<th><a href=\"ima.php?sort=filenamedesc&hostname=" . $hostname . "&boottime=" . $boottime . "&entrynum=" . $entrynum . "\">File Name</a></th>\n";
		break;
		default:
		echo "<th><a href=\"ima.php?sort=filenameasc&hostname=" . $hostname . "&boottime=" . $boottime . "&entrynum=" . $entrynum . "\">File Name</a></th>\n";
		break;
	    }

	    echo "</tr>\n";

	    $result = mysqli_query($connect, "SELECT id, hostname, boottime, timestamp, entrynum, filename, badevent, nosig, nokey, badsig FROM imalog " . $where . $filtertype . $order);

	    if(!mysqli_num_rows($result)) {
		echo "<tr><td>No Results</td></tr>";
	    }

	    else {
		while($row = mysqli_fetch_array($result)) {

		    echo "<tr>";

		    //echo "<td><a href=\"machines.php?hostname=" . $row["hostname"] . "\">" . $row["hostname"] . "</td>\n";

		    echo "<td>" . $row["timestamp"] . "</td>\n";

		    echo "<td><a href=\"imaevent.php?hostname=" . $row["hostname"] . "&boottime=" . $boottime . "&entrynum=" . $row["entrynum"] . "\">" . $row["entrynum"] . "</td>\n";

		    // badevent
		    if ($row["badevent"] == "1") {
			echo "<td align=\"center\"><img src=\"red.png\" width=\"16\" height=\"16\"></td>\n";
			echo "<td></td>\n";
			echo "<td></td>\n";
			echo "<td></td>\n";
		    }
		    else {
			echo "<td align=\"center\"><img src=\"green.png\" width=\"16\" height=\"16\"></td>\n";

			// nosig
			if ($row["nosig"] == "1") {
			    echo "<td align=\"center\"><img src=\"red.png\" width=\"16\" height=\"16\"></td>\n";
			    echo "<td></td>\n";
			    echo "<td></td>\n";
			}
			else {
	    		    echo "<td align=\"center\"><img src=\"green.png\" width=\"16\" height=\"16\"></td>\n";

			    // nokey
			    if ($row["nokey"] == "1") {
				echo "<td align=\"center\"><img src=\"red.png\" width=\"16\" height=\"16\"></td>\n";
				echo "<td></td>\n";
			    }
			    else {
				echo "<td align=\"center\"><img src=\"green.png\" width=\"16\" height=\"16\"></td>\n";

				// badsig
				if ($row["badsig"] == "1") {
				    echo "<td align=\"center\"><img src=\"red.png\" width=\"16\" height=\"16\"></td>\n";
				}
				else {
				    echo "<td align=\"center\"><img src=\"green.png\" width=\"16\" height=\"16\"></td>\n";
				}
			    }
			}
		    }
		    echo "<td>" . $row["filename"] . "</td>\n";
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
