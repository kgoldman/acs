<?php
/* $Id: pcrinvalid.php 1198 2018-05-04 15:06:06Z kgoldman $			*/
/*										*/
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

/* connect to the database */
require("dbconnect.php");
?>

<html>
<head>
<title>TPM 2.0 Attestation Invalid PCRs</title>  
<link rel="stylesheet" type="text/css" href="demo.css">
</head>

<body>
<div id="header">
<h2>TPM 2.0 Attestation Invalid PCRs</h2>
<?php
require 'header.php';
?>
</div>
<?php
require 'navigation.php';


if(isset($_GET["id"]) && is_numeric($_GET["id"]))
{
    $id = $_GET["id"];
}
else
{
   /* stop execution on post error */
    die("Error: Invalid ID.\n");
}

$aresult = mysqli_query($connect, "SELECT hostname, pcr00sha256, pcr01sha256, pcr02sha256, pcr03sha256, pcr04sha256, pcr05sha256, pcr06sha256, pcr07sha256 FROM attestlog WHERE id = " . $id);
if(!mysqli_num_rows($aresult)) {
    die("Error: Invalid ID " . $id . "<br>\n");
}
$arow = mysqli_fetch_array($aresult);

/*echo "SELECT pcr00sha256, pcr01sha256, pcr02sha256, pcr03sha256, pcr04sha256, pcr05sha256, pcr06sha256, pcr07sha256 FROM machines WHERE hostname = '" . $arow["hostname"] . "'<br>"; */

$mresult = mysqli_query($connect, "SELECT pcr00sha256, pcr01sha256, pcr02sha256, pcr03sha256, pcr04sha256, pcr05sha256, pcr06sha256, pcr07sha256 FROM machines WHERE hostname = '" . $arow["hostname"] . "'");
if(!mysqli_num_rows($mresult)) {
    die("Error: Invalid hostname " . $arow["hostname"] . "<br>\n");
}
$mrow = mysqli_fetch_array($mresult);

echo '<h2>Invalid PCRs for Machine: ' . $arow["hostname"] . '</h2>';

echo "<kbd>";
for ( $pcrnum = 0 ; $pcrnum < 8 ; $pcrnum++ ) {
	$pcr = "pcr0" . $pcrnum . "sha256";
	if ( strcmp($mrow[$pcr], $arow[$pcr]) != 0) {
		echo '0' . $pcrnum . ' expected '         . $mrow[$pcr] . "<br>\n";
		echo '0' . $pcrnum . ' actual&nbsp&nbsp ' . $arow[$pcr] . "<br><br>\n";
	}
}
echo "</kbd>";


?>

<?php
require 'footer.php';
/* close the database connection */
?>
</body>
</html>
