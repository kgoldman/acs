<?php
// $Id: imaevent.php 1198 2018-05-04 15:06:06Z kgoldman $

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

// check to make sure entrynum is defined and is numeric
if(isset($_GET["entrynum"]) && is_numeric($_GET["entrynum"]))
{
    $entrynum = $_GET["entrynum"];
    $where = " WHERE entrynum = '$entrynum'";
}
else
{
    echo "Error: Invalid entrynum";
}

if(isset($_GET["hostname"]))
{
    $hostname = $_GET["hostname"];
    $where .= " AND hostname = '$hostname'";
}
else {
    echo "Error: No hostname\n";
}

if(isset($_GET["boottime"]))
{
    $boottime = $_GET["boottime"];
    $where .= " AND boottime  = '$boottime'";
}
else {
    echo ">No boottime!\n";
}

// query for the text of the event
$result = mysqli_query($connect, "SELECT ima_entry FROM imalog " . $where);

echo "
<html>
<head>
<title>IMA Event</title>
</head>
<body>
<div id=\"breakword\">
<kbd>
<font size=5>
";

//OUTPUT THE ENTIRE EVENT
while($row = mysqli_fetch_array($result))
{
    echo $row["ima_entry"];
}

echo "
</div>
</font>
</kbd>
</body>

<style>
#breakword {
width: 600px;
word-wrap:break-word;
}
</style>

";

/* close the database connection */
mysqli_close($connect);

?>
