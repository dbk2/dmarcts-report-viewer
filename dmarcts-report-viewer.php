<?php

// dmarcts-report-viewer - A PHP based viewer of parsed DMARC reports.
// Copyright (C) 2016 TechSneeze.com and John Bieling
//
// Available at:
// https://github.com/techsneeze/dmarcts-report-viewer
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.
//
//####################################################################
//### configuration ##################################################
//####################################################################

// Copy dmarcts-report-viewer-config.php.sample to
// dmarcts-report-viewer-config.php and edit with the appropriate info
// for your database authentication and location.

//####################################################################
//### functions ######################################################
//####################################################################

function format_date($date, $format) {
	$answer = date($format, strtotime($date));
	return $answer;
};

function tmpl_reportList($allowed_reports, $selected_report_id, $date_format, $host_lookup) {
	$reportlist[] = "";
	$reportlist[] = "<!-- Start of report list -->";

	$reportlist[] = "<h1>DMARC Reports</h1>";
	$reportlist[] = "<table class='reportlist'>";
	$reportlist[] = "  <thead>";
	$reportlist[] = "    <tr>";
	$reportlist[] = "      <th>ID</th>";
	$reportlist[] = "      <th>Start Date</th>";
	$reportlist[] = "      <th>End Date</th>";
	$reportlist[] = "      <th>Domain</th>";
	$reportlist[] = "      <th>Reporting Organization</th>";
	$reportlist[] = "      <th>Report ID</th>";
	$reportlist[] = "      <th>Messages</th>";
	$reportlist[] = "      <th>Raw</th>";
	$reportlist[] = "    </tr>";
	$reportlist[] = "  </thead>";

	$reportlist[] = "  <tbody>";

	foreach ($allowed_reports[BySerial] as $row) {
		$status = $row['serial'] == $selected_report_id ? "selected" : "";
		$rawtype = '';
		if (isset($row['raw_xml'])) {
			$rawtype = 'xml';
		} elseif (isset($row['gz_xml'])) {
			$rawtype = 'xml.gz';
		}
		$reportlist[] =  "    <tr class='".$status."'>";
		$reportlist[] =  "      <td class='right'>". $row['serial'] . "</td>";
		$reportlist[] =  "      <td class='right'>". format_date($row['mindate'], $date_format). "</td>";
		$reportlist[] =  "      <td class='right'>". format_date($row['maxdate'], $date_format). "</td>";
		$reportlist[] =  "      <td class='center'>". $row['domain']. "</td>";
		$reportlist[] =  "      <td class='center'>". $row['org']. "</td>";
		$reportlist[] =  "      <td class='center'><a href='?report=" . $row['serial'] . "&hostlookup=" . $host_lookup . "#rpt". $row['serial'] . "'>". $row['reportid']. "</a></td>";
		$reportlist[] =  "      <td class='center'>". $row['rcount']. "</td>";
		$reportlist[] =  "      <td class='center'><a href='?report=" . $row['serial'] . "&raw=" . $rawtype . "'>" . $rawtype . "</a></td>";
		$reportlist[] =  "    </tr>";
	}
	$reportlist[] =  "  </tbody>";

	$reportlist[] =  "</table>";

	$reportlist[] = "<!-- End of report list -->";
	$reportlist[] = "";

	#indent generated html by 2 extra spaces
	return implode("\n  ",$reportlist);
}

function tmpl_reportListMore($report_limit, $host_lookup) {
	if ($report_limit === 0) {
		return '';
	}
	return "\n  <div class='showmore'><a href='?limit=$report_limit&hostlookup=$host_lookup'>Show more</a></div>";
}

function tmpl_reportData($reportnumber, $allowed_reports, $date_format, $host_lookup) {

	if (!$reportnumber) {
		return "";
	}

	$reportdata[] = "";
	$reportdata[] = "<!-- Start of report rata -->";

	if (isset($allowed_reports[BySerial][$reportnumber])) {
		$row = $allowed_reports[BySerial][$reportnumber];
    $reportdata[] = "<a id='rpt".$reportnumber."'></a>";
		$reportdata[] = "<div class='center reportdesc'><p> Report from ".$row['org']." for ".$row['domain']."<br>(". format_date($row['mindate'], $date_format ). " - ".format_date($row['maxdate'], $date_format ).")<br> Policies: adkim=" . $row['policy_adkim'] . ", aspf=" . $row['policy_aspf'] .  ", p=" . $row['policy_p'] .  ", sp=" . $row['policy_sp'] .  ", pct=" . $row['policy_pct'] . "</p></div>";
	} else {
		return "Unknown report number!";
	}

	$reportdata[] = "<table class='reportdata'>";
	$reportdata[] = "  <thead>";
	$reportdata[] = "    <tr>";
	$reportdata[] = "      <th>IP Address</th>";
	$reportdata[] = "      <th>Host Name</th>";
	$reportdata[] = "      <th>Message Count</th>";
	$reportdata[] = "      <th>Disposition</th>";
	$reportdata[] = "      <th>DKIM Result</th>";
	$reportdata[] = "      <th>SPF Result</th>";
	$reportdata[] = "      <th>Reason</th>";
	$reportdata[] = "      <th>Header From</th>";
	$reportdata[] = "      <th>DKIM Domain</th>";
	$reportdata[] = "      <th>Raw DKIM Result</th>";
	$reportdata[] = "      <th>SPF Domain</th>";
	$reportdata[] = "      <th>Raw SPF Result</th>";
	$reportdata[] = "    </tr>";
	$reportdata[] = "  </thead>";

	$reportdata[] = "  <tbody>";

	$raw_result_failed = array('fail', null, 'none', 'neutral');

	global $mysqli;
	$sql = "SELECT * FROM rptrecord where serial = $reportnumber order by ip, ip6";
	$query = $mysqli->query($sql) or die("Query failed: ".$mysqli->error." (Error #" .$mysqli->errno.")");
	while($row = $query->fetch_assoc()) {
		$status="";
		if (($row['dkim_align'] === "pass") && ($row['spf_align'] === "pass")) {
			$status="lime";
		} elseif (($row['dkim_align'] === "pass") || ($row['spf_align'] === "pass")) {
			$status="yellow";
		} elseif (in_array($row['dkimresult'], $raw_result_failed, true) && in_array($row['spfresult'], $raw_result_failed, true)
			&& strtolower($row['spfdomain']) === strtolower($row['identifier_hfrom']) ) {
			$status="red";
		} else {
			$status="orange";
		};

		if ( $row['ip'] ) {
			$ip = long2ip($row['ip']);
		}
		if ( $row['ip6'] ) {
			$ip = inet_ntop($row['ip6']);
		}

		$reportdata[] = "    <tr class='".$status."'>";
		$reportdata[] = "      <td>". $ip. "</td>";
		if ( $host_lookup ) {
			$reportdata[] = "      <td>". gethostbyaddr($ip). "</td>";
		} else {
			$reportdata[] = "      <td>#off#</td>";
		}
		$reportdata[] = "      <td>". $row['rcount']. "</td>";
		$reportdata[] = "      <td>". $row['disposition']. "</td>";
		$reportdata[] = "      <td>". $row['dkim_align']. "</td>";
		$reportdata[] = "      <td>". $row['spf_align']. "</td>";
		$reportdata[] = "      <td>". $row['reason']. "</td>";
		$reportdata[] = "      <td>". $row['identifier_hfrom']. "</td>";
		$reportdata[] = "      <td>". $row['dkimdomain']. "</td>";
		$reportdata[] = "      <td>". $row['dkimresult']. "</td>";
		$reportdata[] = "      <td>". $row['spfdomain']. "</td>";
		$reportdata[] = "      <td>". $row['spfresult']. "</td>";
		$reportdata[] = "    </tr>";
	}
	$reportdata[] = "  </tbody>";
	$reportdata[] = "</table>";

	$reportdata[] = "<!-- End of report rata -->";
	$reportdata[] = "";

	#indent generated html by 2 extra spaces
	return implode("\n  ",$reportdata);
}

function raw_reportData($reportnumber, $type) {
	global $mysqli;
	$sql = "SELECT reportid, raw_xml, gz_xml FROM report where serial = $reportnumber";
	$query = $mysqli->query($sql) or die("Query failed: ".$mysqli->error." (Error #" .$mysqli->errno.")");
	$xml = null;
	if($row = $query->fetch_assoc()) {
		switch ($type) {
			case 'xml':
				header('Content-Type: application/xml');
				$xml = $row['raw_xml'];
				break;
			case 'xml.gz':
				header('Content-Type: application/gzip');
				$xml = $row['gz_xml'];
				break;
		}
		header('Content-Disposition: inline; filename="' . rawurlencode($row['reportid']) . '.' . $type . '"');
	}
	if ($xml !== null ) {
		echo $xml;
	} else {
		header("HTTP/1.0 404 Not Found");
	}
}

function tmpl_page ($body, $reportid, $report_limit, $host_lookup) {
	$html       = array();
	$url_switch = '?' . ($reportid ? "report=$reportid&" : '') . ($report_limit !== false ? "limit=$report_limit&" : '') . 'hostlookup=' . (1 - $host_lookup);

	$html[] = "<!DOCTYPE html>";
	$html[] = "<html>";
	$html[] = "  <head>";
	$html[] = "    <title>DMARC Report Viewer</title>";
	$html[] = "    <link rel='stylesheet' href='default.css'>";
	$html[] = "  </head>";

	$html[] = "  <body>";
	$html[] = "  <div class='options'>Hostname Lookup is " . ($host_lookup ? 'on' : 'off') . " [<a href='$url_switch'>" . ($host_lookup ? 'off' : 'on') . "</a>]</div>";

	$html[] = $body;

	$html[] = "  <div class='footer'>Brought to you by <a href='http://www.techsneeze.com'>TechSneeze.com</a> - <a href='mailto:dave@techsneeze.com'>dave@techsneeze.com</a></div>";
	$html[] = "  </body>";
	$html[] = "</html>";

	return implode("\n",$html);
}


//####################################################################
//### main ###########################################################
//####################################################################

// The file is expected to be in the same folder as this script, and it
// must exist.
include "dmarcts-report-viewer-config.php";

$date_format= isset( $default_date_format ) ? $default_date_format : "r";
$page_limit= isset( $default_page_limit ) ? $default_page_limit : 0;

if(isset($_GET['report']) && is_numeric($_GET['report'])){
  $reportid=$_GET['report']+0;
}elseif(!isset($_GET['report'])){
  $reportid=false;
}else{
  die('Invalid Report ID');
}
if($page_limit > 0 && isset($_GET['limit'])){
	if (is_numeric($_GET['limit'])){
		$report_limit=$_GET['limit']+0;
	}else{
		die('Invalid Report Limit');
	}
}else{
	$report_limit=$page_limit;
}
if(isset($_GET['hostlookup']) && is_numeric($_GET['hostlookup'])){
  $hostlookup=$_GET['hostlookup']+0;
}elseif(!isset($_GET['hostlookup'])){
  $hostlookup= isset( $default_lookup ) ? $default_lookup : 1;
}else{
  die('Invalid hostlookup flag');
}
$rawtype = isset($_GET['raw']) ? $_GET['raw'] : false;

// Make a MySQL Connection using mysqli
$mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
if ($mysqli->connect_errno) {
	echo "Error: Failed to make a MySQL connection, here is why: \n";
	echo "Errno: " . $mysqli->connect_errno . "\n";
	echo "Error: " . $mysqli->connect_error . "\n";
	exit;
}

if ($rawtype) {
	raw_reportData($reportid, $rawtype);
	exit;
}

define("BySerial", 1);
define("ByDomain", 2);
define("ByOrganisation", 3);

// Get allowed reports and cache them - using serial as key
$allowed_reports = array();
$current_report_limit = $report_limit > 0 ? $report_limit : PHP_INT_MAX;
$auto_limit = $reportid !== false;
$has_more_reports = false;
# Include the rcount via left join, so we do not have to make an sql query for every single report.
$sql = "SELECT report.* , sum(rptrecord.rcount) as rcount FROM `report` LEFT Join rptrecord on report.serial = rptrecord.serial group by serial order by serial desc";
$query = $mysqli->query($sql) or die("Query failed: ".$mysqli->error." (Error #" .$mysqli->errno.")");
while($row = $query->fetch_assoc()) {
	if ($current_report_limit-- === 0) {
		if ($auto_limit) {
			$current_report_limit += $page_limit;
			$report_limit += $page_limit;
		} else {
			$has_more_reports = true;
			break;
		}
	}
	if ($auto_limit && $row['serial'] == $reportid) {
		$auto_limit = false;
	}
	//todo: check ACL if this row is allowed
	if (true) {
		//add data by serial
		$allowed_reports[BySerial][$row['serial']] = $row;
		//make a list of serials by domain and by organisation
		$allowed_reports[ByDomain][$row['domain']][] = $row['serial'];
		$allowed_reports[ByOrganisation][$row['org']][] = $row['serial'];
	}
}

// Generate Page with report list and report data (if a report is selected).
echo tmpl_page( ""
	.tmpl_reportList($allowed_reports, $reportid, $date_format, $hostlookup)
	.tmpl_reportListMore($has_more_reports ? $report_limit + $page_limit : 0, $hostlookup)
	.tmpl_reportData($reportid, $allowed_reports, $date_format, $hostlookup)
	, $reportid
	, $report_limit !== $page_limit ? $report_limit : false
	, $hostlookup
);
?>
