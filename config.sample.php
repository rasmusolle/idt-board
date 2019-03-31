<?php
date_default_timezone_set("Europe/Stockholm");

$host = "";
$user = "";
$pass = "";
$db = "";

$threadsperpage = 20;
$postsperpage = 20;

$timefmt = "H:i";
$datefmt = "Y-m-d";

$cookie_uname = "hcsforumlogin";
$cookie_token = "hcsforumtoken";
$cookie_site = ".127.0.0.1";
$cookie_path = "/";
$cookie_expire = 60 * 60 * 24 * 60; // 60 days

$my_path = "./";
$full_path = "http://127.0.0.1/forum/" . $my_path;

// pinned at top of results
$pinned_threads = array();

$messages = array(
	"So, you wanted a message board, eh?"
);